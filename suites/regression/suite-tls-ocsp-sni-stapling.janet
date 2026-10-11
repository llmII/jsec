# OCSP stapling callback reads its response from the post-SNI SSL_CTX regression test
# Ticket 5cfda654c2a8c78ca2edb297af1ec812b3cc8053
#
# "OCSP stapling callback reads its response from the post-SNI SSL_CTX"
#
# Mechanism (this tree, ticket branch off 0.2.0): the status callback
# jtls_ocsp_status_cb fetches the active context with
# SSL_get_SSL_CTX(ssl) and reads the OCSPData from its ex_data
# (src/jtls/context/ocsp.c:15-18, the fetch at :17). The callback is
# installed on the accepting context when :security's :ocsp-stapling is
# truthy (src/jtls/context/server.c:82-84, the option read at :73-80;
# note it is read only from a mutable TABLE). tls-stream/set-ocsp-response
# stores the OCSPData on exactly one TLSContext (src/jtls/api/context.c:157-186).
# The :sni option builds bare per-name SSL_CTXs (src/jtls/api/context.c:75-131,
# creation at :97-98) that carry no OCSPData and that no Janet API can
# hand one to. jtls_sni_callback switches the connection to the matching
# per-name context with SSL_set_SSL_CTX (src/jtls/context/sni.c:26), so
# when SNI selects a name the callback's lookup lands on that post-SNI
# context, finds no OCSPData and returns SSL_TLSEXT_ERR_NOACK
# (src/jtls/context/ocsp.c:29) - no staple, silently. No client path
# ever enables status requests (no SSL_CTX_set_tlsext_status_type
# anywhere in src/), so a jsec client cannot even ask for a staple; the
# probe here is openssl s_client -status, pinned to TLS 1.2 so its
# status lines are stable.
#
# Platform notes (OpenSSL 3.6.5, this host): the TLS 1.2/1.3 construct
# path refuses to staple for self-signed certificates (ossl_get_ocsp_response:
# "for a selfsigned certificate there will be no OCSP response") and
# matches the OCSP certID against the leaf's issuer-name hash and serial,
# so the fixture is a CA-issued leaf (ca/generate + ca/issue, first serial
# 1) with a ca/create-ocsp-response built for that serial - a self-signed
# fixture can never staple on this host regardless of the defect.
#
# This test demonstrates:
#   (a) control: with no SNI the accepting context serves the staple -
#       s_client prints OCSP Response Status: successful and
#       Cert Status: good - proving the response data and the status
#       callback work,
#   (b) with SNI selecting either of the two server names on the same
#       listener the staple is silently not served - s_client prints
#       OCSP response: no OCSP response received - exactly the
#       post-SNI lookup miss at src/jtls/context/ocsp.c:17-18.
#
# Predicted symptom: stapling silently stops exactly when SNI selects a
# different context - both server names report no OCSP response received
# while the default context staples.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes. The guard pins the ticket's
# own contract: with two server names on one listener the staple is
# served for both.

(use assay)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import jsec/ca :as ca)
(import ../helpers :prefix "")

# Fixture: CA-issued leaf + matching OCSP response (see platform notes).
(def root (ca/generate {:common-name "jsec-sni-staple-root" :days-valid 2
                        :serial 1}))
(def leaf (ca/issue root {:common-name "localhost" :days-valid 2
                          :key-type :rsa-2048}))
(def ocsp-der (ca/create-ocsp-response root @{:serial 1} :good))

(def ctx
  (tls/new-context
    {:cert (leaf :cert)
     :key (leaf :key)
     :sni {"a.test" {:cert (leaf :cert) :key (leaf :key)
                     :security @{:ocsp-stapling true}}
           "b.test" {:cert (leaf :cert) :key (leaf :key)
                     :ocsp-response ocsp-der
                     :security @{:ocsp-stapling true}}}
     :security @{:ocsp-stapling true}}))
(tls-stream/set-ocsp-response ctx ocsp-der)

(defn- probe-ocsp-lines
  ``Run openssl s_client -status against the listener (optional SNI name)
   and return the OCSP-related lines of its output, joined with newlines.``
  [&opt sni-name]
  (def listener (tls/listen "127.0.0.1" "0"))
  (defer (:close listener)
    (def [host port] (net/localname listener))
    (ev/go (fn []
             (try
               (when-let [s (tls/accept listener ctx)]
                 (try (:write s "hi") ([_] nil))
                 (try (:close s) ([_] nil)))
               ([_] nil))))
    (def args @["openssl" "s_client" "-connect" (string host ":" port)
                "-status" "-tls1_2"])
    (when sni-name
      (array/push args "-servername" sni-name))
    (def proc (os/spawn args :p {:out :pipe :err :pipe :in :pipe}))
    (:close (proc :in))
    (def out-buf @"")
    (def err-buf @"")
    (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
    (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
    (os/proc-wait proc)
    (:close (proc :out))
    (:close (proc :err))
    (def lines @[])
    (each line (string/split "\n" (string out-buf))
      (when (or (string/find "OCSP" line) (string/find "ocsp" line)
                (string/find "Cert Status" line)
                (string/find "Response Status" line))
        (array/push lines line)))
    (string/join lines "\n")))

(defn- stapled?
  ``True when the s_client output shows a successfully stapled response.``
  [ocsp-text]
  (and (string/find "Response Status: successful" ocsp-text)
       (string/find "Cert Status: good" ocsp-text)))

(def-suite :name "TLS OCSP SNI Stapling Regression"
  :description "Ticket 5cfda654c2: the OCSP staple must be served for both SNI names on one listener"

  (def-test "staple-served-for-default-context"
    :timeout 30

    (def ocsp-text (probe-ocsp-lines nil))
    (assert (stapled? ocsp-text)
            (string/format
              (string "control: with no SNI the accepting context must "
                      "serve the staple (the OCSPData is set on it via "
                      "tls-stream/set-ocsp-response); s_client output: %s")
              ocsp-text)))

  (def-test "staple-served-for-sni-name-a"
    :timeout 30

    (def ocsp-text (probe-ocsp-lines "a.test"))
    (assert (stapled? ocsp-text)
            (string/format
              (string "with SNI a.test on the shared listener the staple "
                      "must be served exactly as for the default context: "
                      "the callback's OCSPData lookup lands on the post-SNI "
                      "SSL_CTX (src/jtls/context/ocsp.c:17-18) which carries "
                      "none and silently returns no staple; s_client "
                      "output: %s")
              ocsp-text)))

  (def-test "staple-served-for-sni-name-b"
    :timeout 30

    (def ocsp-text (probe-ocsp-lines "b.test"))
    (assert (stapled? ocsp-text)
            (string/format
              (string "with SNI b.test on the shared listener the staple "
                      "must be served exactly as for the default context: "
                      "the callback's OCSPData lookup lands on the post-SNI "
                      "SSL_CTX (src/jtls/context/ocsp.c:17-18) which carries "
                      "none and silently returns no staple; s_client "
                      "output: %s")
              ocsp-text)))

  (def-test "client-ocsp-stapling-option-sends-status-request"
    :timeout 10

    # RFC 6066 section 8 status_request extension with empty responder_id_list
    # and request_extensions: type 0x0005, len 0x0005, status_type 1 (ocsp),
    # 0x0000, 0x0000.
    (def status-request-ext "\x00\x05\x00\x05\x01\x00\x00\x00\x00")

    (defn capture-client-hello [client-opts]
      (def raw-srv (net/listen "127.0.0.1" "0"))
      (defer (:close raw-srv)
        (def [shost sport] (net/localname raw-srv))
        (def ch-buf @"")
        (def done (ev/chan 1))
        (ev/go (fn []
                 (defer (ev/give done true)
                   (when-let [conn (:accept raw-srv)]
                     (defer (:close conn)
                       (ev/read conn 4096 ch-buf))))))
        (try
          (with [c (tls/connect shost sport client-opts)]
            nil)
          ([_] nil))
        (ev/take done)
        (string ch-buf)))

    (def default-ch (capture-client-hello {:verify false}))
    (assert (nil? (string/find status-request-ext default-ch))
            "default tls/connect client must not send OCSP status_request without opt-in")

    (def optin-ch (capture-client-hello {:verify false
                                         :security {:ocsp-stapling true}}))
    (assert (truthy? (string/find status-request-ext optin-ch))
            (string "tls/connect with {:security {:ocsp-stapling true}} must "
                    "send the OCSP status_request (0x0005) extension in "
                    "ClientHello, but no status_request extension was sent"))))

