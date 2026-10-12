# Client hostname option divergence across the connection entry points
#
# The client SSL name setup (SNI extension and certificate name
# verification) is configured separately at every connection entry
# point, and the entry points disagree about which option key supplies
# the client name and how it ranks against the positional host:
#
#   src/jtls/api/connect.c:200           - cfun_wrap takes the positional
#     hostname string
#   src/jtls/api/connect.c:250-253       - cfun_wrap reads the :hostname
#     option ONLY when no positional hostname was given, so the
#     positional host silently wins over the documented override
#   src/jtls/api/connect.c:728-733       - tls_connect_callback (the
#     tls/connect path) lets the :hostname option override the
#     positional host unconditionally
#   src/jtls/api/connect.c:354-361       - cfun_wrap always honours
#     :verify-hostname from the options table, so :hostname and
#     :verify-hostname are treated differently inside one entry point
#   src/jtls/api/connect.c:377-399       - cfun_wrap installs SNI and
#     binds the verification name from that hostname
#   src/jtls/api/connect.c:744-763       - tls_connect_callback installs
#     SNI and binds the verification name from sni_hostname
#   src/jdtls/api/connect.c:88-90        - cfun_dtls_connect reads ONLY
#     :sni for the client name; :hostname is silently dropped and the
#     name falls back to the positional host
#   src/jdtls/api/connect.c:297-313      - SNI and verification binding
#     from that :sni value
#   src/jdtls/api/upgrade.c:73-75        - cfun_dtls_upgrade reads ONLY
#     :sni for the client name; :hostname is silently dropped
#   src/jdtls/api/upgrade.c:212-237      - with neither :sni nor
#     :verify-hostname the upgrade binds NO verification name at all,
#     so any certificate name is accepted
#   src/jtls/api/context.c:73            - on tls/new-context the same
#     :sni key is the SERVER virtual-host map, not a client name
#
# This test demonstrates, one observable difference per test:
#   (a) tls/wrap with a positional host and the :hostname option must
#       verify the certificate for the :hostname value, as tls/connect
#       already does;
#   (b) tls/wrap with the same shape must install the SNI extension
#       carrying the :hostname value, as tls/connect already does;
#   (c) dtls/connect must override the positional host with the
#       :hostname option for certificate verification;
#   (d) dtls/upgrade with the :hostname option must bind that name for
#       certificate verification and reject a certificate valid only
#       for another name;
#   (e) dtls/connect must take the client name from :hostname even when
#       a :sni key is also present.
#
# Behaviour under the defect: (a) fails with the TLS handshake error
# "certificate verify failed" because the positional literal
# 127.0.0.1 is verified instead of the :hostname override; (b) fails
# with the server receiving no server name at all; (c) fails with
# "certificate verify failed" because the :hostname option is dropped
# and the positional host is verified; (d) fails because the handshake
# COMPLETES and the round trip delivers the echo although the
# certificate is valid only for the other name - no verification name
# is bound at all; (e) fails with "certificate verify failed" because
# the :sni key supplies the client name and its name is verified
# instead of the :hostname value. Exactly those symptoms and nothing
# else. Under fixed code - one shared client SSL setup driven by
# :hostname over the positional host, :sni reserved for the server
# virtual-host map - all five tests pass and guard that behaviour.

(use assay)
(import jsec/tls :as tls)
(import jsec/dtls-stream :as dtls)
(import jsec/ca)
(import ../helpers :prefix "")

# One CA, two leaves: the leaf the :hostname option names, and a leaf
# valid only for a DIFFERENT name (the rejection material).
(def ca
  (ca/generate {:common-name "jsec client name test CA"
                :key-type :ec-p256
                :days-valid 1}))

(def leaf-server
  (:issue ca {:common-name "server.example"
              :san ["DNS:server.example"]
              :key-type :ec-p256
              :days-valid 1}))

(def leaf-other
  (:issue ca {:common-name "other.example"
              :san ["DNS:other.example"]
              :key-type :ec-p256
              :days-valid 1}))

(defn- start-tls-name-server
  ``TLS server that completes the handshake, reports the server_name
   SNI value the ClientHello carried (nil when no SNI extension was
   sent), then pushes "ok". Returns {:server :host :port :seen} - seen
   yields the server-name per connection, or :server-done.``
  [leaf]
  (def server (net/listen "127.0.0.1" "0"))
  (def [host port] (net/localname server))
  (def seen (ev/chan 4))
  (ev/go (fn []
           (try
             (do
               (while true
                 (with [conn (:accept server)]
                   (with [s (tls/wrap conn {:cert (leaf :cert)
                                            :key (leaf :key)})]
                     (:read s 2 nil 5.0)
                     (ev/give seen ((:connection-info s) :server-name))
                     (:write s "ok")
                     (ev/sleep 0.3)))))
             ([_] (ev/give seen :server-done)))))
  {:server server :host host :port port :seen seen})

(defn- start-dtls-echo-server
  ``DTLS echo server on a random port. Returns {:server :port :done}.``
  [leaf]
  (def server (dtls/listen "127.0.0.1" "0"
                           {:cert (leaf :cert) :key (leaf :key)}))
  (def [_ port] (dtls/localname server))
  (def done (ev/chan 1))
  (ev/go (fn []
           (try
             (do
               (while true
                 (def buf @"")
                 (def addr (dtls/recv-from server 1024 buf 3))
                 (if addr
                   (dtls/send-to server addr (string "Echo: " buf))
                   (break))))
             ([_] nil))
           (ev/give done true)))
  {:server server :port port :done done})

(defn- stop-dtls-echo-server [echo]
  (try (dtls/close-server (echo :server) true) ([_] nil))
  (try (ev/take (echo :done)) ([_] nil)))

(def-suite :name "Client Hostname Option Divergence Regression"
  :description "Client SSL name setup diverges across the connection entry points"

  (def-test "wrap-hostname-option-must-override-positional-host-verification"
    :timeout 15

    (def srv (start-tls-name-server leaf-server))
    (var data nil)
    (var err nil)
    (try
      (with [c (tls/wrap (net/connect (srv :host) (srv :port)) "127.0.0.1"
                         {:hostname "server.example"
                          :verify true
                          :trusted-cert (:get-cert ca)})]
        (:write c "hi")
        (set data (string (:read c 2 nil 5.0))))
      ([e] (set err (string e))))
    (:close (srv :server))

    (assert (nil? err)
            (string/format
              (string "tls/wrap with the positional host 127.0.0.1 and the "
                      ":hostname option server.example must verify the "
                      "certificate for server.example - the option "
                      "overrides the positional host for verification, "
                      "as tls/connect already does at "
                      "src/jtls/api/connect.c:728-733 while wrap reads "
                      ":hostname only when no positional hostname is "
                      "given (src/jtls/api/connect.c:250-253) - but the "
                      "handshake failed: %v")
              err))
    (assert (= "ok" data)
            "the verified wrap connection must carry application data"))

  (def-test "wrap-hostname-option-must-install-sni-like-connect"
    :timeout 15

    (def srv (start-tls-name-server leaf-server))
    (var server-name :none)
    (var err nil)
    (try
      (with [c (tls/wrap (net/connect (srv :host) (srv :port)) "127.0.0.1"
                         {:hostname "server.example" :verify false})]
        (:write c "hi")
        (:read c 2 nil 5.0)
        (set server-name (ev/take (srv :seen))))
      ([e] (set err (string e))))
    (:close (srv :server))

    (assert (nil? err)
            (string/format "the SNI face must run a full handshake: %v" err))
    (assert (= "server.example" server-name)
            (string/format
              (string "tls/wrap with the positional host 127.0.0.1 and "
                      "the :hostname option server.example must send an "
                      "SNI extension carrying server.example - "
                      "tls/connect with the same option already does "
                      "(src/jtls/api/connect.c:728-733, :744-746) while "
                      "wrap derives SNI from the positional host and "
                      "sends none for a literal (src/jtls/api/connect.c:"
                      "250-253, :377-381) - but the server received "
                      "server name %q")
              server-name)))

  (def-test "dtls-connect-hostname-option-must-override-positional-host-verification"
    :timeout 15

    (def echo (start-dtls-echo-server leaf-server))
    (var data nil)
    (var err nil)
    (try
      (do
        (def c (dtls/connect "127.0.0.1" (echo :port)
                             {:hostname "server.example"
                              :verify true
                              :trusted-cert (:get-cert ca)}))
        (dtls/write c "Ping")
        (set data (string (dtls/read c 1024)))
        (try (dtls/close c) ([_] nil)))
      ([e] (set err (string e))))
    (stop-dtls-echo-server echo)

    (assert (nil? err)
            (string/format
              (string "dtls/connect with the positional host 127.0.0.1 "
                      "and the :hostname option server.example must "
                      "verify the certificate for server.example - the "
                      "option overrides the positional host, as "
                      "tls/connect already does at "
                      "src/jtls/api/connect.c:728-733 - but "
                      "cfun_dtls_connect reads only :sni and silently "
                      "drops :hostname (src/jdtls/api/connect.c:88-90), "
                      "so the positional host was verified and the "
                      "handshake failed: %v")
              err))
    (assert (= "Echo: Ping" data)
            "the verified DTLS connection must carry application data"))

  (def-test "dtls-upgrade-hostname-option-must-bind-verification-name"
    :timeout 15

    (def echo (start-dtls-echo-server leaf-other))
    (var data nil)
    (var err nil)
    (try
      (do
        (def sock (net/connect "127.0.0.1" (echo :port) :datagram))
        (def c (dtls/upgrade sock {:hostname "server.example"
                                   :verify true
                                   :trusted-cert (:get-cert ca)}))
        (dtls/write c "Ping")
        (set data (string (dtls/read c 1024)))
        (try (dtls/close c) ([_] nil)))
      ([e] (set err (string e))))
    (stop-dtls-echo-server echo)

    (assert (not (nil? err))
            (string/format
              (string "dtls/upgrade with the :hostname option "
                      "server.example must bind server.example for "
                      "certificate verification and reject this server "
                      "certificate, which is valid only for "
                      "other.example - tls/wrap with the same option "
                      "binds and enforces it (src/jtls/api/connect.c:"
                      "354-361, :377-399) while cfun_dtls_upgrade reads "
                      "only :sni (src/jdtls/api/upgrade.c:73-75) and "
                      "with neither :sni nor :verify-hostname binds no "
                      "verification name at all "
                      "(src/jdtls/api/upgrade.c:212-237) - instead the "
                      "handshake completed and the round trip "
                      "delivered %q with no hostname mismatch raised")
              data)))

  (def-test "dtls-connect-client-name-must-come-from-hostname-not-sni"
    :timeout 15

    (def echo (start-dtls-echo-server leaf-server))
    (var data nil)
    (var err nil)
    (try
      (do
        (def c (dtls/connect "127.0.0.1" (echo :port)
                             {:hostname "server.example"
                              :sni "other.example"
                              :verify true
                              :trusted-cert (:get-cert ca)}))
        (dtls/write c "Ping")
        (set data (string (dtls/read c 1024)))
        (try (dtls/close c) ([_] nil)))
      ([e] (set err (string e))))
    (stop-dtls-echo-server echo)

    (assert (nil? err)
            (string/format
              (string "dtls/connect with :hostname server.example and "
                      ":sni other.example must verify the certificate "
                      "for the :hostname value server.example - the "
                      "client name comes from :hostname and the :sni "
                      "key names the server virtual-host map on "
                      "tls/new-context (src/jtls/api/context.c:73) - "
                      "but cfun_dtls_connect takes the client name "
                      "from :sni (src/jdtls/api/connect.c:88-90), so "
                      "the certificate for server.example failed "
                      "verification against other.example and the "
                      "handshake failed: %v")
              err))
    (assert (= "Echo: Ping" data)
            "the verified DTLS connection must carry application data")))
