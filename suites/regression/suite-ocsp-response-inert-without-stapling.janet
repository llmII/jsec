# set-ocsp-response inert without :ocsp-stapling regression test
# Ticket 6911526b562efc4e4a9606f71c85639bf0c6f35b
#
# "set-ocsp-response silently inert without :ocsp-stapling security option"
#
# cfun_set_ocsp_response (src/jtls/api/context.c:157-186 in this tree)
# copies the response DER into a heap OCSPData (:162-171), frees any
# previous OCSPData (:173-177), stores the new one in the SSL_CTX
# ex_data slot ocsp_idx (:179-183) and returns nil (:185). It never
# installs the OpenSSL status callback. The only install site in the
# tree is apply_session_options (src/jtls/context/server.c:72-85), which
# runs at context creation and calls SSL_CTX_set_tlsext_status_cb
# (:83) / SSL_CTX_set_tlsext_status_arg (:84) ONLY when the
# :ocsp-stapling security option is truthy (:73-81). So on a context
# created without :ocsp-stapling, set-ocsp-response stores OCSPData
# that jtls_ocsp_status_cb (src/jtls/context/ocsp.c:15-30) can never be
# asked to staple - the call is a silent no-op.
#
# The predicted symptom, verbatim (forge ticket):
#
# : setting an OCSP response does nothing, with no warning.
#
# This test demonstrates:
#   (a) set-ocsp-response on a context created WITHOUT :ocsp-stapling
#       returns nil silently - no error, no warning,
#   (b) a TLS client that requests a status (status_request extension)
#       then receives no CertificateStatus handshake message carrying
#       the configured response bytes - the response is never stapled,
#       so the security feature is silently dead.
#
# Probe design: jsec's client paths never send status_request (no
# SSL_CTX_set_tlsext_status_type in the tree), so the probe speaks the
# wire directly - a raw TLS 1.2 ClientHello with a status_request
# extension. TLS 1.2 is forced (no supported_versions extension) so the
# server flight is carried in plaintext handshake records and the
# staple is observable without any TLS implementation: RFC 6066 places
# the response in a CertificateStatus handshake message (type 22),
# body: status_type(1)=ocsp(1), OCSPResponse = u24 length + response
# bytes. The marker bytes must appear verbatim in that message when the
# server staples.
#
# Fixture constraints of the platform OpenSSL (3.6.5), taken from its
# ossl_get_ocsp_response (ssl/statem/statem_srvr.c): it returns NULL for
# self-signed certificates, and responses set through
# SSL_set_tlsext_status_ocsp_resp are only used if they parse as an
# OCSPResponse DER. So the fixture uses a CA-issued server certificate
# (ca/generate + :issue) and ocsp-response-der builds a syntactically
# valid OCSPResponse whose responseStatus is unauthorized (non-
# successful skips the SingleResponse-to-certificate matching) and
# whose responseBytes OCTET STRING carries the marker.
#
# Proof contract: correct behaviour is that set-ocsp-response either
# raises (loud rejection when :ocsp-stapling is absent) or makes the
# response actually staple to a status_request client (auto-install of
# the status callback); under the defect the test fails with exactly
# the predicted symptom (silent no-op: no raise and no staple), and it
# becomes the regression guard after the fix lands.

(use assay)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import jsec/ca)
(import ../helpers :prefix "")

# Distinctive bytes carried inside the OCSP response so the staple can
# be identified on the wire.
(def- ocsp-marker "OCSP-MARKER-6911526b56-RESPONSE-BYTES")

# --- raw TLS 1.2 status_request probe ---------------------------------------
(defn- be16
  [n]
  (string/from-bytes (band (brshift n 8) 0xFF) (band n 0xFF)))

(defn- be24
  [n]
  (string/from-bytes (band (brshift n 16) 0xFF)
                     (band (brshift n 8) 0xFF)
                     (band n 0xFF)))

(defn- ocsp-response-der
  ``A syntactically valid OCSPResponse DER (RFC 6960) carrying marker in
   its responseBytes. responseStatus is unauthorized(2), a non-
   successful status: OpenSSL then staples the bytes as-is, without
   requiring a SingleResponse that matches the served certificate.
   Layout: SEQUENCE { ENUMERATED 2, [0] EXPLICIT SEQUENCE {
   OID id-pkix-ocsp-basic, OCTET STRING marker } }.``
  [marker]
  (def oid (string/from-bytes
             0x06 0x09 # OBJECT IDENTIFIER, 9 content bytes
             0x2B 0x06 0x01 0x05 0x05 0x07 0x30 0x01 0x01)) # 1.3.6.1.5.5.7.48.1.1
  (def oct (string (string/from-bytes 0x04 (band (length marker) 0xFF))
                   marker))
  (def rb-body (string oid oct))
  (def rb (string (string/from-bytes 0x30 (band (length rb-body) 0xFF))
                  rb-body))
  (def wrapped (string (string/from-bytes 0xA0 (band (length rb) 0xFF))
                       rb))
  (def body (string (string/from-bytes 0x0A 0x01 0x02) wrapped))
  (string (string/from-bytes 0x30 (band (length body) 0xFF)) body))

(defn- client-hello-record
  ``One TLS record (type 22 handshake) holding a TLS 1.2 ClientHello that
   offers a status_request extension, enough groups/point formats/
   signature algorithms for an OpenSSL server to pick a suite, and the
   renegotiation SCSV.``
  []
  (def random (string (os/cryptorand 32)))
  (def suites
    (string/from-bytes
      0xC0 0x2F # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      0xC0 0x30 # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      0xC0 0x2B # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      0xC0 0x2C # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      0xCC 0xA9 # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      0x00 0x9C # TLS_RSA_WITH_AES_128_GCM_SHA256
      0x00 0x9D # TLS_RSA_WITH_AES_256_GCM_SHA384
      0xCC 0xA8 # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      0xC0 0x13 # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
      0xC0 0x14 # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      0x00 0x2F # TLS_RSA_WITH_AES_128_CBC_SHA
      0x00 0x35 # TLS_RSA_WITH_AES_256_CBC_SHA
      0x00 0xFF # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
      ))
  (def groups
    (string/from-bytes 0x00 0x1D # x25519
                       0x00 0x17 # secp256r1
                       0x00 0x18 # secp384r1
                       0x00 0x19 # secp521r1
                       ))
  (def sigalgs
    (string/from-bytes
      0x04 0x01 # rsa_pkcs1_sha256
      0x05 0x01 # rsa_pkcs1_sha384
      0x06 0x01 # rsa_pkcs1_sha512
      0x08 0x04 # rsa_pss_rsae_sha256
      0x08 0x05 # rsa_pss_rsae_sha384
      0x08 0x06 # rsa_pss_rsae_sha512
      0x04 0x03 # ecdsa_secp256r1_sha256
      0x05 0x03 # ecdsa_secp384r1_sha384
      0x06 0x03 # ecdsa_secp521r1_sha512
      ))
  (def extensions
    (string
      # status_request (5): ocsp, no responders, no request extensions
      (be16 5) (be16 5) (string/from-bytes 0x01 0x00 0x00 0x00 0x00)
      # signature_algorithms (13)
      (be16 13) (be16 (+ 2 (length sigalgs))) (be16 (length sigalgs))
      sigalgs
      # supported_groups (10)
      (be16 10) (be16 (+ 2 (length groups))) (be16 (length groups)) groups
      # ec_point_formats (11): uncompressed
      (be16 11) (be16 2) (string/from-bytes 0x01 0x00)
      # session_ticket (35): empty
      (be16 35) (be16 0)))
  (def body
    (string (string/from-bytes 0x03 0x03) # client_version TLS 1.2
            random
            (string/from-bytes 0x00) # empty session_id
            (be16 (length suites)) suites
            (string/from-bytes 0x01 0x00) # null compression
            (be16 (length extensions)) extensions))
  (def hello (string (string/from-bytes 0x01) (be24 (length body)) body))
  (string (string/from-bytes 0x16 0x03 0x01) # handshake record, TLS 1.0 header
          (be16 (length hello)) hello))

(defn- handshake-messages
  ``Parse complete TLS handshake messages out of an accumulated handshake
   record payload stream. Returns [{:type t :body s} ...]; a trailing
   partial message is ignored.``
  [buf]
  (var i 0)
  (def msgs @[])
  (while (<= (+ i 4) (length buf))
    (def t (in buf i))
    (def len (+ (* 65536 (in buf (+ i 1)))
                (* 256 (in buf (+ i 2)))
                (in buf (+ i 3))))
    (when (> (+ i 4 len) (length buf))
      (break))
    (array/push msgs {:type t :body (string/slice buf (+ i 4) (+ i 4 len))})
    (set i (+ i 4 len)))
  msgs)

(defn- status-request-probe
  ``Connect to host:port, send the status_request ClientHello, and inspect
   the server's first flight. Returns
   {:types [...] :marker bool :alert bytes-or-nil :error s-or-nil}``
  [host port]
  (def conn (net/connect host port))
  (defer (:close conn)
    (:write conn (client-hello-record))
    (def hs @"")
    (var alert nil)
    (var error nil)
    (var done false)
    (while (not done)
      (var hdr nil)
      (try
        (set hdr (:chunk conn 5 nil 5))
        ([e] (set error (string e))))
      (cond
        error (set done true)
        (or (nil? hdr) (not= 5 (length hdr))) (set done true)
        (do
          (def ctype (in hdr 0))
          (def rlen (+ (* 256 (in hdr 3)) (in hdr 4)))
          (def payload (:chunk conn rlen nil 5))
          (cond
            (or (nil? payload) (not= rlen (length payload)))
            (set done true)
            (= ctype 21) # alert record: handshake failure or close
            (do (set alert payload) (set done true))
            (= ctype 22) # handshake record: accumulate and scan
            (do
              (buffer/push hs payload)
              (each m (handshake-messages hs)
                (when (or (= 22 (m :type)) # CertificateStatus
                          (= 14 (m :type))) # ServerHelloDone
                  (set done true))))))))
    (def msgs (handshake-messages hs))
    (var marker false)
    (each m msgs
      (when (and (= 22 (m :type))
                 (string/find ocsp-marker (m :body)))
        (set marker true)))
    {:types (map |(get $ :type) msgs)
     :marker marker
     :alert alert
     :error error}))

(def-suite :name "Ocsp Response Inert Regression"
  :description "Ticket 6911526b56: set-ocsp-response without :ocsp-stapling must auto-install status callback and staple"

  (def-test "set-ocsp-response without ocsp-stapling auto-arms and staples"
    :timeout 20

    # CA-issued server certificate: the platform OpenSSL refuses to
    # staple for self-signed certificates (fixture constraint above).
    (def authority (ca/generate {:common-name "jsec-ocsp-test-ca"
                                 :key-type :rsa-2048}))
    (def issued (:issue authority {:common-name "127.0.0.1"
                                  :key-type :rsa-2048}))

    # A server-capable context with NO :security {:ocsp-stapling true},
    # so apply_session_options (src/jtls/context/server.c:72-85) leaves
    # the status callback uninstalled at context creation time.
    (def ctx (tls-stream/new-context {:cert (issued :cert)
                                      :key (issued :key)}))
    (def set-ret
      (tls-stream/set-ocsp-response ctx (ocsp-response-der ocsp-marker)))
    (assert (nil? set-ret)
            (string/format "expected set-ocsp-response to return nil, got %q"
                           set-ret))

    # Calling set-ocsp-response alone must install the status callback so
    # the configured response actually staples to a status_request client.
    (var probe nil)
    (with [server (tls/listen "127.0.0.1" "0")]
      (def [_ port] (net/localname server))
      (ev/go (fn []
               (try
                 (do
                   (def s (tls/accept server ctx))
                   (try (:read s 1 nil 5) ([_] nil))
                   (try (:close s) ([_] nil)))
                 ([_] nil))))
      (try
        (set probe (status-request-probe "127.0.0.1" (string port)))
        ([e] (set probe {:error (string e)}))))

    (def stapled (and probe (probe :marker)))
    (assert stapled
            (string/format
              (string "set-ocsp-response without :ocsp-stapling must "
                      "install the status callback so the response staples "
                      "(src/jtls/api/context.c:157-186 stores OCSPData "
                      "without installing jtls_ocsp_status_cb); "
                      "a client status_request probe observed %q "
                      "(expected symptom: setting an OCSP response does "
                      "nothing, with no warning)")
              probe))))

