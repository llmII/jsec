# :security acceptance contract and session-options unification regression test
# Ticket b50c059aa9a73149d59f37b9600578a8deda3c4b
#
# ":security struct literals silently ignored"
#
# 2026-10-11 maintainer ruling widened the scope: accept table-or-struct,
# raise on non-dictionary with PNB-08 cleanup safety, unify session
# options across server context builders, and document the 4 session keys
# in docs/API.org. Each ruled behaviour carries a failing proof-of-defect
# guard with its predicted symptom.
#
# Mechanism (this tree, ticket branch off 0.2.0):
#   - apply_session_options (src/jtls/context/server.c:44-107, called
#     from jtls_create_server_ctx at src/jtls/context/server.c:353)
#     guards every option block with
#     janet_checktype(security_opts, JANET_TABLE) and reads via
#     janet_unwrap_table/janet_table_get - :session-cache at
#     src/jtls/context/server.c:47-50, :session-tickets at :60-63,
#     :ocsp-stapling at :74-77, :session-cache-size at :89-92. A struct
#     literal fails every guard, so all four options are silently
#     dropped - including the :ocsp-stapling request that gates the
#     status callback install at :83-84
#     (SSL_CTX_set_tlsext_status_cb). A negative :session-cache-size is
#     silently clamped to 1000 (:93-94) and a non-number silently
#     defaulted.
#   - The sibling parser apply_security_options
#     (src/jutils/security.c:53) accepts both tables and structs
#     (:60-62), so the SAME :security value is half-honoured depending
#     on which parser reads it. A non-dictionary :security value is
#     still silently ignored there (return 1 at src/jutils/security.c
#     :59-62) and the session trio is never applied there at all.
#   - The session trio is honoured inconsistently across the server
#     context builders: jtls_create_server_ctx honours it (table
#     literals only, via apply_session_options), jtls_create_client_ctx
#     duplicates it inline (table literals only, src/jtls/context/client.c
#     :46-90), and the DTLS builders drop it entirely -
#     cfun_dtls_listen (src/jdtls/server.c:340) and jutils_create_context
#     (src/jutils/context.c:153) call only apply_security_options, which
#     never reads :session-cache, :session-tickets or
#     :session-cache-size.
#   - Tree-wide, table-or-struct acceptance is already the norm
#     (src/jcrypto/rsa.c:65-75, src/jcrypto/convert.c:26-40,
#     src/jcrypto/keys.c:203-235, src/jcrypto/ec.c:103-115,
#     src/jtls/api/server.c:406-415, src/jtls/api/io.c:67-68, the
#     jdtls option sites); src/jcert/verify.c:159-165 raises on
#     anything else ("options must be a table or struct") and
#     src/jca/ocsp.c:176-180 requires a table by name - three policies
#     in one tree.
#
# The predicted symptoms, verbatim (forge ticket plus the ruling):
#   (1) a struct-literal :security option is silently ignored while the
#       same options in a mutable table apply - :security
#       {:ocsp-stapling true} never installs the status callback and
#       the configured OCSP response is never stapled,
#   (2) a non-dictionary :security value is silently ignored at both
#       parser sites - the context is built with default security and
#       no error is raised,
#   (3) the server context builders drop the session options - a
#       :security @{:session-cache false :session-tickets false} at
#       dtls/listen changes nothing and a replayed session is still
#       resumed.
#
# Guards:
#   (1) "struct-literal-security-ocsp-stapling-applies-like-table-literal"
#       - table literal staples, struct literal must staple identically.
#   (2) "non-dictionary-security-raises-at-tls-context-builders" and
#       "non-dictionary-security-raises-at-dtls-context-builders" - a
#       non-dictionary :security must raise a parameter error naming
#       :security instead of silently defaulting, at every context
#       builder entry. The TLS guard also carries the PNB-08 cleanup
#       safety leg: the raise must leave the context cache lock usable
#       (a later valid build must succeed, not deadlock).
#   (3) "dtls-server-context-builder-honours-session-options" - with
#       :session-cache and :session-tickets false, a replayed session
#       must NOT be resumed, under both table and struct literals.
#   (4) "invalid-session-cache-size-raises-not-clamps" - a negative or
#       non-number :session-cache-size must raise instead of being
#       silently clamped to 1000 or silently defaulted.
#
# Proof contract: one :security contract for both parsers and every
# context builder - nil, table, or struct; anything else raises; the
# four session keys (:session-cache, :session-tickets,
# :session-cache-size, :ocsp-stapling) apply under both literal shapes
# everywhere a server context is built. Every guard fails on purpose
# under the defect with exactly its predicted symptom and becomes the
# regression guard after the fix lands.

(use assay)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import jsec/ca)
(import ../helpers :prefix "")

# Distinctive bytes carried inside the OCSP response so the staple can
# be identified on the wire.
(def- ocsp-marker "OCSP-MARKER-b50c059aa9-RESPONSE-BYTES")

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
   requiring a SingleResponse that matches the served certificate.``
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

(defn- stapling-probe-with-security
  ``One stapling scenario: CA-issued server cert, a server context created
   with the given :security value, one configured OCSP response, and a
   status_request probe against it. Returns the probe result map.``
  [security-opts]
  (def authority (ca/generate {:common-name "jsec-struct-literal-test-ca"
                               :key-type :rsa-2048}))
  (def issued (:issue authority {:common-name "127.0.0.1"
                                 :key-type :rsa-2048}))
  (def ctx (tls-stream/new-context {:cert (issued :cert)
                                    :key (issued :key)
                                    :security security-opts}))
  (tls-stream/set-ocsp-response ctx (ocsp-response-der ocsp-marker))
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
  probe)

# --- error capture ----------------------------------------------------------
(defn- captured-error
  ``Run f; return nil when f succeeds, else the stringified error.``
  [f]
  (try (do (f) nil) ([e] (string e))))

# --- DTLS session-reuse probe ----------------------------------------------
(defn- session-reuse-probe
  ``One DTLS session-reuse scenario: a server built with the given
   :security value, one full handshake whose session is captured, then a
   second connection replaying that session at the same server. Returns
   {:first-ok bool :second-ok bool :session-len n :reused bool}
   or {:error s}.``
  [security-opts]
  (def certs (generate-temp-certs {:common-name "127.0.0.1"}))
  (var result nil)
  (try
    (do
      (def server (tls/listen "127.0.0.1" "0"
                              {:datagram true
                               :cert (certs :cert)
                               :key (certs :key)
                               :security security-opts}))
      (def [_ port] (:localname server))
      (ev/go (fn []
               (var runs 2)
               (while (pos? runs)
                 (def buf (buffer/new 1024))
                 (try
                   (ev/with-deadline 8
                     (when-let [addr (:recv-from server 1024 buf)]
                       (:send-to server addr buf)))
                   ([_] nil))
                 (set runs (dec runs)))))
      (var sess nil)
      (var first-ok false)
      (var second-ok false)
      (var reused nil)
      (ev/with-deadline 15
        (def c1 (tls/connect "127.0.0.1" port
                             {:datagram true :verify false}))
        (:write c1 "one")
        (def r1 (ev/with-deadline 8 (:read c1 1024)))
        (set first-ok (and r1 (= "one" (string r1))))
        (set sess (:session c1))
        (try (ev/with-deadline 3 (:close c1)) ([_] nil))
        (def c2 (tls/connect "127.0.0.1" port
                             {:datagram true :verify false :session sess}))
        (:write c2 "two")
        (def r2 (ev/with-deadline 8 (:read c2 1024)))
        (set second-ok (and r2 (= "two" (string r2))))
        (set reused (:session-reused? c2))
        (try (ev/with-deadline 3 (:close c2)) ([_] nil)))
      (try (ev/with-deadline 3 (:close server)) ([_] nil))
      (set result {:first-ok first-ok
                   :second-ok second-ok
                   :session-len (if sess (length sess) 0)
                   :reused reused}))
    ([e] (set result {:error (string e)})))
  result)

(def-suite :name "Security Struct Literal Ignored Regression"
  :description "Ticket b50c059aa9: one :security contract for both parsers and every context builder - table-or-struct accepted, anything else raises, and the four session keys apply everywhere"

  (def-test "struct-literal-security-ocsp-stapling-applies-like-table-literal"
    :timeout 30

    # (a) Control: the mutable-table literal. The :ocsp-stapling
    # request must be honoured - the status callback installs at
    # src/jtls/context/server.c:83-84 and the configured response
    # staples into the CertificateStatus message. This is the scenario
    # validity condition: if this leg does not staple, the probe and
    # fixture prove nothing.
    (def table-probe (stapling-probe-with-security @{:ocsp-stapling true}))
    (assert (and table-probe (table-probe :marker))
            (string/format
              (string "control leg broken: :security @{:ocsp-stapling "
                      "true} (mutable table literal) must staple the "
                      "configured OCSP response to a status_request "
                      "client, but the probe observed %q - without this "
                      "leg the struct comparison proves nothing")
              table-probe))

    # (b) The proof: the struct literal must be indistinguishable from
    # the table literal. Under the defect apply_session_options drops
    # it at the janet_checktype(security_opts, JANET_TABLE) guard
    # (src/jtls/context/server.c:74-77), the status callback is never
    # installed (:83-84), and the identical probe receives no
    # CertificateStatus staple.
    (def struct-probe (stapling-probe-with-security {:ocsp-stapling true}))
    (assert (and struct-probe (struct-probe :marker))
            (string/format
              (string ":security {:ocsp-stapling true} (struct literal) "
                      "must apply exactly like :security @{:ocsp-stapling "
                      "true} - the identical OCSP response must staple "
                      "to the same status_request client - but the "
                      "struct literal was silently dropped at the "
                      "JANET_TABLE guard of apply_session_options "
                      "(src/jtls/context/server.c:74-77) and nothing "
                      "stapled; table literal probe: %q; struct literal "
                      "probe: %q (expected symptom: a struct-literal "
                      ":security option is silently ignored while the "
                      "same options in a mutable table apply)")
              table-probe struct-probe)))

  (def-test "non-dictionary-security-raises-at-tls-context-builders"
    :timeout 30

    (def certs (generate-temp-certs {:common-name "127.0.0.1"}))

    # (a) A non-dictionary :security value must raise a parameter error
    # naming :security. Under the defect it is silently ignored at both
    # parser sites - apply_security_options (return 1 at
    # src/jutils/security.c:59-62) and apply_session_options (every
    # JANET_TABLE guard) - and a context with default security is
    # built with no error at all.
    (def err (captured-error
               (fn []
                 (tls-stream/new-context {:cert (certs :cert)
                                          :key (certs :key)
                                          :security 42}))))
    (assert err
            (string/format
              (string ":security 42 (non-dictionary) must raise a "
                      "parameter error naming :security, but "
                      "tls/new-context silently built a context with "
                      "default security - no error raised (expected "
                      "symptom: a non-dictionary :security value is "
                      "silently ignored at both parser sites)")))
    (assert (string/find ":security must be a table or struct" err)
            (string/format
              (string "the raise must name the :security contract "
                      "(\"[UTILS:PARAM] :security must be a table or "
                      "struct\" shape), got %q") err))

    # Same contract for a non-dictionary string spelling.
    (def err2 (captured-error
                (fn []
                  (tls-stream/new-context {:cert (certs :cert)
                                           :key (certs :key)
                                           :security "nope"}))))
    (assert (and err2 (string/find ":security must be a table or struct"
                                  err2))
            (string/format
              (string ":security \"nope\" must raise the same "
                      ":security-must-be-a-table-or-struct parameter "
                      "error, got %q") err2))

    # (b) PNB-08 cleanup safety leg: the raise must run before any
    # SSL_CTX exists or ctx_cache_lock is taken - a later valid build
    # must succeed instead of deadlocking on the leaked lock.
    (assert (tls-stream/new-context {:cert (certs :cert)
                                     :key (certs :key)})
            (string "a valid context build must still succeed after the "
                    "non-dictionary :security raise - the raise must not "
                    "leak ctx_cache_lock or an SSL_CTX (PNB-08 cleanup "
                    "safety); if this hangs the raise panicked past the "
                    "cleanup")))

  (def-test "non-dictionary-security-raises-at-dtls-context-builders"
    :timeout 30

    (def certs (generate-temp-certs {:common-name "127.0.0.1"}))

    # dtls/listen reaches only apply_security_options
    # (src/jdtls/server.c:340), whose non-dictionary branch reports
    # success with defaults (return 1 at src/jutils/security.c:59-62).
    (def err (captured-error
               (fn []
                 (def s (tls/listen "127.0.0.1" "0"
                                    {:datagram true
                                     :cert (certs :cert)
                                     :key (certs :key)
                                     :security 42}))
                 (try (ev/with-deadline 3 (:close s)) ([_] nil)))))
    (assert err
            (string/format
              (string ":security 42 (non-dictionary) must raise a "
                      "parameter error at the DTLS server builder too, "
                      "but dtls/listen silently accepted it and built a "
                      "server with default security (expected symptom: "
                      "the non-dictionary :security value is silently "
                      "dropped at apply_security_options)")))
    (assert (string/find ":security must be a table or struct" err)
            (string/format
              (string "the DTLS-side raise must name the same :security "
                      "contract as the TLS-side one, got %q") err))

    # dtls/new-context reaches jutils_create_context
    # (src/jdtls/context.c:45 -> src/jutils/context.c:153) - same
    # contract at the third builder entry.
    (def err2 (captured-error
                (fn []
                  (tls/new-context {:datagram true
                                    :cert (certs :cert)
                                    :key (certs :key)
                                    :security [1 2 3]}))))
    (assert (and err2 (string/find ":security must be a table or struct"
                                  err2))
            (string/format
              (string ":security [1 2 3] must raise at dtls/new-context "
                      "as well, got %q") err2)))

  (def-test "dtls-server-context-builder-honours-session-options"
    :timeout 60

    # (a) Table literal. With :session-cache and :session-tickets both
    # false the DTLS server must neither cache nor ticket the session,
    # so the replayed session must NOT be resumed. Under the defect
    # cfun_dtls_listen applies only apply_security_options
    # (src/jdtls/server.c:340) and never reads the session keys, so
    # caching and tickets stay enabled and the second handshake
    # resumes (session-reused? true).
    (def table-probe (session-reuse-probe
                       @{:session-cache false :session-tickets false}))
    (assert (and table-probe (not (table-probe :error))
                 (table-probe :first-ok) (table-probe :second-ok)
                 (> (table-probe :session-len) 0))
            (string/format
              (string "scenario invalid: both handshakes must complete "
                      "and a session must be captured for the replay, "
                      "probe: %q") table-probe))
    (assert (= false (table-probe :reused))
            (string/format
              (string ":security @{:session-cache false :session-tickets "
                      "false} at dtls/listen must disable server-side "
                      "session caching and tickets, so a replayed "
                      "session must NOT be resumed - but the second "
                      "handshake resumed it (session-reused? %q) "
                      "(expected symptom: the server context builder "
                      "drops the session options and a replayed session "
                      "is still resumed); probe: %q")
              (table-probe :reused) table-probe))

    # (b) The struct literal must be indistinguishable.
    (def struct-probe (session-reuse-probe
                        {:session-cache false :session-tickets false}))
    (assert (and struct-probe (not (struct-probe :error))
                 (struct-probe :first-ok) (struct-probe :second-ok)
                 (> (struct-probe :session-len) 0))
            (string/format
              (string "scenario invalid (struct literal): both "
                      "handshakes must complete and a session must be "
                      "captured, probe: %q") struct-probe))
    (assert (= false (struct-probe :reused))
            (string/format
              (string ":security {:session-cache false :session-tickets "
                      "false} (struct literal) must behave exactly like "
                      "the table literal - no resumption - but the "
                      "second handshake resumed (session-reused? %q); "
                      "probe: %q")
              (struct-probe :reused) struct-probe)))

  (def-test "invalid-session-cache-size-raises-not-clamps"
    :timeout 30

    (def certs (generate-temp-certs {:common-name "127.0.0.1"}))

    # (a) Negative size, table literal. Under the defect
    # apply_session_options silently clamps to 1000
    # (src/jtls/context/server.c:93-94).
    (def neg-err (captured-error
                   (fn []
                     (tls-stream/new-context
                       {:cert (certs :cert) :key (certs :key)
                        :security @{:session-cache-size -5}}))))
    (assert (and neg-err (string/find
                           ":session-cache-size must be a non-negative number"
                           neg-err))
            (string/format
              (string ":security @{:session-cache-size -5} must raise a "
                      "parameter error instead of being silently "
                      "clamped to 1000 (expected symptom: a negative "
                      ":session-cache-size is silently clamped), got "
                      "%q") neg-err))

    # (b) Non-number size. Under the defect the JANET_NUMBER guard
    # silently defaults to 1000.
    (def nan-err (captured-error
                   (fn []
                     (tls-stream/new-context
                       {:cert (certs :cert) :key (certs :key)
                        :security @{:session-cache-size "big"}}))))
    (assert (and nan-err (string/find ":session-cache-size must be a number"
                                     nan-err))
            (string/format
              (string ":security @{:session-cache-size \"big\"} must "
                      "raise a parameter error instead of silently "
                      "defaulting to 1000, got %q") nan-err))

    # (c) Struct literal, negative size - same contract under both
    # literal shapes.
    (def struct-err (captured-error
                      (fn []
                        (tls-stream/new-context
                          {:cert (certs :cert) :key (certs :key)
                           :security {:session-cache-size -5}}))))
    (assert (and struct-err (string/find
                              ":session-cache-size must be a non-negative number"
                              struct-err))
            (string/format
              (string "the struct literal must raise the same "
                      ":session-cache-size error as the table literal, "
                      "got %q") struct-err))

    # (d) The DTLS builder entry shares the contract.
    (def dtls-err (captured-error
                    (fn []
                      (def s (tls/listen "127.0.0.1" "0"
                                         {:datagram true
                                          :cert (certs :cert)
                                          :key (certs :key)
                                          :security @{:session-cache-size -5}}))
                      (try (ev/with-deadline 3 (:close s)) ([_] nil)))))
    (assert (and dtls-err (string/find
                            ":session-cache-size must be a non-negative number"
                            dtls-err))
            (string/format
              (string "the DTLS builder entry must raise the same "
                      ":session-cache-size error, got %q") dtls-err))))
