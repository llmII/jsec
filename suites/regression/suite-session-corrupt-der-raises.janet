# session deserialization corrupt DER regression test
# Ticket 7abba4d727caa15f72922ecff29e9af9b2885f57
#
# "dtls/set-session and :session option in connect/wrap/upgrade fail to
# raise on corrupt DER"
#
# Mechanism (this tree, branch off 0.2.0):
#   tls/set-session (src/jtls/api/session.c) checks both d2i_SSL_SESSION
#   and SSL_set_session and raises via tls_panic_ssl - draining the
#   OpenSSL error queue - when the session DER is corrupt or
#   incompatible, returning nil on success. The DTLS side diverges:
#   - src/jdtls/api/info.c:206-233 (cfun_dtls_set_session): a NULL
#     d2i_SSL_SESSION at :221 returns janet_wrap_false() at :225, a
#     failed SSL_set_session at :226 returns false at :233, and a
#     successful set returns true - while leaving the ASN.1 decode
#     error on the OpenSSL error queue (ERRORS.org E-50). The ruled
#     contract is to raise via dtls_panic_ssl("failed to parse session
#     data") / ("failed to set session") and return nil on success.
#   - src/jtls/api/connect.c:320-327 (tls/wrap) and :623-646
#     (tls/connect): non-nil :session bytes that fail d2i_SSL_SESSION
#     or SSL_set_session are silently ignored.
#   - src/jdtls/api/connect.c:315-327 (dtls/connect) and
#     src/jdtls/api/upgrade.c:242-252 (dtls/upgrade): the same silent
#     ignore - a NULL d2i_SSL_SESSION at connect.c:321 / upgrade.c:247
#     simply skips the attach and the corrupt bytes never surface
#     (ERRORS.org E-08).
#
# This test demonstrates:
#   (a) (dtls/set-session client corrupt) raises a [DTLS:SSL] error,
#       exactly like tls/set-session raises on corrupt DER, while under
#       the defect the call returns false and leaves the ASN.1 error on
#       the OpenSSL queue,
#   (b) (dtls/set-session client good) returns nil on success, matching
#       tls/set-session, while under the defect it returns true,
#   (c) an explicit non-nil :session value with corrupt DER raises
#       [DTLS:SSL] / [TLS:SSL] on all four consumers - dtls/connect,
#       dtls/upgrade, tls/connect, tls/wrap - instead of being silently
#       ignored.
#
# Predicted symptom: (a) the corrupt call returns false instead of
# raising, (b) the good call returns true instead of nil, and (c) each
# :session consumer silently ignores the corrupt DER and completes
# normally.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its assertion and nothing else: no crash,
# no hang, no unrelated error. Under fixed code every test passes.
(use assay)
(import jsec/tls :as tls)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Session Corrupt DER Raises Regression"
  :description "Ticket 7abba4d727: dtls/set-session and the :session option raise on corrupt DER like tls/set-session"

  (def-test "dtls-set-session-raises-on-corrupt-der"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)]
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (forever (:recv-from server 1024 (buffer/new 1024))))
              ([_] nil))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)
          (:write conn "Ping1")
          (:read conn 1024)

          # (a) corrupt DER must raise like tls/set-session does.
          # Under the defect the call returns false and the assertion
          # fails with the predicted symptom.
          (assert-error
            (dtls/set-session conn "not-a-session")
            (string
              "the corrupt-der (dtls/set-session client data) call "
              "returned a boolean instead of raising a [DTLS:SSL] "
              "error (tls/set-session raises on corrupt DER and the "
              "ruled dtls contract matches it; the ASN.1 decode error "
              "is left on the OpenSSL error queue)"))))))

  (def-test "dtls-set-session-good-returns-nil"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)]
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (forever (:recv-from server 1024 (buffer/new 1024))))
              ([_] nil))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)
          (:write conn "Ping1")
          (:read conn 1024)

          # (b) a good session blob must set and return nil, matching
          # tls/set-session. Under the defect the call returns true.
          (def blob (dtls/session conn))
          (def r (dtls/set-session conn blob))
          (assert (= nil r)
                  (string/format
                    (string "the good (dtls/set-session client data) "
                            "call returned %q instead of nil "
                            "(tls/set-session returns nil on success "
                            "and the ruled dtls contract matches it)")
                    r))))))

  (def-test "dtls-connect-session-option-raises-on-corrupt-der"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)]
        (ev/go
          (fn []
            (try
              (forever (:recv-from server 1024 (buffer/new 1024)))
              ([_] nil))))

        # (c1) dtls/connect with explicit corrupt :session bytes must
        # raise before any attach. Under the defect the call silently
        # ignores the corrupt DER and returns a connected client.
        (assert-error
          (tls/connect "127.0.0.1" (string port)
                       {:datagram true :verify false
                        :session "not-a-session"})
          (string
            "dtls/connect with a non-nil :session holding corrupt DER "
            "completed normally instead of raising [DTLS:SSL] (an "
            "explicitly supplied :session that fails to deserialize or "
            "attach must raise and drain the OpenSSL queue, not be "
            "silently ignored)")))))

  (def-test "dtls-upgrade-session-option-raises-on-corrupt-der"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)]
        (ev/go
          (fn []
            (try
              (forever (:recv-from server 1024 (buffer/new 1024)))
              ([_] nil))))

        (def raw (net/connect "127.0.0.1" (string port) :datagram))
        (defer (:close raw)
          # (c2) dtls/upgrade with explicit corrupt :session bytes must
          # raise. Under the defect the corrupt DER is silently ignored.
          (assert-error
            (dtls/upgrade raw {:verify false :session "not-a-session"})
            (string
              "dtls/upgrade with a non-nil :session holding corrupt "
              "DER completed normally instead of raising [DTLS:SSL]"))))))

  (def-test "tls-connect-session-option-raises-on-corrupt-der"
    :timeout 20

    (let [[server socket-path] (make-server :tcp)
          addr (get-server-addr server :tcp socket-path)]
      (defer (:close server)
        (ev/go
          (fn []
            (try
              (forever
                (def c (:accept server))
                (ev/go
                  (fn []
                    (try
                      (do
                        (def s (tls/wrap c {:cert (certs :cert)
                                            :key (certs :key)}))
                        (forever
                          (def b (:read s 1024))
                          (when (or (not b) (empty? b)) (break))))
                      ([_] nil)))))
              ([_] nil))))

        # (c3) tls/connect with explicit corrupt :session bytes must
        # raise. Under the defect the corrupt DER is silently ignored
        # and the connection completes.
        (assert-error
          (tls/connect (addr :host) (addr :port)
                       {:verify false :session "not-a-session"})
          (string
            "tls/connect with a non-nil :session holding corrupt DER "
            "completed normally instead of raising [TLS:SSL]")))))

  (def-test "tls-wrap-session-option-raises-on-corrupt-der"
    :timeout 20

    (let [[server socket-path] (make-server :unix)
          addr (get-server-addr server :unix socket-path)]
      (defer (do (:close server) (cleanup-socket socket-path))
        (ev/go
          (fn []
            (try
              (do
                (def sconn (:accept server))
                (def s (tls/wrap sconn {:cert (certs :cert)
                                        :key (certs :key)}))
                (forever
                  (def b (:read s 1024))
                  (when (or (not b) (empty? b)) (break))))
              ([_] nil))))

        (def raw (make-client-conn :unix addr))
        (defer (:close raw)
          # (c4) tls/wrap with explicit corrupt :session bytes must
          # raise. Under the defect the corrupt DER is silently ignored.
          (assert-error
            (tls/wrap raw {:verify false :session "not-a-session"})
            (string
              "tls/wrap with a non-nil :session holding corrupt DER "
              "completed normally instead of raising [TLS:SSL]")))))))
