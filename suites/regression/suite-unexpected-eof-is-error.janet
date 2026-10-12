# Unexpected EOF without close_notify must be an error regression test
# Ticket 70a405f7e09f35fd6d335a35b6bff771a9705869
#
# "Unexpected EOF must be an error, documented, and consistent across
#  the supported TLS libraries"
#
# Ruled policy (tickets/DECISIONS.org, BLOCKERS.org): a peer close
# without close_notify is an error, not a clean end of data - a
# truncated stream must never look like a complete one.
#
# Mechanism in src/jtls/state_machine.c: handle_ssl_error
# (src/jtls/state_machine.c:166-205) routes the EOF-shaped outcomes
# SSL_ERROR_ZERO_RETURN (:176-179) and SSL_ERROR_SYSCALL with
# ret == 0 or sock_err == 0 (:181-187) into handle_eof_close
# (src/jtls/state_machine.c:130-146), which completes the read-style
# operations as a clean EOF. An unexpected EOF - the peer's transport
# closed without a close_notify - surfaces through the custom BIO as
# EOF (src/jtls/bio.c:88 and :108-109) and is classified into that
# same clean-EOF path instead of an error, on every read surface: the
# synchronous ops in jtls_process_operation (TLS_OP_READ at
# :281-331, TLS_OP_CHUNK at :334-401) and the async completions of
# jtls_attempt_io (src/jtls/state_machine.c:672-683). The async read
# therefore completes with the buffered plaintext - or nil - as if the
# peer had closed cleanly, and the truncation is silent.
#
# This test demonstrates: a peer that sends application data and then
# closes its transport WITHOUT close_notify (a truncated stream) must
# make the read RAISE; under the defect the read completes normally,
# handing back the buffered plaintext as a clean end of data - the
# exact predicted symptom, "a truncated stream can look like a
# complete one".
#
# Proof contract: under the defect the test fails with exactly that
# symptom (a returned buffer instead of a raise); under fixed code the
# whole test passes. This proof commit contains ONLY the failing
# test: no production code changes.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Unexpected EOF Is Error Regression"
  :description "Ticket 70a405f7e0: a peer close without close_notify must raise, never a clean end of data"

  (def-test "read on a truncated stream raises instead of clean EOF"
    :timeout 15

    (let [[server socket-path] (make-server :unix)
          addr (get-server-addr server :unix socket-path)]
      (defer (do (:close server) (cleanup-socket socket-path))
        (def ready (ev/chan 1))
        (var mc nil)
        (ev/go (fn []
                 (do
                   (def conn (make-client-conn :unix addr))
                   (def c (tls/wrap conn {:verify false}))
                   (set mc c)
                   (ev/give ready :done))))
        (def sconn (:accept server))
        (def s (tls/wrap sconn {:cert (certs :cert) :key (certs :key)}))
        (ev/take ready)
        (def c mc)
        (def out (ev/chan 1))
        (ev/go (fn []
                 (ev/give out
                   (try
                     [:returned (:read c :all)]
                     ([e] [:raised (string e)])))))
        (ev/sleep 0.1)
        # Application data, then the transport closes with no
        # close_notify: the stream is truncated, not completed.
        (:write s "hello")
        (:close sconn)
        (def r (ev/take out))
        (assert (= :raised (r 0))
                (string/format
                  (string "an unexpected EOF - the peer closed the "
                          "transport without close_notify - must be an "
                          "error, not a clean end of data (the policy "
                          "that a truncated stream can never look like a "
                          "complete one); handle_ssl_error "
                          "(src/jtls/state_machine.c:166-205) routes the "
                          "EOF-shaped SSL_get_error outcomes through "
                          "handle_eof_close (:130-146), which completes "
                          "the read-style operations as a clean EOF "
                          "instead of raising; got: %s %q")
                  (r 0) (r 1)))))))
