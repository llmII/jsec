# Async completion at clean close_notify keeps buffered plaintext
# Ticket 1b5bd49de4ae2b9960764e0c5ccb576e8f0a633d
#
# "jtls async HUP handler loop clobbers ret and discards already-read
#  plaintext on clean close_notify"
#
# Completion contract for the async read surfaces at a CLEAN
# close_notify (the peer sent close_notify and closed): when
# application bytes were buffered before the close_notify, complete
# with that plaintext - never nil, which would silently discard it;
# return nil only when zero application bytes were buffered before the
# close_notify (while a truncation without close_notify must still
# raise per the unexpected-EOF policy, ticket 70a405f7e0).
#
# Mechanism in jsec: the async read completions are the TLS_OP_READ
# and TLS_OP_CHUNK arms of the TLS_IO_COMPLETE case in jtls_attempt_io
# (src/jtls/state_machine.c:666-700, arms at :672-683) and the
# JANET_ASYNC_EVENT_HUP drain of jtls_async_callback
# (src/jtls/state_machine.c:930-1037). The ticket's cited
# "else if (ret == 0) -> janet_wrap_nil()" branch is stale: the
# post-loop SSL_ERROR_ZERO_RETURN arm of the HUP drain (:994-1003)
# already completes with the accumulated bytes, and the drain loop
# (:970-984) appends every positive SSL_read into state->user_buf
# before the close_notify terminates it. What remains observable
# through the public API is the completion rule itself on the async
# surfaces - the plaintext half and the nil half.
#
# This test demonstrates, in the ticket's scenario - application data
# followed immediately by close_notify and the transport close in one
# wakeup - that (a) an async (tls/read s :all) that has already
# buffered plaintext completes with that plaintext (the headline
# rule), and (b) the same completion returns nil when zero application
# bytes were buffered before the close_notify (the ticket's own
# companion clause: "return nil only when zero application bytes were
# buffered before close_notify"). Under the defect (b) hands back a
# buffer - truthy - instead of nil.
#
# Proof contract: under the defect the test fails with exactly that
# symptom; under fixed code the whole test passes. This proof commit
# contains ONLY the failing test: no production code changes.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- session []
  (def [server socket-path] (make-server :unix))
  (def addr (get-server-addr server :unix socket-path))
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
  [mc s sconn server socket-path])

(defn- outcome [thunk]
  (try [:returned (thunk)] ([e] [:raised (string e)])))

(defn- shape [r]
  (cond
    (not= :returned (r 0)) (string (r 0) " " (r 1))
    (nil? (r 1)) "nil"
    (buffer? (r 1)) (string/format "buffer %q" (string (r 1)))
    (string/format "%q" (r 1))))

(defn- parked-read-all-then-close [send-first]
  # The ticket's scenario: the async (tls/read s :all) is parked
  # first, then the peer's application data (if any) is followed
  # immediately by close_notify and the transport close.
  (def [c s sconn server socket-path] (session))
  (defer (do (try (:close sconn) ([_] nil))
             (try (:close server) ([_] nil))
             (cleanup-socket socket-path))
    (def out (ev/chan 1))
    (ev/go (fn [] (ev/give out (outcome (fn [] (:read c :all))))))
    (ev/sleep 0.1)
    (when send-first (:write s "hello"))
    (:close s)
    (ev/take out)))

(def-suite :name "HUP Delivers Buffered Plaintext Regression"
  :description "Ticket 1b5bd49de4: the async completion at a clean close_notify must deliver buffered plaintext, nil only when none was buffered"

  (def-test "async read-all completes with buffered plaintext at clean close_notify"
    :timeout 30

    (def obs-with-plaintext (shape (parked-read-all-then-close true)))
    (def obs-zero-bytes (shape (parked-read-all-then-close false)))

    (assert (and (= "buffer \"hello\"" obs-with-plaintext) (= "nil" obs-zero-bytes))
            (string/format
              (string "at a clean close_notify the async read "
                      "completion must complete with the plaintext "
                      "already buffered - never nil, which would "
                      "silently discard it - and return nil only when "
                      "zero application bytes were buffered before the "
                      "close_notify (the JANET_ASYNC_EVENT_HUP drain "
                      "and the TLS_OP_CHUNK arm of jtls_attempt_io, "
                      "src/jtls/state_machine.c:678-683 and :994-1003); "
                      "observed: {:with-plaintext %s :zero-bytes %s}")
              obs-with-plaintext obs-zero-bytes))))
