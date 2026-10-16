# Chunk and async read :all return nil at EOF with zero bytes regression
# Ticket 83339adde2e329b2aac5ed69acfc45aad6758bfd
#
# "tls/chunk and async (tls/read s :all) return buffer instead of nil
#  on EOF when 0 bytes were read"
#
# Contract (Janet's ev/read, ev/chunk, net/read, net/chunk): return nil
# on clean EOF when 0 bytes were read during the call, and return the
# buffer when at least 1 byte was read before EOF. A returned buffer -
# even empty - is truthy in Janet, so idiom loops like
# (while (let [b (:chunk conn n)] ...) ...) never terminate on EOF.
#
# Mechanism in jsec: two completions return the buffer unconditionally.
#   - cfun_chunk (src/jtls/api/io.c:147-173) on synchronous completion
#     returns janet_wrap_buffer(buffer) at :168-170 even when
#     buffer->count == state->buf_start and bytes_to_read > 0 - 0 new
#     bytes at EOF - unlike cfun_read at :124-131, which returns nil
#     for the same condition.
#   - jtls_attempt_io (src/jtls/state_machine.c:615-782) on async
#     completion of TLS_OP_CHUNK - which serves both tls/chunk and
#     (tls/read stream :all), since cfun_read at :116-117 sets
#     state->op = read_all ? TLS_OP_CHUNK : TLS_OP_READ - returns
#     janet_wrap_buffer(state->user_buf) at :678-683 even when
#     state->user_buf->count == state->buf_start and
#     state->bytes_requested > 0, while the TLS_OP_READ completion at
#     :672-677 returns nil for that condition.
#
# This test demonstrates: at a CLEAN end of stream (the peer closed
# with close_notify) with 0 bytes read during the call, tls/chunk
# (sync), async (tls/read s :all), and the pre-filled-caller-buffer
# variant must all return nil; under the defect they return a buffer -
# @"", or the unchanged pre-filled buffer, both truthy - the exact
# predicted symptom.
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

(def-suite :name "EOF Zero Bytes Returns Nil Regression"
  :description "Ticket 83339adde2: tls/chunk and async (tls/read s :all) must return nil at EOF with 0 bytes read"

  (def-test "chunk and async read-all return nil at clean EOF with zero bytes"
    :timeout 30

    (defn session-data-consumed []
      # Clean close scenario: the application data is sent and
      # consumed first, so the read under test sees a clean EOF
      # (close_notify) with 0 bytes read during its own call.
      (def sess (session))
      (def [c s sconn server socket-path] sess)
      (:write s "hello")
      (ev/sleep 0.1)
      (assert (= "hello" (string (:read c 5 nil 2)))
              "setup: the sent data must be consumable first")
      sess)

    (defn close-tail [s sconn server socket-path run]
      (defer (do (try (:close sconn) ([_] nil))
                 (try (:close server) ([_] nil))
                 (cleanup-socket socket-path))
        (run)))

    (def obs-chunk
      (shape
        (do
          (def [c s sconn server socket-path] (session-data-consumed))
          (close-tail s sconn server socket-path
            (fn []
              (:close s)
              (ev/sleep 0.2)
              (outcome (fn [] (:chunk c 10 nil 2))))))))

    (def obs-read-all
      (shape
        (do
          (def [c s sconn server socket-path] (session-data-consumed))
          (close-tail s sconn server socket-path
            (fn []
              (def out (ev/chan 1))
              (ev/go (fn []
                       (ev/give out (outcome (fn [] (:read c :all))))))
              (ev/sleep 0.1)
              (:close s)
              (ev/take out))))))

    (def obs-prefilled
      (shape
        (do
          (def [c s sconn server socket-path] (session-data-consumed))
          (close-tail s sconn server socket-path
            (fn []
              (def buf @"PRE")
              (def out (ev/chan 1))
              (ev/go (fn []
                       (ev/give out
                         (try [:returned (:read c :all buf)]
                              ([e] [:raised (string e)])))))
              (ev/sleep 0.1)
              (:close s)
              (ev/take out))))))

    (assert (and (= "nil" obs-chunk) (= "nil" obs-read-all) (= "nil" obs-prefilled))
            (string/format
              (string "at a clean EOF with 0 bytes read during the call, "
                      "tls/chunk and async (tls/read s :all) must return "
                      "nil - a returned buffer is truthy and never "
                      "terminates a read loop - where cfun_chunk "
                      "(src/jtls/api/io.c:168-170) and the async "
                      "TLS_OP_CHUNK completion (src/jtls/state_machine.c:"
                      "678-683) unconditionally wrap the buffer even "
                      "when nothing was appended; observed: {:chunk %s "
                      ":read-all %s :read-all-prefilled %s}")
              obs-chunk obs-read-all obs-prefilled))))
