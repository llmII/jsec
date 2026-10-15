# Closed-stream, JANET_ASYNC_EVENT_CLOSE, and JANET_ASYNC_EVENT_ERR parity
# Ticket b4c97ad4dc7d93a29bdee622c742011375fe0117
#
# "Align jtls and jdtls closed-stream, JANET_ASYNC_EVENT_CLOSE, and
#  JANET_ASYNC_EVENT_ERR semantics with Janet ev/net"
#
# Janet's reference semantics (core ev.c / net.c of the pinned janet
# 1.41.1 at 8b6d56ed):
#   - janet_stream_flags (ev.c:2389-2392) raises "stream is closed" when
#     an I/O primitive is called on a stream whose JANET_STREAM_CLOSED
#     flag is set. nil on a read exclusively means clean peer EOF.
#   - ev_callback_read (ev.c:2473-2476) and net_callback_accept
#     (net.c:306-309) schedule nil on JANET_ASYNC_EVENT_CLOSE.
#   - ev_callback_write (ev.c:2723-2726) cancels a parked writer with
#     "stream closed" on JANET_ASYNC_EVENT_CLOSE.
#   - a socket error that surfaces through the read attempt is reported
#     with the OS reason (ev.c:2600 janet_cancel(fiber,
#     janet_ev_lasterr())).
#
# Mechanism (this tree, re-derived at 2eef29afaf):
#   1. Closed-stream reads return nil instead of raising.
#      cfun_dtls_read (src/jdtls/api/io.c:105-148) returns
#      janet_wrap_nil() at :111-113 when client->closed or
#      DTLS_STATE_CLOSED, and cfun_dtls_chunk
#      (src/jdtls/api/io.c:210-213) delegates to it at :212, so
#      (dtls/read client n) and (dtls/chunk client n) on an
#      already-closed client hand back nil - the clean-peer-EOF answer -
#      for a programming error. cfun_dtls_recv_from
#      (src/jdtls/server.c:764-808) does the same at :771-773 for
#      server->closed. The jtls side already raises
#      tls_panic_io("stream is closed") (src/jtls/api/io.c:93-95,
#      :148-150, :187-189) and dtls/write and dtls/send-to raise too
#      (src/jdtls/api/io.c:167-169, src/jdtls/server.c:823-825), so the
#      three read entry points above are the only ones that lie.
#   2. A concurrent local close cancels parked readers instead of
#      scheduling nil. janet_stream_close (core ev.c:390-402) delivers
#      JANET_ASYNC_EVENT_CLOSE to every fiber registered on the
#      transport, and jtls_async_callback's CLOSE/ERR arm
#      (src/jtls/state_machine.c:1038-1046) cancels ALL parked
#      operations - TLS_OP_READ and TLS_OP_CHUNK included - with
#      "Connection closed" (:1043). dtls_client_async_callback
#      (src/jdtls/api/async.c:112-120) does the same with "stream
#      error" (:118) for CLIENT_OP_READ, and dtls_recv_from_callback
#      (src/jdtls/server.c:627-632) cancels parked dtls/recv-from
#      fibers with "server closed" (:630).
#   3. JANET_ASYNC_EVENT_ERR is folded into the same branch as CLOSE on
#      both stacks (src/jtls/state_machine.c:1038-1039,
#      src/jdtls/api/async.c:112-113), so a genuine socket error - the
#      connected UDP case below draws ICMP port unreachable and epoll
#      reports EPOLLERR at core ev.c:1829, :1837-1838 - is reported as
#      the hardcoded "stream error" with no OS reason and no [DTLS:IO]
#      category, instead of SO_ERROR / jsec_socket_strerror
#      (src/compat.h:211, :271) giving the specific reason the way
#      janet_ev_lasterr does at ev.c:2600.
#
# Contract pinned by the guards below (behavioral; the production fix
# lands later and must match this):
#   - Closed-handle calls raise handle-specific messages: [TLS:IO]
#     "stream is closed" on a TLSStream (tls/read, tls/chunk, tls/write;
#     a concurrent-close write cancellation also accepts the "stream
#     closed" spelling); [DTLS:IO] "DTLS client is closed" on a
#     DTLSClient (dtls/read, dtls/chunk, dtls/write); [DTLS:IO]
#     "server is closed" on a DTLSServer (dtls/recv-from, dtls/send-to).
#     nil on a read exclusively means a clean peer close_notify EOF.
#   - A concurrent local close schedules nil for a parked read (tls/read,
#     tls/chunk, dtls/read, dtls/chunk, dtls/recv-from) and cancels a
#     parked write with [TLS:IO] "stream closed" or "stream is closed".
#   - An OS-level error (JANET_ASYNC_EVENT_ERR) during a parked read
#     raises carrying the OS reason under [TLS:IO] / [DTLS:IO] - a
#     raise, never nil, never a hardcoded string. Both stacks.
#
# Platform caveat: the DTLS-side concurrent-close write cancellation is
# not exhibitable on this host - a UDP send never suspends on loopback,
# so there is no parked dtls/write to cancel. The write-cancel half of
# the contract is asserted for jtls only.
#
# Proof contract: under the defect the guards marked as failing below
# fail with exactly the predicted symptom named in their final
# assertion and nothing else - no crash, no hang, no unrelated error -
# while the fix-contract pin passes. Under fixed code every test
# passes.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

# =============================================================================
# Loopback helpers
# =============================================================================

(defn- with-dtls-pong
  ``Run body with conn bound to a live DTLS client whose server answers
   every application datagram with PONG. body is a function of conn and
   server. The helper closes both before returning.``
  [body]
  (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                             :cert (certs :cert)
                                             :key (certs :key)})]
    (let [[_ port] (:localname server)]
      (ev/go
        (fn []
          (try
            (do
              (while (def addr (:recv-from server 1024 (buffer/new 1024)))
                (:send-to server addr "PONG")))
            ([_] nil))))
      (def conn (tls/connect "127.0.0.1" (string port)
                             {:datagram true :verify false}))
      (defer (:close conn true)
        (:write conn "probe")
        (def pong (:read conn 1024))
        (assert pong "priming read should return the PONG payload")
        (body conn server)))))

(defn- with-dtls-recv-from-done
  ``Run body with server bound to a DTLS server whose first recv-from has
   already completed against a live client. body is a function of server.``
  [body]
  (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                             :cert (certs :cert)
                                             :key (certs :key)})]
    (let [[_ port] (:localname server)
          got (ev/chan 4)]
      (ev/go
        (fn []
          (var r :none)
          (try
            (do (set r (:recv-from server 1024 (buffer/new 1024)))
                (ev/give got [:ok r]))
            ([e] (ev/give got [:raised (string e)])))))
      (def conn (tls/connect "127.0.0.1" (string port)
                             {:datagram true :verify false}))
      (defer (:close conn true)
        (:write conn "probe")
        (def [tag _] (ev/take got))
        (assert (= :ok tag)
                "the priming dtls/recv-from must deliver the probe datagram")
        (body server)))))

(defn- with-tls-unread-peer
  ``Run body with conn bound to a live TLS client stream whose server-side
   peer is accepted and then never reads, so a large write parks once the
   socket buffers fill. body is a function of the client stream.``
  [body]
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (def ready (ev/chan 4))
  (ev/go
    (fn []
      (try
        (do
          (with [conn (:accept server)]
            (with [tc (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
              (ev/give ready tc)
              (ev/sleep 30))))
        ([_] (ev/give ready :no-peer)))))
  (ev/sleep 0.1)
  (def raw (net/connect "127.0.0.1" (string port)))
  (def client (tls/wrap raw {:verify false}))
  (def peer (ev/take ready))
  (assert (not= peer :no-peer) "the TLS peer must accept and wrap")
  (defer (do (:close client true) (:close server))
    (body client)))

(defn- with-tls-rst-peer
  ``Run body with client bound to a live TLS stream and peer bound to its
   server-side TLS stream. The peer completes the handshake and then
   never reads, so client writes land unread in the peer's TCP receive
   queue; closing the peer with those bytes unread makes its kernel send
   RST rather than FIN. body is a function of client and peer. The
   helper closes the client and the listening server before returning.``
  [body]
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (def ready (ev/chan 4))
  (ev/go
    (fn []
      (try
        (do
          (with [conn (:accept server)]
            (with [tc (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
              (ev/give ready tc)
              (ev/sleep 30))))
        ([_] (ev/give ready :no-peer)))))
  (ev/sleep 0.1)
  (def raw (net/connect "127.0.0.1" (string port)))
  (def client (tls/wrap raw {:verify false}))
  (def peer (ev/take ready))
  (assert (not= peer :no-peer) "the TLS peer must accept and wrap")
  (defer (do (:close client true) (:close server))
    (body client peer)))

(defn- await-outcome
  ``Take one [tag value] outcome from ch within seconds, else report a
   watchdog miss as [:watchdog msg].``
  [ch seconds]
  (def probe (ev/chan 2))
  (ev/go (fn [] (ev/give probe (ev/take ch))))
  (ev/go (fn [] (ev/sleep seconds)
               (ev/give probe [:watchdog (string "the operation was "
                                                 "still suspended after "
                                                 seconds "s")])))
  (def r (ev/take probe))
  (if (and (tuple? r) (= :watchdog (get r 0)))
    r
    r))

(defn- collect
  ``Run op in a fresh fiber and deliver [:returned v] or [:raised msg] to
   a channel.``
  [op]
  (def ch (ev/chan 4))
  (ev/go
    (fn []
      (try
        (do (def r (op)) (ev/give ch [:returned (describe r)]))
        ([e] (ev/give ch [:raised (string e)])))))
  ch)

(defn- raise-shaped?
  ``True when outcome is [:raised msg] and msg carries needle.``
  [outcome needle]
  (and (tuple? outcome)
       (= :raised (get outcome 0))
       (string/find needle (get outcome 1))))

(def-suite :name "Stream Close And Async Event Parity Regression"
  :description "Ticket b4c97ad4dc: closed-stream, JANET_ASYNC_EVENT_CLOSE and JANET_ASYNC_EVENT_ERR semantics match Janet ev/net"

  (def-test "closed dtls reads raise handle-specialized errors instead of returning nil"
    :timeout 25

    (var closed-client nil)
    (var closed-server nil)
    (with-dtls-pong
      (fn [conn server]
        (:close conn true)
        (set closed-client conn)
        (set closed-server server)))

    (var outcome :no-call)
    (try
      (do (:read closed-client 8) (set outcome [:returned-nil]))
      ([e] (set outcome [:raised (string e)])))
    (assert (and (raise-shaped? outcome "[DTLS:IO]")
                 (raise-shaped? outcome "DTLS client is closed"))
            (string/format
              (string "(dtls/read client 8) on an already-closed DTLS "
                      "client must raise [DTLS:IO] DTLS client is "
                      "closed, the handle-specialized message matching "
                      "dtls/write (src/jdtls/api/io.c:167-169) - nil on "
                      "a read exclusively means a clean peer "
                      "close_notify EOF. Under the defect "
                      "cfun_dtls_read (src/jdtls/api/io.c:111-113) "
                      "returns janet_wrap_nil() when client->closed is "
                      "set, so a programming error is reported as a "
                      "clean EOF: got %q")
              outcome))

    (set outcome :no-call)
    (try
      (do (:chunk closed-client 8) (set outcome [:returned-nil]))
      ([e] (set outcome [:raised (string e)])))
    (assert (and (raise-shaped? outcome "[DTLS:IO]")
                 (raise-shaped? outcome "DTLS client is closed"))
            (string/format
              (string "(dtls/chunk client 8) on an already-closed DTLS "
                      "client must raise [DTLS:IO] DTLS client is "
                      "closed - it delegates to cfun_dtls_read at "
                      "src/jdtls/api/io.c:212 and inherits the same "
                      "nil-on-closed hole: got %q")
              outcome))

    (:close closed-server)
    (set outcome :no-call)
    (try
      (do (:recv-from closed-server 8 (buffer/new 8))
          (set outcome [:returned-nil]))
      ([e] (set outcome [:raised (string e)])))
    (assert (and (raise-shaped? outcome "[DTLS:IO]")
                 (raise-shaped? outcome "server is closed"))
            (string/format
              (string "(dtls/recv-from server 8 buf) on an "
                      "already-closed DTLS server must raise [DTLS:IO] "
                      "server is closed, the handle-specialized "
                      "message matching dtls/send-to "
                      "(src/jdtls/server.c:823-825). Under the defect "
                      "cfun_dtls_recv_from (src/jdtls/server.c:771-773) "
                      "returns janet_wrap_nil() when server->closed is "
                      "set: got %q")
              outcome))

    (with-dtls-pong
      (fn [conn server]
        (:close server)
        (ev/sleep 0.3)
        (var eof-outcome :no-call)
        (try
          (set eof-outcome (:read conn 8))
          ([e] (set eof-outcome [:raised (string e)])))
        (assert (= eof-outcome nil)
                (string/format
                  (string "a clean peer close_notify EOF must still "
                          "return nil from dtls/read - the raise above is "
                          "only for an already-closed LOCAL handle: got %q")
                  eof-outcome)))))

  (def-test "parked tls read resumes nil on local close, not Connection closed"
    :timeout 25

    (with-tls-unread-peer
      (fn [client]
        (def ch (collect |(:read client 8)))
        (ev/sleep 0.3)
        (:close client true)
        (def [tag a] (await-outcome ch 5))
        (assert (= :returned tag)
                (string/format
                  (string "a fiber parked in tls/read when another fiber "
                          "closes the stream locally must be scheduled nil "
                          "(Janet ev_callback_read, core ev.c:2473-2476), "
                          "not cancelled. Under the defect "
                          "jtls_async_callback's CLOSE arm "
                          "(src/jtls/state_machine.c:1038-1046) cancels "
                          "every parked operation including TLS_OP_READ "
                          "with the hardcoded \"Connection closed\" at "
                          ":1043: %s %s")
                  tag a))
        (assert (= a "nil")
                (string/format
                  (string "the parked tls/read must resume with nil on a "
                          "local close; got %s %s")
                  tag a)))))

  (def-test "parked dtls read resumes nil on local close, not stream error"
    :timeout 25

    (with-dtls-pong
      (fn [conn server]
        (def ch (collect |(:read conn 8)))
        (ev/sleep 0.3)
        (:close conn true)
        (def [tag a] (await-outcome ch 5))
        (assert (= :returned tag)
                (string/format
                  (string "a fiber parked in dtls/read when another fiber "
                          "closes the stream locally must be scheduled nil, "
                          "not cancelled. Under the defect "
                          "dtls_client_async_callback's CLOSE arm "
                          "(src/jdtls/api/async.c:112-120) cancels every "
                          "parked operation including CLIENT_OP_READ with "
                          "the hardcoded \"stream error\" at :118: %s %s")
                  tag a))
        (assert (= a "nil")
                (string/format
                  (string "the parked dtls/read must resume with nil on a "
                          "local close; got %s %s")
                  tag a)))))

  (def-test "parked dtls recv-from resumes nil on local close, not server closed"
    :timeout 25

    (with-dtls-recv-from-done
      (fn [server]
        (def ch (collect |(:recv-from server 1024 (buffer/new 1024))))
        (ev/sleep 0.3)
        (:close server)
        (def [tag a] (await-outcome ch 5))
        (assert (= :returned tag)
                (string/format
                  (string "a fiber parked in dtls/recv-from when another "
                          "fiber closes the server locally must be "
                          "scheduled nil, not cancelled. Under the defect "
                          "dtls_recv_from_callback "
                          "(src/jdtls/server.c:627-632) cancels every "
                          "parked recv-from with \"server closed\" at "
                          ":630: %s %s")
                  tag a))
        (assert (= a "nil")
                (string/format
                  (string "the parked dtls/recv-from must resume with nil "
                          "on a local close; got %s %s")
                  tag a)))))

  (def-test "parked tls write is cancelled with [TLS:IO] stream closed on local close"
    :timeout 30

    (with-tls-unread-peer
      (fn [client]
        (def ch (collect |(:write client (string/repeat "A" 67108864))))
        (ev/sleep 0.8)
        (:close client true)
        (def [tag a] (await-outcome ch 8))
        (assert (= :raised tag)
                (string/format
                  (string "a fiber parked in tls/write when another fiber "
                          "closes the stream locally must be cancelled - "
                          "the bytes can never be delivered - not resumed "
                          "as a success. Under the defect the parked write "
                          "ends as %s %s")
                  tag a))
        (assert (and (string/find "[TLS:IO]" a)
                     (or (string/find "stream closed" a)
                         (string/find "stream is closed" a)))
                (string/format
                  (string "the parked tls/write must be cancelled with "
                          "[TLS:IO] stream closed or [TLS:IO] stream is "
                          "closed on a local close - both spellings are "
                          "contract-legal for a concurrent-close write "
                          "cancellation. Under the defect "
                          "jtls_async_callback's CLOSE arm "
                          "(src/jtls/state_machine.c:1038-1046) "
                          "reports the hardcoded \"Connection closed\" at "
                          ":1043 with no [TLS:IO] category: got %s %s")
                  tag a)))))

  (def-test "async socket error surfaces the OS reason, not the hardcoded stream error"
    :timeout 25

    # A connected UDP socket that draws an ICMP port unreachable gets
    # EPOLLERR (core ev.c:1829, :1837-1838) - the JANET_ASYNC_EVENT_ERR
    # this test is about. Nothing closes the client transport here, so
    # the only event the parked reader can see is the socket error.
    (with-dtls-pong
      (fn [conn server]
        (def ch (collect |(:read conn 8)))
        (ev/sleep 0.3)
        # Hard-close the server transport so the client's next datagram
        # draws ICMP port unreachable from the now-dead UDP port.
        (:close server true)
        (ev/sleep 0.2)
        (try (:write conn "poke") ([_] nil))
        (ev/sleep 0.3)
        (def [tag a] (await-outcome ch 5))
        (assert (= :raised tag)
                (string/format
                  (string "an async socket error must be reported as an "
                          "error carrying the OS reason; got %s %s")
                  tag a))
        (assert (and (string/find "[DTLS:IO]" a)
                     (or (string/find "refused" a)
                         (string/find "reset" a)
                         (string/find "unreach" a)
                         (string/find "Connection" a)))
                (string/format
                  (string "JANET_ASYNC_EVENT_ERR must be handled apart "
                          "from JANET_ASYNC_EVENT_CLOSE and report the "
                          "specific OS error reason under the [DTLS:IO] "
                          "category (SO_ERROR via getsockopt, or "
                          "jsec_socket_strerror at src/compat.h:211 and "
                          ":271, the way janet_ev_lasterr does at "
                          "ev.c:2600). Under the defect "
                          "dtls_client_async_callback folds ERR into the "
                          "CLOSE branch (src/jdtls/api/async.c:112-113) "
                          "and cancels with the hardcoded \"stream error\" "
                          "at :118, discarding the reason: got %s %s")
                  tag a)))))

  (def-test "async socket error surfaces the OS reason on the TLS stack"
    :timeout 25

    # A peer that never reads lets the client's bytes pile up unread in
    # its TCP receive queue; closing the peer then makes its kernel send
    # RST rather than FIN, so the parked reader sees the socket error
    # (the JANET_ASYNC_EVENT_ERR this test is about). Nothing closes the
    # client transport here, so the only event the parked reader can
    # see is the socket error.
    (with-tls-rst-peer
      (fn [client peer]
        (def ch (collect |(:read client 8)))
        (ev/sleep 0.3)
        # Leave unread bytes in the peer's receive queue so its close
        # sends RST rather than FIN.
        (try (:write client "poke") ([_] nil))
        (ev/sleep 0.2)
        (:close peer true)
        (ev/sleep 0.3)
        (def [tag a] (await-outcome ch 5))
        (assert (= :raised tag)
                (string/format
                  (string "an async socket error during a parked "
                          "tls/read must be reported as a raise "
                          "carrying the OS reason - a raise, never "
                          "nil, never a hardcoded string; got %s %s")
                  tag a))
        (assert (and (string/find "[TLS:IO]" a)
                     (or (string/find "refused" a)
                         (string/find "reset" a)
                         (string/find "unreach" a)
                         (string/find "Connection" a)))
                (string/format
                  (string "JANET_ASYNC_EVENT_ERR must be handled apart "
                          "from JANET_ASYNC_EVENT_CLOSE and report the "
                          "specific OS error reason under the [TLS:IO] "
                          "category (SO_ERROR via getsockopt as in "
                          "src/jtls/api/connect.c:549-563, or "
                          "jsec_socket_strerror at src/compat.h:211 "
                          "and :271, the way janet_ev_lasterr does at "
                          "ev.c:2600). Under the defect the "
                          "cancellation carries \"Read syscall error: "
                          "Connection reset by peer\" with no [TLS:IO] "
                          "category (handle_ssl_error at "
                          "src/jtls/state_machine.c:181-199 through "
                          "the retry arm :1048-1051), or the HUP drain "
                          "reports a clean nil for the reset "
                          "(src/jtls/state_machine.c:1004-1013) - "
                          "either violates the contract (a raise "
                          "carrying the OS reason; never nil; never "
                          "category-less): got %s %s")
                  tag a)))))

  (def-test "closed-handle messages are handle-specialized on the remaining entry points"
    :timeout 25

    # Fix-contract pin (this guard PASSES under the current behavior):
    # the remaining closed-handle entry points already raise the
    # handle-specialized messages today. It pins those spellings so the
    # parity fix cannot silently reword the handles that are already
    # correct - [TLS:IO] stream is closed for a TLSStream, [DTLS:IO]
    # DTLS client is closed for a DTLSClient, [DTLS:IO] server is
    # closed for a DTLSServer.
    (var outcome :no-call)
    (with-tls-unread-peer
      (fn [client]
        (:close client true)
        (try
          (do (:read client 8) (set outcome [:returned-nil]))
          ([e] (set outcome [:raised (string e)])))))
    (assert (and (raise-shaped? outcome "[TLS:IO]")
                 (raise-shaped? outcome "stream is closed"))
            (string/format
              (string "(tls/read stream 8) on an already-closed "
                      "TLSStream must raise [TLS:IO] stream is closed "
                      "(src/jtls/api/io.c:93-95), matching tls/chunk "
                      "and tls/write: got %q")
              outcome))

    (with-dtls-pong
      (fn [conn server]
        (:close conn true)
        (try
          (do (:write conn "x") (set outcome [:returned-nil]))
          ([e] (set outcome [:raised (string e)])))))
    (assert (and (raise-shaped? outcome "[DTLS:IO]")
                 (raise-shaped? outcome "DTLS client is closed"))
            (string/format
              (string "(dtls/write client \"x\") on an already-closed "
                      "DTLS client must raise [DTLS:IO] DTLS client is "
                      "closed (src/jdtls/api/io.c:167-169), the "
                      "spelling closed dtls/read and dtls/chunk must "
                      "adopt: got %q")
              outcome))

    (with-dtls-pong
      (fn [conn server]
        (def addr (:localname conn))
        (:close server)
        (try
          (do (:send-to server addr "x") (set outcome [:returned-nil]))
          ([e] (set outcome [:raised (string e)])))))
    (assert (and (raise-shaped? outcome "[DTLS:IO]")
                 (raise-shaped? outcome "server is closed"))
            (string/format
              (string "(dtls/send-to server addr \"x\") on an "
                      "already-closed DTLS server must raise [DTLS:IO] "
                      "server is closed (src/jdtls/server.c:823-825), "
                      "the spelling closed dtls/recv-from must adopt: "
                      "got %q")
              outcome)))
)
