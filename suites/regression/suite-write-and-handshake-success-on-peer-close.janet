# Writes and handshakes report success on peer close/EOF regression test
# Ticket 084cc8cb6f7f2f7609f0fd03b5571e1a1e856e44
#
# "Writes and handshakes report success on peer close/EOF"
#
# handle_ssl_error (src/jtls/state_machine.c:137-178) maps
# SSL_ERROR_ZERO_RETURN (state_machine.c:147-150) and SSL_ERROR_SYSCALL
# with ret==0 or sock_err==0 (state_machine.c:152-159) to TLS_IO_COMPLETE
# for EVERY operation, regardless of what the operation needed to
# accomplish. The two consumers that turn this into silent success:
#   - TLS_OP_WRITE (state_machine.c:375-399): the loop at :376 only
#     finishes honestly when write_offset reaches write_len (:387-388).
#     When handle_ssl_error returns COMPLETE at :393-394 with
#     write_offset < write_len, cfun_write (src/jtls/api/io.c:183-224)
#     hands back nil - "success" - while bytes remain unwritten. Silent
#     data loss.
#   - TLS_OP_HANDSHAKE (state_machine.c:217-233): SSL_connect/SSL_accept
#     sets conn_state = TLS_CONN_READY only on ret == 1 (:223). When
#     handle_ssl_error returns COMPLETE at :231-232 with conn_state
#     still TLS_CONN_HANDSHAKING, cfun_wrap (src/jtls/api/connect.c:
#     379-380) hands back the stream instead of raising.
# errno is read at state_machine.c:153 (jsec_socket_errno) AFTER
# SSL_get_error has run at :230/:392, so the ret==0/sock_err==0 EOF
# heuristic is taken on stale state.
#
# Mechanism exercised here (OpenSSL 3.x ZERO_RETURN surface, which the
# defect maps to COMPLETE for every op on every backend): a raw TCP peer
# accepts the TCP connection, reads the ClientHello, then answers with a
# TLS close_notify alert record (15 03 03 00 02 01 00) and closes. The
# client's SSL_connect consumes the close_notify mid-handshake: the
# handshake ends with conn_state != READY (no ServerHello was ever
# sent), yet handle_ssl_error reports COMPLETE.
#
# This test demonstrates:
#   (a) a write against a peer-closed connection does NOT report
#       success while bytes remain unwritten: the 64 MiB payload of the
#       write below can never be delivered (the peer is gone and no TLS
#       connection was ever established), so a correct implementation
#       must raise; under the defect the write returns nil ("success")
#       with write_offset 0 still less than write_len 67108864.
#   (b) a handshake ending not-READY raises instead of returning a
#       stream: tls/wrap must raise because the handshake consumed a
#       peer close instead of completing; under the defect it hands
#       back a stream whose conn_state never reached TLS_CONN_READY.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (write returns nil with bytes unwritten; handshake
# returns a stream instead of raising); under fixed code the whole test
# passes.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# TLS close_notify alert: content type 21 (alert), record version 3.3,
# length 2, level 1 (warning), description 0 (close_notify).
(def close-notify @"\x15\x03\x03\x00\x02\x01\x00")

(defn- peer-close-server
  ``Raw TCP peer: accept one connection, read the ClientHello, answer
   with a clean TLS close_notify, then close. Nothing else is ever sent,
   so any handshake that reports success is lying. Returns [server port].``
  []
  (def [server socket-path] (make-server :tcp))
  (def [_ port] (net/localname server))
  (ev/go
    (fn []
      (try
        (do
          (with [conn (:accept server)]
            (def buf @"")
            (:read conn 8192 buf 2)
            (:write conn close-notify)
            (ev/sleep 0.2)
            (:close conn)))
        ([_] nil))))
  [server port])

(def-suite :name "Success On Peer Close Regression"
  :description "Ticket 084cc8cb6f: writes and handshakes must not report success on peer close/EOF"

  (def-test "handshake ending not-ready raises instead of returning a stream"
    :timeout 15

    (def [server port] (peer-close-server))
    (defer (:close server)
      (with [conn (net/connect "127.0.0.1" port)]
        (var outcome :none)
        (try
          (do
            (def s (tls/wrap conn "127.0.0.1" {:verify false}))
            (set outcome [:returned-stream (if s :stream nil)]))
          ([e] (set outcome [:raised (string e)])))
        (assert (= :raised (first outcome))
                (string/format
                  (string "a handshake that ends before the connection is "
                          "READY must raise, not hand back a stream "
                          "(conn_state never reached TLS_CONN_READY; the "
                          "peer answered the ClientHello with close_notify "
                          "and closed): got %q")
                  outcome)))))

  (def-test "write against peer-closed connection does not report success"
    :timeout 15

    (def [server port] (peer-close-server))
    (defer (:close server)
      (with [conn (net/connect "127.0.0.1" port)]
        # 64 MiB cannot be absorbed by any loopback socket buffer pair,
        # so a nil ("success") return here means handle_ssl_error mapped
        # the peer close to TLS_IO_COMPLETE with write_offset 0 still
        # less than write_len 67108864 - every byte unwritten.
        (def payload (string/repeat "A" 67108864))
        (var outcome :none)
        (try
          (do
            (def s (tls/wrap conn "127.0.0.1" {:verify false}))
            (def r (:write s payload))
            (set outcome [:write-returned r]))
          ([e] (set outcome [:raised (string e)])))
        (assert (= :raised (first outcome))
                (string/format
                  (string "a write against a peer-closed connection must "
                          "not report success while bytes remain "
                          "unwritten (64 MiB payload, peer gone before the "
                          "first record could be written; write_offset 0 "
                          "less than write_len 67108864): got %q")
                  outcome))))))
