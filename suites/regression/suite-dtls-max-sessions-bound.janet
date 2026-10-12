# DTLS server session table is unbounded regression test
# Ticket 354d6b64f53713de37295506566a6a7dc3fc67c0
#
# "Bound DTLS server session table with :max-sessions to prevent UDP
# flood memory exhaustion"
#
# Mechanism (this tree): process_datagram (src/jdtls/server.c:465-548)
# creates a session for every datagram whose source address is new
# (the create block at src/jdtls/server.c:469-478) through
# dtls_server_create_session (src/jdtls/session.c:124-144), which
# prepends to the hash table and increments server->session_count at
# src/jdtls/session.c:141 with no upper bound. Each session owns an
# OpenSSL SSL object plus two memory BIOs (dtls_session_new,
# src/jdtls/session.c:34-76), so the table grows into real process
# memory. dtls/listen has no :max-sessions option at all - the option
# parse at src/jdtls/server.c:321-336 reads :session-timeout and
# company and silently ignores unknown keys - and the only reclamation
# is dtls_server_cleanup_expired (src/jdtls/session.c:169-188), which
# removes just sessions older than server->session_timeout (default
# DTLS_SESSION_TIMEOUT 300s, src/jdtls/internal.h:263). A burst of UDP
# datagrams from distinct source addresses therefore grows
# server->session_count (src/jdtls/internal.h:270) without limit and
# exhausts process memory before any cleanup can run.
#
# This test demonstrates:
#   (a) dtls/listen with :max-sessions 4 must bound the server session
#       table: after 20 datagrams from distinct source addresses, the
#       sessions that survive must number at most 4 in total, because
#       server->session_count counts every session,
#   (b) the bound holds while a peer is mid-handshake: every flood
#       datagram is a DTLS handshake record carrying a truncated
#       client_hello fragment, so SSL_do_handshake buffers the
#       fragment, wants the rest (SSL_ERROR_WANT_READ), and parks the
#       peer in DTLS_STATE_HANDSHAKING - the unestablished session
#       class the bound must cap - and one established barrier session
#       occupies a slot for the whole flood,
#   (c) the counting itself never disturbs the table: each flood peer
#       is classified through dtls/send-to, whose lookup failure
#       "no session for peer address" (src/jdtls/server.c:830) and
#       state failure "session not established"
#       (src/jdtls/server.c:834) distinguish a peer whose session was
#       reclaimed from one whose session is still held.
#
# Proof contract: under the defect the test fails on purpose with the
# predicted symptom - :max-sessions is ignored and all 20 flood peers
# still hold sessions - and it becomes the regression guard once the
# fix lands.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

# A DTLS handshake record (type 22, DTLS 1.2, epoch 0, seq 0, length
# 22) holding a client_hello handshake message that claims a 200-byte
# body but carries only the first 10 fragment bytes (message_seq 0,
# fragment_offset 0, fragment_length 10). The message is incomplete,
# so a server session buffers it and wants the rest instead of failing:
# the datagram parks an unestablished DTLS_STATE_HANDSHAKING session,
# exactly like a peer whose first handshake flight is still in flight.
(def flood-datagram
  (string
    "\x16\xFE\xFD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16"
    "\x01\x00\x00\xC8\x00\x00\x00\x00\x00\x00\x00\x0A"
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"))

(def-suite :name "DTLS Max Sessions Bound Regression"
  :description "Ticket 354d6b64f5: :max-sessions must bound the DTLS server session table against a UDP flood"

  (def-test "distinct-peer-flood-must-not-grow-session-table-past-max-sessions"
    :timeout 20

    (def max-sessions 4)
    (def flood-size 20)

    (def server (dtls/listen "127.0.0.1" "0"
                             {:cert (certs :cert)
                              :key (certs :key)
                              :max-sessions max-sessions}))
    (def [_ port] (dtls/localname server))

    (defer (:close server)

      # Server recv loop: drives process_datagram; reports each
      # application-data return on done so the flood can be synced.
      (def done (ev/chan 8))
      (ev/go (fn []
               (try
                 (forever
                   (def buf (buffer/new 4096))
                   (ev/give done [:data (dtls/recv-from server 4096 buf)]))
                 ([err] (ev/give done [:end err])))))

      # The barrier holds one established session for the whole flood:
      # its application data is served only once every datagram queued
      # before it has been processed, and a faithful bound never evicts
      # an established session.
      (def barrier (dtls/connect "127.0.0.1" port {:verify false}))
      (defer (:close barrier true)

        # The flood: 20 datagrams from 20 distinct source addresses.
        (def flood-sockets @[])
        (def flood-addrs @[])
        (loop [_ :range [0 flood-size]]
          (def s (net/connect "127.0.0.1" (string port)
                              :datagram "127.0.0.1" "0"))
          (def [_ lp] (net/localname s))
          (array/push flood-sockets s)
          (array/push flood-addrs (dtls/address "127.0.0.1" lp))
          (:write s flood-datagram))
        (defer (each s flood-sockets (:close s))

          (dtls/write barrier "ping")
          (def [kind info] (ev/take done))
          (assert (= :data kind)
                  (string/format
                    (string "setup: the barrier's application data must be "
                            "served after the flood (every flood datagram "
                            "was queued first), but the server recv loop "
                            "reported %q %q")
                    kind info))

          # Count the flood sessions still held. dtls/send-to looks the
          # peer up in the session table and distinguishes the two
          # failure shapes (src/jdtls/server.c:816-847): absent peers
          # raise "no session for peer address" (:830), held but
          # unestablished peers raise "session not established" (:834).
          (var held 0)
          (def held-ports @[])
          (each a flood-addrs
            (try
              (do (dtls/send-to server a "x")
                  (++ held)
                  (array/push held-ports (dtls/address-port a)))
              ([err]
                (cond
                  (string/find "session not established" err)
                  (do (++ held)
                      (array/push held-ports (dtls/address-port a)))
                  (string/find "no session for peer address" err) nil
                  (error (string/format "unexpected probe failure: %q"
                                        err))))))

          (def observed
            (string/format
              (string "%d of the %d flood peers still hold sessions "
                      "(local ports %s)")
              held flood-size (string/join (map string held-ports) ", ")))
          (assert (<= (+ held 1) max-sessions)
                  (string/format
                    (string "dtls/listen with :max-sessions %d must bound "
                            "the DTLS server session table so "
                            "server->session_count never exceeds "
                            ":max-sessions (the cap belongs at "
                            "dtls_server_create_session, "
                            "src/jdtls/session.c:124-144, where "
                            "server->session_count is incremented at :141 "
                            "with no upper bound and every new peer "
                            "address gets a session at "
                            "src/jdtls/server.c:469-478): after a burst of "
                            "%d datagrams from distinct source addresses "
                            "the table must hold at most %d sessions - the "
                            "established barrier session plus at most %d "
                            "flood sessions - but the barrier session "
                            "alone is 1 and %s")
                    max-sessions flood-size max-sessions
                    (dec max-sessions) observed)))))))
