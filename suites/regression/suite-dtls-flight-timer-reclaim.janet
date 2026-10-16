# DTLS flight timer reclaim regression test (combined wave guard)
#
# Combined guard for the jdtls staging wave. It spans the three change
# sets that compose the DTLS server datagram path and belongs to the
# wave, not to any one ticket branch: the flight timer work
# (ticket 5689f2ba70f1c6936e4b003ddf3719df55a2b3a8), the :max-sessions
# bound (ticket 354d6b64f53713de37295506566a6a7dc3fc67c0) and the
# stateless cookie gate (ticket 0eb517885287749705c2d9664896313aff4e5d0d).
#
# Purpose: keep the composed behavior covered - a DTLS flight timer
# retires cleanly when its session is reclaimed, across BOTH the
# :max-sessions eviction path and the cookie-gate admit-failure cleanup
# path (plus the handshake-failure cleanup shape the combined smoke
# also covered and the exit-armed teardown shape). These reclaims span
# three ticket branches and no single ticket branch's suite covers the
# composition.
#
# Mechanism (this tree): while a handshake is pending on WANT_READ,
# process_datagram arms a per-handshake DTLSFlightTimer on the session
# (src/jdtls/server.c handshake block, src/jdtls/state_machine.c DTLS
# Flight Timer). Every reclamation path frees the session through
# dtls_session_free (src/jdtls/session.c:95), which disarms the arm on
# the normal path (in_gc=0 wakes the helper fiber, which retires the
# arm at once; the GC finalizer's in_gc=1 path only marks the arm
# canceled). The reclaim sites guarded here:
#   (A) dtls_server_create_session at the :max-sessions bound evicts
#       the least-recently-active unestablished session
#       (src/jdtls/session.c:147-174) - an armed HANDSHAKING victim;
#   (B) a failed cookie-gate admit: dtls_server_admit_resend fails and
#       dtls_server_remove_session frees the just-created (fresh,
#       unarmed) session (src/jdtls/server.c:937-940);
#   (B1) the handshake-failure cleanup on the same remove_session
#       path, with the WANT_READ arm live
#       (src/jdtls/server.c:963-969);
#   (C) process teardown with the arm still armed: the janet_deinit
#       sweep runs dtls_server_gc -> dtls_session_free(session, 1) ->
#       the in_gc disarm.
#
# Scenario B is driven from the wire. The cookie gate verifies the
# echoed cookie with server_cookie_verify while dtls_server_admit_resend
# re-synthesizes the hello strictly as one unfragmented record carrying
# a complete message (server_synth_client_hello,
# src/jdtls/server.c:782-816): a verified resend with trailing bytes
# past its single record is ADMITTED by the gate (whose parse
# (src/jdtls/server.c:685-715) reads only the first record) and then
# fails the admit - exactly the dtls_server_admit_resend failure then
# dtls_server_remove_session shape. A resend of the same shape with a
# corrupted cookie byte draws a HelloVerifyRequest, pinning that the
# gate parses the trailing-bytes shape and that the cookie verdict is
# what decides the admit. This is a wire-only provocation: no
# production hook is used or needed.
#
# Behavior-free observability map (this guard instruments NO
# production code): the arm itself is not observable from the wire, so
# each retire-shape assertion is pinned through its observable
# consequences. The unique-arm scoping of the combined smoke's log
# assertions is realized as each victim's unique raw-UDP socket - the
# unique flush target of that session's unique flight-timer arm - since
# a freed DTLSSession block can be recycled by a later allocation and
# owner-pointer identity proves nothing:
#   "the arm was armed (WANT_READ) before the reclaim"  ->
#       the server flight parks the session (dtls/send-to reports
#       "session not established") and the armed timer retransmits
#       that flight onto the victim's socket before the reclaim;
#   "the reclaim frees the session on the normal path"  ->
#       dtls/send-to reports "no session for peer address" (the
#       reclaim call sites run dtls_session_free(..., 0), the normal
#       in_gc=0 path);
#   "no residual wake/TICK/FLUSH attributed to the freed arm"  ->
#       the victim's socket stays silent across a window past the DTLS
#       retransmission interval, where the freed arm's next tick would
#       have landed;
#   "clean exit after the retransmission interval"  ->
#       the test completes through the window, the barrier session
#       keeps serving application data, and (C) a parked-armed child
#       process exits 0 through the janet_deinit sweep.
#
# Proof contract: a reclamation path that leaves its flight timer armed
# shows up as a residual retransmission datagram on the freed session's
# socket (or a use-of-freed-state crash) inside the silence window; a
# cleanup that leaks the reclaimed session shows up as "session not
# established" where "no session for peer address" is required.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

# =============================================================================
# Wire helpers (suites/regression/suite-dtls-cookie-exchange.janet idiom)
# =============================================================================

(defn- put-u16
  "Patch a big-endian two-byte field of buffer b at index i to value v."
  [b i v]
  (put b i (brshift v 8))
  (put b (+ i 1) (band v 0xff)))

(defn- put-u24
  "Patch a big-endian three-byte field of buffer b at index i to value v."
  [b i v]
  (put b i (brshift v 16))
  (put b (+ i 1) (band (brshift v 8) 0xff))
  (put b (+ i 2) (band v 0xff)))

(defn- get-u16
  [b i]
  (+ (blshift (get b i) 8) (get b (+ i 1))))

(defn- get-u24
  [b i]
  (+ (blshift (get b i) 16) (blshift (get b (+ i 1)) 8) (get b (+ i 2))))

(defn- parse-first-msg
  "Parse the first record and first handshake message of a DTLS
   datagram. Returns a table with :rec-type and, for handshake
   records, :msg-type and, for HelloVerifyRequest (type 3), :cookie."
  [dg]
  (def out @{:rec-type (get dg 0)})
  (when (and (= 0x16 (out :rec-type)) (>= (length dg) 28))
    (put out :rec-len (get-u16 dg 11))
    (put out :msg-type (get dg 13))
    (put out :msg-len (get-u24 dg 14))
    (when (= 3 (out :msg-type))
      (def cookie-len (get dg 27))
      (put out :cookie (string (slice dg 28 (+ 28 cookie-len))))))
  out)

(defn- msg-desc
  "Compact description of a parsed first message for failure text."
  [parsed]
  (cond
    (nil? parsed) "no datagram"
    (not= 0x16 (parsed :rec-type))
    (string "a non-handshake record of type " (parsed :rec-type))
    (nil? (parsed :msg-type))
    "a short handshake record"
    (= 3 (parsed :msg-type))
    (string "a HelloVerifyRequest with cookie length "
            (length (or (parsed :cookie) "")))
    (= 2 (parsed :msg-type))
    "a ServerHello (handshake type 2) - a session handshake flight"
    (string "handshake message type " (parsed :msg-type))))

(defn- capture-client-hello
  "Capture the ClientHello a jsec dtls client puts on the wire.
   The client talks to a raw UDP sink that never answers, so its
   first flight is the cookie-less ClientHello; the client fiber is
   bounded by a deadline and abandoned. Returns the datagram."
  []
  (def sink (net/listen "127.0.0.1" "0" :datagram))
  (def [_ sink-port] (net/localname sink))
  (def hello (buffer/new 1024))
  (ev/go (fn []
           (try
             (net/recv-from sink 65536 hello 5)
             ([err] nil))))
  (ev/go (fn []
           (try
             (ev/with-deadline 3
               (dtls/connect "127.0.0.1" sink-port {:verify false}))
             ([err] nil))))
  (var waited 0.0)
  (while (and (empty? hello) (< waited 5))
    (ev/sleep 0.05)
    (+= waited 0.05))
  (net/close sink)
  hello)

(defn- splice-cookie
  "Return the captured ClientHello with cookie (bytes) inserted in
   its cookie field (empty in a first-contact hello) and the record,
   handshake and fragment lengths patched to match."
  [hello cookie]
  (def out (buffer/new (+ (length hello) (length cookie) 4)))
  (buffer/push out (take 60 hello))
  (buffer/push out (string/from-bytes (length cookie)))
  (buffer/push out cookie)
  (buffer/push out (drop 61 hello))
  (def delta (length cookie))
  (put-u16 out 11 (+ (get-u16 hello 11) delta))
  (put-u24 out 14 (+ (get-u24 hello 14) delta))
  (put-u24 out 22 (+ (get-u24 hello 22) delta))
  out)

# =============================================================================
# Raw UDP helpers (suite-dtls-cookie-exchange.janet first-server-reply idiom)
# =============================================================================

(defn- raw-socket [] (net/socket :datagram :ipv4))

(defn- server-dest
  [port]
  (def looked (net/address "127.0.0.1" (string port) :datagram))
  (if (indexed? looked) (first looked) looked))

(defn- raw-send
  [sock port payload]
  (net/send-to sock (server-dest port) payload))

(defn- raw-recv
  "One datagram at sock within timeout seconds, or nil on timeout."
  [sock timeout]
  (def reply (buffer/new 65536))
  (try
    (do (net/recv-from sock 65536 reply timeout) reply)
    ([err] nil)))

(defn- raw-local-port
  [sock]
  (def looked (net/localname sock))
  (def unpacked (if (indexed? looked) looked (net/address-unpack looked)))
  (last unpacked))

(defn- probe-session
  "Classify the server's table entry for addr through dtls/send-to
   (src/jdtls/server.c:816-847): :established, :handshaking (held but
   unestablished), or :absent."
  [server addr]
  (try
    (do (dtls/send-to server addr "x") :established)
    ([err]
      (cond
        (string/find "session not established" err) :handshaking
        (string/find "no session for peer address" err) :absent
        [:other err]))))

(defn- start-server-and-echo
  "Start a DTLSServer with opts and a worker fiber that answers every
   application datagram with PONG, recording what it received.
   The worker rides out idle recv timeouts so the event loop stays
   served across the guard's silent windows. Returns
   [server port received]."
  [opts]
  (def server (dtls/listen "127.0.0.1" "0" opts))
  (def [_ port] (dtls/localname server))
  (def received (buffer/new 64))
  (ev/go
    (fn []
      (def b (buffer/new 4096))
      (var running true)
      (while running
        (try
          (do
            (def addr (dtls/recv-from server 4096 b 1))
            (when addr
              (buffer/push received b)
              (buffer/clear b)
              (dtls/send-to server addr "PONG")))
          ([err]
            (if (and (string? err) (= err "timeout"))
              nil
              (set running false)))))))
  [server port received])

(defn- drive-cookie-exchange
  "Run the RFC 6347 cookie exchange from raw socket sock against
   server port with the captured hello: the cookie-less ClientHello
   must draw a HelloVerifyRequest with a non-empty cookie and the
   verified resend must be admitted to the session handshake (the
   server answers with its ServerHello flight). Returns the flight
   datagram; the caller owns sock. Flunks the test when the exchange
   does not complete."
  [port sock hello]
  (raw-send sock port (string hello))
  (def hvr (raw-recv sock 2))
  (def first-msg (parse-first-msg hvr))
  (assert (and hvr (= 3 (first-msg :msg-type)))
          (string/format
            (string "setup: a cookie-less first-contact ClientHello "
                    "must draw a HelloVerifyRequest (RFC 6347 cookie "
                    "exchange; the stateless gate at "
                    "src/jdtls/server.c:762-780 answers before any "
                    "session state exists); got %s")
            (msg-desc first-msg)))
  (assert (not (empty? (first-msg :cookie)))
          (string "setup: the HelloVerifyRequest must carry a "
                  "non-empty cookie for the peer to echo"))
  (raw-send sock port (string (splice-cookie hello (first-msg :cookie))))
  (def flight (raw-recv sock 2))
  (def flight-msg (parse-first-msg flight))
  (assert (and flight (= 2 (flight-msg :msg-type)))
          (string/format
            (string "setup: the verified-cookie resend must be "
                    "admitted to the session handshake (the server "
                    "answers with its ServerHello flight); got %s")
            (msg-desc flight-msg)))
  flight)

(defn- assert-silence
  "Assert sock receives no datagram for window seconds after the
   reclaim: the freed session's flight-timer arm must have retired at
   once, so its next tick (inside the window) never retransmits."
  [sock window label]
  (var residuals @[])
  (var waited 0.0)
  (while (< waited window)
    (def dg (raw-recv sock 0.5))
    (when dg
      (array/push residuals (string/format "%d bytes of type %d"
                                           (length dg) (get dg 0))))
    (+= waited 0.5))
  (assert (empty? residuals)
          (string/format
            (string "%s: residual datagram(s) on the reclaimed "
                    "session's socket after the free (%s): the freed "
                    "flight-timer arm must retire when "
                    "dtls_session_free disarms it (normal in_gc=0 "
                    "disarm wakes the helper fiber, which cancels and "
                    "releases the arm at once), so no wake/tick/flush "
                    "may run against the freed session - a tick would "
                    "retransmit its flight to this, the arm's unique "
                    "flush target")
            label (string/join residuals "; "))))

(defn- assert-barrier-serves
  "The barrier session must keep serving application data: it is
   established (never an eviction victim) and the server loop is
   healthy."
  [barrier received label]
  (:write barrier "ping")
  (def pong (ev/with-deadline 5 (:read barrier 1024)))
  (assert (and pong (= "PONG" (string pong)))
          (string/format
            (string "%s: the established barrier session must keep "
                    "serving application data after the reclaim; "
                    "got %q")
            label (string pong)))
  (assert (= "ping" (string received))
          (string/format
            (string "%s: the server must still receive the barrier's "
                    "application data after the reclaim; got %q")
            label (string received))))

# =============================================================================
# Scenario B's provocation datagram: a verified-cookie ClientHello whose
# datagram carries trailing bytes past the single record. The cookie
# gate's first-record parse admits it; server_synth_client_hello's
# strict one-record shape check (src/jdtls/server.c:795) fails it, so
# dtls_server_admit_resend returns 0 and the fresh session is removed.
# =============================================================================

(def- junk-tail "\x00\x00\x00\x00\x00\x00\x00\x00")

(defn- junk-resend
  "The spliced hello with junk-tail appended past its single record."
  [hello cookie]
  (string (splice-cookie hello cookie) junk-tail))

(defn- corrupt-cookie-resend
  "The junk resend with one byte inside the echoed cookie field
   flipped: the gate parses the same trailing-bytes shape but
   server_cookie_verify rejects it."
  [hello cookie]
  (def out (splice-cookie hello cookie))
  (def flip-at (+ 61 (div (length cookie) 2)))
  (put out flip-at (bxor (get out flip-at) 0xff))
  (buffer/push out junk-tail)
  out)

# =============================================================================
# Scenario C child: park an armed HANDSHAKING session through the cookie
# gate, then os/exit 0 with the WANT_READ flight timer still armed so
# the janet_deinit sweep runs the GC finalizers
# (dtls_server_gc -> dtls_session_free(session, 1) -> in_gc disarm).
# =============================================================================

(def- child-program
  ```
(import jsec/dtls-stream :as dtls)
(import jsec/cert :as cert)

(defn finish [tag msg]
  (print "RESULT:" tag ":" msg)
  (flush))

(defn- put-u16 [b i v]
  (put b i (brshift v 8))
  (put b (+ i 1) (band v 0xff)))

(defn- put-u24 [b i v]
  (put b i (brshift v 16))
  (put b (+ i 1) (band (brshift v 8) 0xff))
  (put b (+ i 2) (band v 0xff)))

(defn- get-u16 [b i]
  (+ (blshift (get b i) 8) (get b (+ i 1))))

(defn- get-u24 [b i]
  (+ (blshift (get b i) 16) (blshift (get b (+ i 1)) 8) (get b (+ i 2))))

(defn- parse-first-msg [dg]
  (def out @{:rec-type (get dg 0)})
  (when (and (= 0x16 (out :rec-type)) (>= (length dg) 28))
    (put out :rec-len (get-u16 dg 11))
    (put out :msg-type (get dg 13))
    (put out :msg-len (get-u24 dg 14))
    (when (= 3 (out :msg-type))
      (def cookie-len (get dg 27))
      (put out :cookie (string (slice dg 28 (+ 28 cookie-len))))))
  out)

(defn- capture-client-hello []
  (def sink (net/listen "127.0.0.1" "0" :datagram))
  (def [_ sink-port] (net/localname sink))
  (def hello (buffer/new 1024))
  (ev/go (fn [] (try (net/recv-from sink 65536 hello 5) ([err] nil))))
  (ev/go (fn []
           (try
             (ev/with-deadline 3
               (dtls/connect "127.0.0.1" sink-port {:verify false}))
             ([err] nil))))
  (var waited 0.0)
  (while (and (empty? hello) (< waited 5))
    (ev/sleep 0.05)
    (+= waited 0.05))
  (net/close sink)
  hello)

(defn- splice-cookie [hello cookie]
  (def out (buffer/new (+ (length hello) (length cookie) 4)))
  (buffer/push out (take 60 hello))
  (buffer/push out (string/from-bytes (length cookie)))
  (buffer/push out cookie)
  (buffer/push out (drop 61 hello))
  (def delta (length cookie))
  (put-u16 out 11 (+ (get-u16 hello 11) delta))
  (put-u24 out 14 (+ (get-u24 hello 14) delta))
  (put-u24 out 22 (+ (get-u24 hello 22) delta))
  out)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048
              :days-valid 1}))
(def server (dtls/listen "127.0.0.1" "0"
                          {:cert (certs :cert) :key (certs :key)}))
(def [_ port] (dtls/localname server))
(ev/go
  (fn []
    (def b (buffer/new 4096))
    (var running true)
    (while running
      (try
        (do (dtls/recv-from server 4096 b 1) nil)
        ([err]
          (if (and (string? err) (= err "timeout"))
            nil
            (set running false)))))))

(def hello (capture-client-hello))
(when (empty? hello)
  (finish "error" "captured-no-client-hello")
  (os/exit 1))
(def sock (net/socket :datagram :ipv4))
(def looked (net/address "127.0.0.1" (string port) :datagram))
(def dest (if (indexed? looked) (first looked) looked))
(net/send-to sock dest (string hello))
(def reply (buffer/new 65536))
(var hvr nil)
(try (do (net/recv-from sock 65536 reply 2) (set hvr (string reply)))
     ([err] nil))
(unless hvr
  (finish "error" "no-hello-verify-request")
  (os/exit 1))
(def cookie ((parse-first-msg hvr) :cookie))
(net/send-to sock dest (string (splice-cookie hello cookie)))
(def reply2 (buffer/new 65536))
(var flight nil)
(try (do (net/recv-from sock 65536 reply2 2) (set flight (string reply2)))
     ([err] nil))
(unless flight
  (finish "error" "no-server-flight")
  (os/exit 1))
(finish "ok" "exit-with-armed-flight-timer")
(os/exit 0)
```)

(defn- run-teardown-child
  "Spawn the exit-armed teardown scenario under the janet interpreter.
   Returns {:exit n :out stdout :err stderr}."
  []
  (def proc (os/spawn ["janet" "-e" child-program] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

# =============================================================================
# Suite
# =============================================================================

(def-suite :name "DTLS Flight Timer Reclaim Regression"
  :description ```
Combined wave guard across the flight timer, the :max-sessions bound and the cookie gate: a reclaimed DTLS session's flight-timer arm must retire cleanly - (A) an armed HANDSHAKING session evicted at capacity by :max-sessions, (B) a fresh session cleaned up after a failed cookie-gate admit (dtls_server_admit_resend failure then dtls_server_remove_session), (B1) the armed companion cleaned up after a handshake failure on the same remove_session path, and (C) the exit-armed teardown shape. B is driven from the wire: the gate's first-record parse admits a verified-cookie resend with trailing bytes while admit_resend's strict one-record re-synthesis fails it - the exact admit-failure cleanup shape (a bad-cookie resend of the same shape draws a HelloVerifyRequest, pinning the gate parses that shape). The guard instruments no production code: the arm is not wire-observable, so each retire-shape assertion (normal-path free, normal disarm, at-once canceled release) is pinned through its consequences - no residual retransmission datagram on the reclaimed session's unique raw-UDP socket across the DTLS retransmission interval, a live established barrier session, clean completion and a clean exit-armed process exit - and every assertion is scoped to that unique socket (the unique flush target of the session's unique arm), never to owner pointers, because a freed DTLSSession block can be recycled by a later allocation.```

  (def-test "armed-handshaking-session-evicted-at-max-sessions-capacity-retires-its-flight-timer"
    :timeout 45

    # Scenario A: a cookie-gate-admitted HANDSHAKING victim parks with
    # its WANT_READ flight timer armed, the table fills to
    # :max-sessions 2 (established barrier + victim), and a newcomer's
    # verified resend runs dtls_server_create_session at capacity,
    # which evicts the victim through dtls_session_free(victim, 0) -
    # the normal reclaim path - while the barrier (established, never
    # an eviction victim) stays.
    (def max-sessions 2)
    (def hello (capture-client-hello))
    (assert (not (empty? hello))
            "setup: the dtls client should emit its ClientHello at the sink")

    (def [server port received]
      (start-server-and-echo {:cert (certs :cert)
                              :key (certs :key)
                              :max-sessions max-sessions}))
    (defer (do
             (try (:close server) ([err] nil)))

      (def barrier (dtls/connect "127.0.0.1" (string port) {:verify false}))
      (defer (try (:close barrier true) ([err] nil))

        (def v (raw-socket))
        (defer (net/close v)
          (drive-cookie-exchange port v hello)
          (def v-addr (dtls/address "127.0.0.1" (raw-local-port v)))
          (assert (= :handshaking (probe-session server v-addr))
                  (string "setup: the cookie-gate-admitted victim must "
                          "be held and unestablished (HANDSHAKING)"))

          # The arm is armed pre-reclaim: the WANT_READ arm retransmits
          # the parked flight onto the victim's socket when its timer
          # fires. Observing that retransmission is the wire proof that
          # the arm exists and ticks before the reclaim.
          (def rexmit (raw-recv v 3))
          (assert rexmit
                  (string "the victim's WANT_READ flight timer must be "
                          "armed before the reclaim: with the raw peer "
                          "silent, the armed timer retransmits the "
                          "parked server flight onto the victim's "
                          "socket (DTLSFlightTimer wake step, "
                          "src/jdtls/state_machine.c)"))

          # The newcomer runs create_session at capacity
          # (barrier established + victim HANDSHAKING = 2/2): the only
          # unestablished occupant, the armed victim, is the eviction
          # victim (src/jdtls/session.c:147-174) and is freed on the
          # normal path (dtls_session_free(victim, 0)).
          (def n (raw-socket))
          (defer (net/close n)
            (drive-cookie-exchange port n hello)
            (def n-addr (dtls/address "127.0.0.1" (raw-local-port n)))
            (assert (= :absent (probe-session server v-addr))
                    (string/format
                      (string "the :max-sessions %d bound must reclaim "
                              "the armed victim when the newcomer's "
                              "verified resend creates a session at "
                              "capacity (eviction in "
                              "dtls_server_create_session, "
                              "src/jdtls/session.c:147-174, frees the "
                              "victim via dtls_session_free(victim, "
                              "0)): the victim's peer must report \"no "
                              "session for peer address\"")
                      max-sessions))
            (assert (= :handshaking (probe-session server n-addr))
                    (string "setup: the newcomer must hold its own "
                            "session after the eviction (its session "
                            "block may have recycled the freed "
                            "victim's, so nothing below may key on "
                            "owner pointers)"))

            # No residual wake/tick/flush against the freed arm: its
            # next scheduled tick lands inside this window, and the
            # retired arm must never retransmit against freed state.
            (assert-silence v 5 "scenario A")

            (assert-barrier-serves barrier received "scenario A"))))))

  (def-test "failed-cookie-gate-admit-cleans-up-its-fresh-session"
    :timeout 30

    # Scenario B: a gate-verified resend whose datagram carries
    # trailing bytes past its single record is admitted by the cookie
    # gate (first-record parse) and allocated by
    # dtls_server_create_session, then dtls_server_admit_resend fails
    # (server_synth_client_hello's strict one-record shape check,
    # src/jdtls/server.c:795) and dtls_server_remove_session frees the
    # just-created session (src/jdtls/server.c:937-940). The session is
    # fresh: its WANT_READ arm is set only after the handshake block,
    # which the admit path never reaches on failure, so the
    # disarm-in-free is a safe no-op on the unarmed slot.
    (def hello (capture-client-hello))
    (assert (not (empty? hello))
            "setup: the dtls client should emit its ClientHello at the sink")

    (def [server port received]
      (start-server-and-echo {:cert (certs :cert)
                              :key (certs :key)
                              :max-sessions 4}))
    (defer (do
             (try (:close server) ([err] nil)))

      (def barrier (dtls/connect "127.0.0.1" (string port) {:verify false}))
      (defer (try (:close barrier true) ([err] nil))

        (def j (raw-socket))
        (defer (net/close j)
          (raw-send j port (string hello))
          (def hvr (raw-recv j 2))
          (def first-msg (parse-first-msg hvr))
          (assert (and hvr (= 3 (first-msg :msg-type)))
                  (string/format
                    (string "setup: a cookie-less first-contact "
                            "ClientHello must draw a "
                            "HelloVerifyRequest; got %s")
                    (msg-desc first-msg)))
          (def cookie (first-msg :cookie))
          (assert (not (empty? cookie))
                  (string "setup: the HelloVerifyRequest must carry a "
                          "non-empty cookie"))

          # Vacuity pin: the SAME trailing-bytes shape with a corrupted
          # cookie byte must draw a second HelloVerifyRequest - the
          # gate parses this shape and its cookie verdict alone decides
          # the admit (src/jdtls/server.c:762-780).
          (raw-send j port (corrupt-cookie-resend hello cookie))
          (def hvr2 (raw-recv j 2))
          (def second-msg (parse-first-msg hvr2))
          (assert (and hvr2 (= 3 (second-msg :msg-type)))
                  (string/format
                    (string "setup: a trailing-bytes resend whose "
                            "cookie does not verify must draw a "
                            "HelloVerifyRequest, pinning that the "
                            "cookie gate parses the trailing-bytes "
                            "shape and admits by cookie verdict; "
                            "got %s")
                    (msg-desc second-msg)))

          # The verified-cookie trailing-bytes resend: gate admits,
          # admit fails, remove_session cleans up. Silence back is the
          # shape: the admit fails before any handshake flight.
          (raw-send j port (junk-resend hello cookie))
          (def back (raw-recv j 1))
          (assert (nil? back)
                  (string/format
                    (string "the failed-admit path must produce no "
                            "handshake flight (the admit fails before "
                            "the handshake block runs); got %s")
                    (msg-desc (parse-first-msg back))))
          (def j-addr (dtls/address "127.0.0.1" (raw-local-port j)))
          (assert (= :absent (probe-session server j-addr))
                  (string "the just-created session must be cleaned "
                          "up after the failed cookie-gate admit "
                          "(dtls_server_admit_resend failure then "
                          "dtls_server_remove_session, "
                          "src/jdtls/server.c:937-940): the peer must "
                          "report \"no session for peer address\" - "
                          "\"session not established\" means the "
                          "fresh session leaked"))

          # The session was fresh (unarmed): no arm was ever created,
          # the disarm-in-free is a safe no-op on the unarmed slot, and
          # nothing may come back to this peer - ever.
          (assert-silence j 3 "scenario B")

          (assert-barrier-serves barrier received "scenario B")))))

  (def-test "handshake-failure-cleanup-retires-the-armed-flight-timer"
    :timeout 45

    # Scenario B's armed companion on the same remove_session path
    # (the shape the combined smoke covered as B1): a cookie-gate-
    # admitted armed HANDSHAKING victim takes a fatal
    # handshake_failure alert, SSL_do_handshake fails hard (not
    # WANT_READ/WANT_WRITE), and the "Handshake failed - clean up"
    # branch frees the session through dtls_server_remove_session ->
    # dtls_session_free(session, 0) while its WANT_READ arm is live
    # (src/jdtls/server.c:963-969).
    (def hello (capture-client-hello))
    (assert (not (empty? hello))
            "setup: the dtls client should emit its ClientHello at the sink")

    (def [server port received]
      (start-server-and-echo {:cert (certs :cert)
                              :key (certs :key)
                              :max-sessions 4}))
    (defer (do
             (try (:close server) ([err] nil)))

      (def barrier (dtls/connect "127.0.0.1" (string port) {:verify false}))
      (defer (try (:close barrier true) ([err] nil))

        (def w (raw-socket))
        (defer (net/close w)
          (drive-cookie-exchange port w hello)
          (def w-addr (dtls/address "127.0.0.1" (raw-local-port w)))
          (assert (= :handshaking (probe-session server w-addr))
                  (string "setup: the cookie-gate-admitted victim must "
                          "be held and unestablished (HANDSHAKING)"))
          (def rexmit (raw-recv w 3))
          (assert rexmit
                  (string "the victim's WANT_READ flight timer must be "
                          "armed before the cleanup: with the raw peer "
                          "silent, the armed timer retransmits the "
                          "parked server flight onto the victim's "
                          "socket"))

          # A fatal handshake_failure alert (record type 21, DTLS 1.2,
          # epoch 0) at record sequence 2 - fresh after the session's
          # internal record sequences 0 and 1 (dtls_server_admit_resend
          # replays the resend through the rbio as sequences 0/1) - so
          # the record is not dropped as a replay before it fails the
          # handshake hard.
          (def alert-datagram
            (string "\x15\xFE\xFD\x00\x00"
                    (string/from-bytes 0 0 0 0 0 2)
                    "\x00\x02"
                    (string/from-bytes 2 0x28)))
          (raw-send w port alert-datagram)
          (def back (raw-recv w 1))
          (assert (nil? back)
                  (string/format
                    (string "the handshake-failure branch cleans up "
                            "and returns before any response flight "
                            "is flushed; got %s")
                    (msg-desc (parse-first-msg back))))
          (assert (= :absent (probe-session server w-addr))
                  (string "the armed victim must be cleaned up after "
                          "the fatal handshake_failure alert "
                          "(SSL_do_handshake fails hard -> \"Handshake "
                          "failed - clean up\" -> "
                          "dtls_server_remove_session -> "
                          "dtls_session_free(session, 0), "
                          "src/jdtls/server.c:963-969): the peer must "
                          "report \"no session for peer address\""))

          # The armed arm must retire with the free - no residual
          # tick/flush against the freed session.
          (assert-silence w 5 "scenario B1")

          (assert-barrier-serves barrier received "scenario B1")))))

  (def-test "teardown-exit-with-armed-flight-timer-is-clean"
    :timeout 30

    # Scenario C (the exit-armed shape the combined smoke ran 10/10
    # clean): a child process parks an armed HANDSHAKING session
    # through the cookie gate and os/exit 0s with the arm still armed,
    # so the janet_deinit sweep runs the GC finalizers
    # (dtls_server_gc -> dtls_session_free(session, 1) -> in_gc disarm,
    # which must only mark the arm canceled and clear the slot). The
    # child must observe its ServerHello flight (the WANT_READ arm site
    # is reached) and exit 0: a use-of-freed-state in the teardown
    # disarm kills the child instead.
    (def child (run-teardown-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    (assert (string/find "RESULT:ok:exit-with-armed-flight-timer" out)
            (string/format
              (string "the child must park an armed HANDSHAKING "
                      "session through the cookie gate and reach its "
                      "exit point (child exit status %d; child "
                      "stdout: %s; child stderr: %s)")
              exit (string/trim out) (string/trim err)))
    (assert (= 0 exit)
            (string/format
              (string "the janet_deinit sweep must retire the armed "
                      "flight timer cleanly (dtls_server_gc -> "
                      "dtls_session_free(session, 1) -> the in_gc "
                      "disarm marks the arm canceled and clears the "
                      "slot; the wake step's later retire must never "
                      "run against swept state): the exit-armed child "
                      "exited %d (stdout: %s; stderr: %s)")
              exit (string/trim out) (string/trim err)))))
