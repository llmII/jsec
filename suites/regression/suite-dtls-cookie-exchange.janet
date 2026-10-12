# DTLS server cookie exchange regression test
# Ticket 0eb517885287749705c2d9664896313aff4e5d0d
#
# "Enable DTLS server cookie exchange, use dedicated ex_data index,
# check RAND_bytes/HMAC, and remove dead state_machine.c callbacks"
#
# Mechanism (this tree, branch ticket-0eb517885287749705c2d9664896313aff4e5d0d
# off 0.2.0 at 2eef29afaf): cfun_dtls_listen registers
# server_generate_cookie and server_verify_cookie on the DTLSServer
# context (src/jdtls/server.c:351-352) but never sets
# SSL_OP_COOKIE_EXCHANGE on server->ctx, and process_datagram
# (src/jdtls/server.c:465-548) allocates a session for the peer on the
# first datagram (src/jdtls/server.c:468-478) and runs SSL_do_handshake
# immediately (src/jdtls/server.c:491). Nothing ever invokes
# DTLSv1_listen or requires a verified cookie before the session
# handshake, so OpenSSL never emits a HelloVerifyRequest and the
# cookie callbacks never run.
#
# This test demonstrates:
#   (a) a cookie-less first-contact ClientHello draws a
#       HelloVerifyRequest carrying a non-empty cookie before any
#       server handshake flight,
#   (b) a resend of the same ClientHello carrying that cookie is
#       admitted to the session handshake (the server answers with
#       its ServerHello flight),
# using a real OpenSSL-generated ClientHello, captured on the wire
# from a jsec dtls client and replayed verbatim at a jsec DTLSServer
# over a raw UDP socket.
#
# Predicted symptom under the defect: the cookie-less replay is
# answered with the server's full handshake flight - the first
# response message is ServerHello (handshake type 2), never
# HelloVerifyRequest (type 3) - because process_datagram starts the
# session handshake on first contact with no cookie round trip.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

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

(defn- start-server-and-worker
  "Start a DTLSServer on a loopback ephemeral port and a fiber that
   keeps dtls/recv-from running so incoming datagrams are processed
   and the server's responses go out. Returns [server port]."
  []
  (def server (dtls/listen "127.0.0.1" "0"
                           {:cert (certs :cert) :key (certs :key)}))
  (def [_ port] (dtls/localname server))
  (ev/go (fn []
           (try
             (do
               (def b (buffer/new 4096))
               (while true
                 (dtls/recv-from server 4096 b 5)))
             ([err] nil))))
  (ev/sleep 0.2)
  [server port])

(defn- first-server-reply
  "Send payload to the server from a fresh raw UDP socket and return
   the first response datagram (or nil when none arrives)."
  [port payload]
  (def sock (net/socket :datagram :ipv4))
  (def looked (net/address "127.0.0.1" port :datagram))
  (def dest (if (indexed? looked) (first looked) looked))
  (def reply (buffer/new 65536))
  (defer (net/close sock)
    (net/send-to sock dest payload)
    (try
      (do (net/recv-from sock 65536 reply 3) reply)
      ([err] nil))))

(def-suite :name "DTLS Server Cookie Exchange Regression"
  :description "Ticket 0eb5178852: a cookie-less ClientHello must draw a HelloVerifyRequest before the session handshake proceeds"

  (def-test "cookie exchange runs before the session handshake"
    :timeout 20

    # Capture a real cookie-less ClientHello on the wire and pin its
    # shape: first-contact handshake type 1 with an empty cookie
    # field (cookie length at offset 60 of an unfragmented hello).
    (def hello (capture-client-hello))
    (assert (not (empty? hello))
            "setup: the dtls client should emit its ClientHello at the sink")
    (assert (and (>= (length hello) 61) (= 0x16 (get hello 0))
                 (= 1 (get hello 13)))
            (string/format
              (string "setup: captured datagram should be a handshake "
                      "record starting with a ClientHello, got %q")
              (parse-first-msg hello)))
    (assert (= 0 (get hello 60))
            (string/format
              (string "setup: the captured first-contact ClientHello "
                      "should carry an empty cookie field, got cookie "
                      "length %d")
              (get hello 60)))

    (def [server port] (start-server-and-worker))
    (defer (:close server)

      # (a) First contact without a cookie must draw a
      # HelloVerifyRequest with a non-empty cookie before any session
      # handshake flight.
      (def reply (first-server-reply port (string hello)))
      (assert reply
              (string "the server must answer a cookie-less first-contact "
                      "ClientHello; no datagram came back"))
      (def first (parse-first-msg reply))
      (assert (= 3 (first :msg-type))
              (string/format
                (string "the first response to a cookie-less ClientHello "
                        "must be a HelloVerifyRequest carrying a non-empty "
                        "cookie (RFC 6347 cookie exchange; "
                        "cfun_dtls_listen registers server_generate_cookie "
                        "and server_verify_cookie at "
                        "src/jdtls/server.c:351-352 but "
                        "process_datagram at src/jdtls/server.c:465-548 "
                        "allocates the session and runs SSL_do_handshake "
                        "on the first datagram); got %s")
                (msg-desc first)))
      (assert (not (empty? (first :cookie)))
              (string/format
                (string "the HelloVerifyRequest must carry a non-empty "
                        "cookie for the client to echo; got cookie %q")
                (first :cookie)))

      # (b) The resend carrying that cookie must be admitted to the
      # session handshake: the server answers with its ServerHello
      # flight.
      (def with-cookie (splice-cookie hello (first :cookie)))
      (def reply2 (first-server-reply port (string with-cookie)))
      (assert reply2
              (string "the server must answer a ClientHello carrying the "
                      "verified cookie; no datagram came back"))
      (def second (parse-first-msg reply2))
      (assert (= 2 (second :msg-type))
              (string/format
                (string "a ClientHello carrying the cookie from the "
                        "HelloVerifyRequest must be admitted to the "
                        "session handshake (the server answers with its "
                        "ServerHello flight); got %s")
                (msg-desc second))))))
