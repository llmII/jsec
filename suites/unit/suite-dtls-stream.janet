# DTLS Stream Test Suite (janet-assay version)
#
# Tests DTLS functionality across versions, verification modes, cert types, and ciphers.
#
# Matrix dimensions:
#   - dtls-version: [:default :dtls1.2]
#   - verify-mode: [:no-verify :verify-trusted]
#   - cert-type: [:rsa :ec-p256]
#   - cipher-group: [:aes-gcm :chacha20]
#
# Total: 2 * 2 * 2 * 2 = 16 combinations per test
#
# In janet-assay matrix tests, matrix vars are bound directly as symbols (e.g., dtls-version,
# verify-mode) rather than accessed via a config table. The harness provides additional
# bindings like 'certs' that setup functions produce.

(use assay)
(import jsec/tls :as tls)
(import jsec/dtls-stream :as dtls-stream)
(import jsec/cert :as cert)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

# =============================================================================
# DTLS-specific helpers
# =============================================================================

(defn- make-dtls-server-opts
  "Build DTLS server options from matrix vars and certs.
   Matrix vars: dtls-version, cipher-group
   Certs: table with :cert and :key"
  [dtls-version cipher-group certs]
  (let [opts @{:datagram true
               :cert (certs :cert)
               :key (certs :key)}]
    (unless (= dtls-version :default)
      (put opts :dtls-version dtls-version))
    (case cipher-group
      :aes-gcm (put opts :ciphersuites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
      :chacha20 (put opts :ciphersuites "TLS_CHACHA20_POLY1305_SHA256"))
    opts))

(defn- make-dtls-client-opts
  "Build DTLS client options from matrix vars and certs.
   Matrix vars: verify-mode, cipher-group
   Certs: table with :cert and :key (for trusted verification)"
  [verify-mode cipher-group certs]
  (let [opts @{:datagram true}]
    (case verify-mode
      :no-verify (put opts :verify false)
      :verify-trusted (do
                        (put opts :verify true)
                        (put opts :trusted-cert (certs :cert))
                        (put opts :hostname "127.0.0.1")))
    (case cipher-group
      :aes-gcm (put opts :ciphersuites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
      :chacha20 (put opts :ciphersuites "TLS_CHACHA20_POLY1305_SHA256"))
    opts))

(defn- make-connected-udp-pair
  ``Create two mutually connected UDP sockets.
   dtls/upgrade needs a connected socket on both ends (it reads the peer
   address with getpeername), and the datagram server exposes no per-peer
   stream, so server-side stream tests drive a pair of connected sockets and
   upgrade each end - one in server mode. Two throwaway listeners reserve
   free ports; each outgoing socket then binds one of them and connects to
   the other, so each socket is the other's peer. Returns [sock-a sock-b].``
  []
  (let [tmp1 (net/listen "127.0.0.1" 0 :datagram)
        tmp2 (net/listen "127.0.0.1" 0 :datagram)
        p1 (get (net/localname tmp1) 1)
        p2 (get (net/localname tmp2) 1)]
    (:close tmp1)
    (:close tmp2)
    (def a (net/connect "127.0.0.1" (string p2) :datagram "127.0.0.1" (string p1)))
    (def b (net/connect "127.0.0.1" (string p1) :datagram "127.0.0.1" (string p2)))
    [a b]))

# =============================================================================
# Suite Definition
# =============================================================================

(def-suite :name "DTLS Stream Suite"

  # ===========================================================================
  # Non-Matrix Tests (Basic Functionality)
  # ===========================================================================

  (def-test "Address Type"
    (let [addr (tls/address "192.168.1.1" 443)]
      (assert (tls/address? addr) "Created address")
      (assert (= (tls/address-host addr) "192.168.1.1") "Host matches")
      (assert (= (tls/address-port addr) 443) "Port matches")))

  (def-test "IPv6 Address"
    (let [addr (tls/address "::1" 8443)]
      (assert (tls/address? addr) "Created IPv6 address")
      (assert (= (tls/address-host addr) "::1") "IPv6 host matches")
      (assert (= (tls/address-port addr) 8443) "IPv6 port matches")))

  (def-test "Timeout"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [_ port] (:localname server)
          timed-out (ev/chan 1)]

      (ev/go
        (fn []
          (try
            (ev/with-deadline 2
              (def buf (buffer/new 1024))
              (:recv-from server 1024 buf)
              (ev/give timed-out false))
            ([_]
              (ev/give timed-out true)))))

      (def result (ev/take timed-out))
      (:close server)
      (assert result "Server recv timed out as expected")))

  (def-test "Invalid port connection fails"
    :expected-fail "Connection to invalid port should fail"
    (ev/with-deadline 2
      (def client (tls/connect "127.0.0.1" 1 {:datagram true :verify false}))
      (:write client "test")))

  (def-test "Bad cert verification fails"
    :expected-fail "Verification with wrong cert should fail"
    (let [server-certs (generate-temp-certs {:common-name "server.local"})
          other-certs (generate-temp-certs {:common-name "other.local"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (server-certs :cert) :key (server-certs :key)})
          [_ port] (:localname server)]
      (defer (:close server)
        (ev/with-deadline 3
          (def client (tls/connect "127.0.0.1" port
                                   {:datagram true :verify true :trusted-cert (other-certs :cert)}))
          (:write client "test")))))

  (def-test "flush returns the client itself and raises on closed client"
    :timeout 20
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [_ port] (:localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go
          (fn []
            (try
              (do
                (def buf (buffer/new 1024))
                (def addr (:recv-from server 1024 buf))
                (when addr (:send-to server addr "Pong")))
              ([_] nil))
            (ev/give done true)))

        (def client (tls/connect "127.0.0.1" port {:datagram true :verify false}))
        (:write client "Ping")
        (assert (:read client 1024) "setup: client should receive the Pong reply")
        (ev/take done)

        # flush returns the client itself, matching net/flush
        (assert (= client (:flush client))
                ":flush must return the client itself like net/flush")
        (assert (= client (dtls-stream/flush client))
                "dtls-stream/flush must return the client itself")

        # Negative shapes: a closed client raises [DTLS:IO]
        (:close client true)
        (assert-error (:flush client)
                      "closed client :flush must raise [DTLS:IO]")
        (assert-error (dtls-stream/flush client)
                      "closed client dtls-stream/flush must raise [DTLS:IO]"))))

  (def-test "Server localname"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [host port] (:localname server)]
      (:close server)
      (assert (= host "127.0.0.1") "Host is localhost")
      (assert (> port 0) "Port was assigned")))

  (def-test "DTLS verify-hostname option"
    (let [certs (generate-temp-certs {:common-name "localhost"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [_ port] (:localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (def buf (buffer/new 1024))
               (try
                 (ev/with-deadline 5
                   (when-let [addr (:recv-from server 1024 buf)]
                     (:send-to server addr "hello")))
                 ([_] nil))
               (ev/give done true)))

      (ev/sleep 0.2)

      (let [client (tls/connect "127.0.0.1" port
                                {:datagram true
                                 :verify true
                                 :trusted-cert (certs :cert)
                                 :verify-hostname "localhost"})]
        (:write client "Ping")
        (def response (string (:read client 1024)))
        (assert (= response "hello") "DTLS verify-hostname: received data")
        (:close client true))

      (ev/take done)
      (:close server)))

  # ===========================================================================
  # Matrix Tests - Comprehensive DTLS Testing
  # ===========================================================================
  #
  # All matrix tests share the same parameter space:
  #   dtls-version × verify-mode × cert-type × cipher-group
  # 
  # The harness generates certificates once per matrix combo based on cert-type.
  # Matrix vars (dtls-version, verify-mode, cert-type, cipher-group) are bound
  # directly as symbols in the test body.

  (def-test "DTLS Config Matrix"
    :type :matrix
    :matrix {:dtls-version [:default :dtls1.2]
             :verify-mode [:no-verify :verify-trusted]
             :cert-type [:rsa :ec-p256]
             :cipher-group [:aes-gcm :chacha20]}
    :parallel {:fiber 6 :thread 6 :subprocess 6}
    :harness [:certs {:setup (fn [cfg vs]
                               # cfg contains the matrix combo as a table
                               (generate-certs-for-matrix cfg))}]

    # -------------------------------------------------------------------------
    # basic echo - Simple send/receive test
    # -------------------------------------------------------------------------
    (def-test "basic echo"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "Pong")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "Ping")
        (def reply (:read client 1024))
        (assert (= (string reply) "Pong") "Got Pong")
        (:close client true)

        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # large message - Test with larger payloads
    # -------------------------------------------------------------------------
    (def-test "large message"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            msg-size 4000 # Conservative size for DTLS
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new (+ msg-size 100)))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server (+ msg-size 100) buf)]
                  (:send-to server addr buf)))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def large-msg (string/repeat "X" msg-size))
        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client large-msg)
        (def reply (:read client (+ msg-size 100)))
        (:close client true)

        (ev/take done)
        (:close server)

        (assert (= (length reply) msg-size) "Large message echoed correctly")))

    # -------------------------------------------------------------------------
    # connection info - Verify connection metadata available
    # -------------------------------------------------------------------------
    (def-test "connection info"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "info")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (:read client 1024)

        (def info (:connection-info client))
        (assert (struct? info) "Connection info is a struct")
        (when (info :cipher)
          (assert (string? (info :cipher)) "Cipher is a string"))

        (:close client true)
        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # ALPN negotiation - Application-Layer Protocol Negotiation
    # -------------------------------------------------------------------------
    (def-test "ALPN negotiation"
      (let [server-opts (merge (make-dtls-server-opts dtls-version cipher-group certs)
                               {:alpn ["h2" "http/1.1"]})
            client-opts (merge (make-dtls-client-opts verify-mode cipher-group certs)
                               {:alpn ["h2"]})
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "alpn-ok")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (def reply (:read client 1024))

        (def info (:connection-info client))

        (:close client true)
        (ev/take done)
        (:close server)

        (assert (= (string reply) "alpn-ok") "ALPN negotiation completed")))

    # -------------------------------------------------------------------------
    # multiple simultaneous clients - Concurrency test
    # -------------------------------------------------------------------------
    (def-test "multiple simultaneous clients"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            num-clients 3
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            results (ev/chan num-clients)
            server-done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (for i 0 num-clients
              (buffer/clear buf)
              (try
                (ev/with-deadline 5
                  (when-let [addr (:recv-from server 1024 buf)]
                    (:send-to server addr (string "Reply-" (string buf)))))
                ([_] nil)))
            (ev/give server-done true)))

        (ev/sleep 0.2)

        (for i 0 num-clients
          (ev/go
            (fn []
              (try
                (ev/with-deadline 5
                  (def client (tls/connect "127.0.0.1" port client-opts))
                  (:write client (string "Client-" i))
                  (def reply (:read client 1024))
                  (:close client true)
                  (ev/give results
                           {:client i
                            :success (string/has-prefix? "Reply-Client-" (string reply))}))
                ([_]
                  (ev/give results {:client i :success false}))))))

        (var successes 0)
        (for i 0 num-clients
          (let [r (ev/take results)]
            (when (r :success) (++ successes))))

        (ev/take server-done)
        (:close server)

        (assert (= successes num-clients)
                (string "All " num-clients " clients succeeded"))))

    # -------------------------------------------------------------------------
    # close with force flag - Test forced close behavior
    # -------------------------------------------------------------------------
    (def-test "close with force flag"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 3
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "done")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (:read client 1024)
        (:close client true)

        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # peer-cert - Export peer certificate DER after handshake
    # -------------------------------------------------------------------------
    (def-test "peer-cert"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (try
                   (ev/with-deadline 5
                     (when-let [addr (:recv-from server 1024 buf)]
                       (:send-to server addr "Pong")))
                   ([_] nil))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "Ping")
        (def reply (:read client 1024))
        (assert (= (string reply) "Pong") "handshake completed via echo")

        (let [peer-der (:peer-cert client)
              fn-der (dtls-stream/get-peer-cert client)]
          (assert (string? peer-der) ":peer-cert returns a string")
          (assert (= peer-der fn-der) "method and function agree")
          (assert (= peer-der (crypto/convert-cert (certs :cert) :der))
                  "DER is byte-identical to the known test certificate")
          (let [parsed (cert/parse (crypto/convert-cert peer-der :pem))
                known (cert/parse (certs :cert))]
            (assert (= (parsed :serial) (known :serial))
                    "returned DER parses to the test certificate (serial)")
            (assert (= (parsed :fingerprint-sha256) (known :fingerprint-sha256))
                    "returned DER parses to the test certificate (fingerprint)")
            (assert (= (get-in parsed [:subject :dn])
                       (get-in known [:subject :dn]))
                    "returned DER parses to the test certificate (subject)")))

        (:close client true)
        (ev/take done)
        (:close server))

      # Server side sees nil without client auth. The datagram server has no
      # per-peer stream, so the server side rides dtls/upgrade in server mode
      # over a connected UDP pair.
      (let [pair (make-connected-udp-pair)
            sock-s (pair 0)
            sock-c (pair 1)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (do
                     (def srv (dtls-stream/upgrade sock-s
                                                   {:server true
                                                    :cert (certs :cert)
                                                    :key (certs :key)}))
                     (ev/give done [:ok srv]))
                   ([err] (ev/give done [:err err])))))

        (def cli (dtls-stream/upgrade sock-c {:verify false}))
        (def res (ev/take done))
        (assert (= (res 0) :ok) (string "server-side upgrade: " (res 1)))
        (def srv (res 1))
        (assert (nil? (:peer-cert srv))
                (string "server sees nil without client auth, got: " (:peer-cert srv)))
        (:close cli true)
        (:close srv true)))

    # -------------------------------------------------------------------------
    # peer-cert mTLS - Server side sees the client certificate DER
    # -------------------------------------------------------------------------
    (def-test "peer-cert mTLS"
      (let [client-certs (generate-certs-for-matrix
                           @{:cert-type cert-type :common-name "client"})
            pair (make-connected-udp-pair)
            sock-s (pair 0)
            sock-c (pair 1)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (do
                     (def srv (dtls-stream/upgrade sock-s
                                                   {:server true
                                                    :cert (certs :cert)
                                                    :key (certs :key)
                                                    :verify true
                                                    :trusted-cert (client-certs :cert)}))
                     (ev/give done [:ok srv]))
                   ([err] (ev/give done [:err err])))))

        (def cli (dtls-stream/upgrade sock-c {:cert (client-certs :cert)
                                              :key (client-certs :key)
                                              :verify false}))
        (def res (ev/take done))
        (assert (= (res 0) :ok) (string "mTLS server-side upgrade: " (res 1)))
        (def srv (res 1))

        (def server-peer-cert (:peer-cert srv))
        (assert (string? server-peer-cert)
                (string "server received client cert DER, got: " server-peer-cert))
        (assert (= server-peer-cert (crypto/convert-cert (client-certs :cert) :der))
                "server-side DER is byte-identical to the client certificate")
        (let [parsed (cert/parse (crypto/convert-cert server-peer-cert :pem))
              known (cert/parse (client-certs :cert))]
          (assert (= (parsed :serial) (known :serial))
                  "server-side DER parses to the client certificate (serial)")
          (assert (= (parsed :fingerprint-sha256) (known :fingerprint-sha256))
                  "server-side DER parses to the client certificate (fingerprint)"))

        (:close cli true)
        (:close srv true)))

    # -------------------------------------------------------------------------
    # peer-cert failure shapes - Each failure path raises
    # -------------------------------------------------------------------------
    (def-test "peer-cert failure shapes"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (try
                   (ev/with-deadline 5
                     (when-let [addr (:recv-from server 1024 buf)]
                       (:send-to server addr "Pong")))
                   ([_] nil))
                 (ev/give done true)))

        (ev/sleep 0.2)

        # Arity mismatch raises
        (assert-error (dtls-stream/get-peer-cert) "0-arity raises")
        # Wrong argument type raises
        (assert-error (dtls-stream/get-peer-cert "not-a-stream")
                      "non-stream argument raises")
        (assert-error (dtls-stream/get-peer-cert 42)
                      "non-stream argument raises")
        (assert-error (:peer-cert 42) "method dispatch on non-stream raises")

        (let [raw (net/connect "127.0.0.1" (string port) :datagram)]
          # Wrong abstract type: a raw net stream is not a jsec/dtls-client
          (assert-error (dtls-stream/get-peer-cert raw)
                        "raw net stream raises")
          (:close raw))

        (let [client (tls/connect "127.0.0.1" port client-opts)]
          (:write client "Ping")
          (:read client 1024)
          (let [der (:peer-cert client)]
            (assert (string? der) "live stream returns DER before close"))
          # Arity mismatch raises with a live stream too
          (assert-error (dtls-stream/get-peer-cert client client)
                        "2-arity raises")
          (:close client true)
          # Closed stream raises
          (assert-error (dtls-stream/get-peer-cert client)
                        "closed stream raises")
          (assert-error (:peer-cert client)
                        "closed stream raises via method"))

        (ev/take done)
        (:close server)))))
