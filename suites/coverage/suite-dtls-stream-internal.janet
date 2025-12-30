###
### Coverage tests for jsec/dtls-stream internal API
###
### These tests exercise the low-level dtls-stream module directly.
### Users should use jsec/tls with :datagram true instead.
###

(use assay)
(import jsec/dtls-stream)
(import jsec/cert)
(import ../helpers :prefix "")

(def-suite :name "DTLS Stream Internal API Coverage"
  :timeout 30

  # =============================================================================
  # Direct Function Tests (internal API)
  # =============================================================================

  (def-test "new-context creates context directly"
    (let [ctx (dtls-stream/new-context {:verify false})]
      (assert ctx "Created context")
      (assert (abstract? ctx) "Context is abstract type")))

  (def-test "address functions work directly"
    (let [addr (dtls-stream/address "192.168.1.1" 443)]
      (assert (dtls-stream/address? addr) "address? works")
      (assert (= (dtls-stream/address-host addr) "192.168.1.1") "address-host works")
      (assert (= (dtls-stream/address-port addr) 443) "address-port works")))

  (def-test "listen creates server directly"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})]
      (defer (:close server)
        (assert server "Created server")
        (let [[_ port] (dtls-stream/localname server)]
          (assert (> port 0) "Server has valid port")))))

  (def-test "connect and read/write work directly"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        # Server fiber
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "Pong"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        # Client using dtls-stream/connect directly
        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "Ping")
            (let [reply (dtls-stream/read client 1024)]
              (assert (= (string reply) "Pong") "Direct connect/read/write works"))))

        (ev/take done))))

  (def-test "recv-from and send-to work directly"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        # Server using recv-from/send-to directly
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 # Use dtls-stream/recv-from directly
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   # Use dtls-stream/send-to directly
                   (dtls-stream/send-to server addr (string "echo:" (string buf))))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test-data")
            (let [reply (dtls-stream/read client 1024)]
              (assert (= (string reply) "echo:test-data") "recv-from/send-to work"))))

        (ev/take done))))

  (def-test "upgrade raw UDP socket to DTLS"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "upgraded"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        # Create raw UDP socket and upgrade
        (let [raw-sock (net/connect "127.0.0.1" port :datagram)
              client (dtls-stream/upgrade raw-sock {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            (let [reply (dtls-stream/read client 1024)]
              (assert (= (string reply) "upgraded") "upgrade works"))))

        (ev/take done))))

  (def-test "chunk reads exact bytes"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "ChunkData1"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            # Use dtls-stream/chunk directly
            (let [reply (dtls-stream/chunk client 10)]
              (assert (buffer? reply) "chunk returns buffer")
              (assert (= (string reply) "ChunkData1") "chunk reads correct data"))))

        (ev/take done))))

  (def-test "shutdown connection"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "before-shutdown"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            (dtls-stream/read client 1024)
            # Use dtls-stream/shutdown directly
            (dtls-stream/shutdown client)))

        (ev/take done))))

  (def-test "session and session-reused? functions"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "session"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            (dtls-stream/read client 1024)

            # Test session directly
            (let [session (dtls-stream/session client)]
              (assert (buffer? session) "session returns buffer"))

            # Test session-reused? directly
            (let [reused (dtls-stream/session-reused? client)]
              (assert (boolean? reused) "session-reused? returns boolean"))))

        (ev/take done))))

  (def-test "connection info version/cipher/bits/info"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "info"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            (dtls-stream/read client 1024)

            # Test version directly
            (let [ver (dtls-stream/version client)]
              (assert (string? ver) "version returns string")
              (assert (string/has-prefix? "DTLS" ver) "version starts with DTLS"))

            # Test cipher directly
            (let [cipher (dtls-stream/cipher client)]
              (assert (string? cipher) "cipher returns string"))

            # Test cipher-bits directly
            (let [bits (dtls-stream/cipher-bits client)]
              (assert (number? bits) "cipher-bits returns number")
              (assert (>= bits 128) "cipher bits >= 128"))

            # Test connection-info directly
            (let [info (dtls-stream/connection-info client)]
              (assert (struct? info) "connection-info returns struct")
              (assert (info :version) "info has :version")
              (assert (info :cipher) "info has :cipher"))))

        (ev/take done))))

  (def-test "localname and peername"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "names"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/write client "test")
            (dtls-stream/read client 1024)

            # Test peername directly
            (let [peer (dtls-stream/peername client)]
              (assert (dtls-stream/address? peer) "peername returns address")
              (assert (= (dtls-stream/address-port peer) port) "peername port matches"))))

        (ev/take done))))

  (def-test "trust-cert on connection"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
          [_ port] (dtls-stream/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (when addr
                   (dtls-stream/send-to server addr "trusted"))
                 (ev/give done true)))

        (ev/sleep 0.2)

        # Client with trust-cert
        (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls-stream/trust-cert client (certs :cert))
            (dtls-stream/write client "test")
            (let [reply (dtls-stream/read client 1024)]
              (assert (= (string reply) "trusted") "trust-cert works"))))

        (ev/take done))))

  (def-test "close-server"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
    (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})]
      # Use dtls-stream/close-server directly
      (dtls-stream/close-server server)
      (assert true "close-server works"))))
