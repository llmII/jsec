###
### Coverage tests for jsec/tls-stream internal API
###
### These tests exercise the low-level tls-stream module directly.
### Users should use jsec/tls instead - these are for ensuring
### internal implementation works correctly.
###

(use assay)
(import jsec/tls-stream)
(import jsec/cert)
(import ../helpers :prefix "")

(def-suite :name "TLS Stream Internal API Coverage"
  :timeout 30

  # =============================================================================
  # Direct Function Tests (not methods on TLSStream)
  # =============================================================================

  (def-test "new-context creates context directly"
    (let [ctx (tls-stream/new-context {:verify false})]
      (assert ctx "Created context")
      (assert (abstract? ctx) "Context is abstract type")))

  (def-test "set-ocsp-response on connection"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        # Server with OCSP response
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       (defer (:close tls-conn)
                         # Set mock OCSP response
                         (try
                           (tls-stream/set-ocsp-response tls-conn "mock-ocsp-data")
                           ([err] nil)) # May not be supported
                         (:write tls-conn "hello")
                         (ev/sleep 0.05))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            (:read tls-conn 10)))

        (ev/take done))))

  (def-test "accept directly on listener"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)
          ctx (tls-stream/new-context {:cert (certs :cert) :key (certs :key)})]
      (defer (:close server)
        # Server using tls-stream/accept directly on listener
        (ev/go (fn []
                 (try
                   # tls-stream/accept takes LISTENER, not raw connection
                   (with [tls-conn (tls-stream/accept server ctx)]
                     (let [data (:read tls-conn 100)]
                       (:write tls-conn data)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            (:write tls-conn "echo-test")
            (let [echo (:read tls-conn 100)]
              (assert (= (string echo) "echo-test") "Direct accept works"))))

        (ev/take done))))

  (def-test "accept-loop handles multiple clients"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [handled (ev/chan 3)
          server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)]
      (defer (:close server)
        # Start accept loop in background
        (ev/go (fn []
                 (tls-stream/accept-loop server
                                         {:cert (certs :cert) :key (certs :key)}
                                         (fn [tls-conn]
                                           (defer (:close tls-conn)
                                             (let [data (:read tls-conn 100)]
                                               (:write tls-conn data)
                                               (ev/give handled :ok)))))))

        (ev/sleep 0.1)

        # Connect 3 clients
        (for i 0 3
          (with [conn (net/connect "127.0.0.1" (string port))]
            (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
              (:write tls-conn (string "msg-" i))
              (let [echo (:read tls-conn 100)]
                (assert (= (string echo) (string "msg-" i))
                        (string "Accept loop client " i " works"))))))

        # Verify all handled
        (for i 0 3
          (assert (= :ok (ev/take handled)) (string "Handler " i " completed"))))))

  (def-test "direct stream functions read/write/shutdown"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       # Use tls-stream/read directly
                       (let [data (tls-stream/read tls-conn 100)]
                         # Use tls-stream/write directly
                         (tls-stream/write tls-conn data))
                       # Use tls-stream/shutdown directly
                       (tls-stream/shutdown tls-conn)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            (tls-stream/write tls-conn "direct-test")
            (let [echo (tls-stream/read tls-conn 100)]
              (assert (= (string echo) "direct-test") "Direct functions work"))
            (tls-stream/shutdown tls-conn)))

        (ev/take done))))

  (def-test "chunk function reads exact bytes"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)
          chunk-size 50
          test-data (string/repeat "X" chunk-size)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       # Send data in small pieces
                       (for i 0 5
                         (tls-stream/write tls-conn (string/slice test-data (* i 10) (* (+ i 1) 10)))
                         (ev/sleep 0.01))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.05)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            # Use tls-stream/chunk directly
            (def buf @"")
            (tls-stream/chunk tls-conn chunk-size buf)
            (assert (= (length buf) chunk-size)
                    (string "Chunk read exactly " chunk-size " bytes"))))

        (ev/take done))))

  (def-test "session functions get-session and session-reused?"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       (tls-stream/write tls-conn "session-test")
                       (ev/sleep 0.1)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            (tls-stream/read tls-conn 100)

            # Test tls-stream/get-session directly
            (let [session (tls-stream/get-session tls-conn)]
              (assert session "get-session returns session data"))

            # Test tls-stream/session-reused? directly
            (let [reused (tls-stream/session-reused? tls-conn)]
              (assert (boolean? reused) "session-reused? returns boolean"))))

        (ev/take done))))

  (def-test "connection info functions version/cipher/bits"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       (tls-stream/write tls-conn "info-test")
                       (ev/sleep 0.1)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:verify false})]
            (tls-stream/read tls-conn 100)

            # Test get-version directly
            (let [version (tls-stream/get-version tls-conn)]
              (assert (string? version) "get-version returns string")
              (assert (or (string/has-prefix? "TLS" version)
                          (string/has-prefix? "SSL" version))
                      "version is TLS/SSL"))

            # Test get-cipher directly
            (let [cipher (tls-stream/get-cipher tls-conn)]
              (assert (string? cipher) "get-cipher returns string")
              (assert (> (length cipher) 0) "cipher is non-empty"))

            # Test get-cipher-bits directly
            (let [bits (tls-stream/get-cipher-bits tls-conn)]
              (assert (number? bits) "get-cipher-bits returns number")
              (assert (>= bits 128) "cipher bits >= 128"))

            # Test get-connection-info directly
            (let [info (tls-stream/get-connection-info tls-conn)]
              (assert (struct? info) "get-connection-info returns struct")
              (assert (info :version) "info has :version")
              (assert (info :cipher) "info has :cipher"))))

        (ev/take done))))

  (def-test "trust-cert on context"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [ctx (tls-stream/new-context {:verify true})
          _ (tls-stream/trust-cert ctx (certs :cert))
          server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn {:cert (certs :cert) :key (certs :key)})]
                       (tls-stream/write tls-conn "trusted")))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Connect using context with trusted cert
        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost" {:context ctx})]
            (let [data (tls-stream/read tls-conn 100)]
              (assert (= (string data) "trusted") "Trust cert on context works"))))

        (ev/take done))))

  (def-test "listen directly creates raw listener"
    (let [listener (tls-stream/listen "127.0.0.1" "0" {})]
      (defer (:close listener)
        (assert listener "Created listener")
        # Listener should be a core stream (not TLSStream)
        (let [[_ port] (net/localname listener)]
          (assert (> port 0) "Listener has valid port")))))

  (def-test "renegotiate on TLS 1.2"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn
                                                      {:cert (certs :cert) :key (certs :key)
                                                       :min-version :TLS1_2 :max-version :TLS1_2})]
                       (tls-stream/read tls-conn 100)
                       (tls-stream/write tls-conn "renegotiated")
                       (ev/sleep 0.1)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost"
                                           {:verify false :min-version :TLS1_2 :max-version :TLS1_2})]
            (tls-stream/write tls-conn "test")
            # Try renegotiate (may or may not succeed)
            (try
              (tls-stream/renegotiate tls-conn)
              ([err] nil))
            (let [data (tls-stream/read tls-conn 100)]
              (assert (= (string data) "renegotiated") "Renegotiate test completed"))))

        (ev/take done))))

  (def-test "key-update on TLS 1.3"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn
                                                      {:cert (certs :cert) :key (certs :key)
                                                       :min-version :TLS1_3})]
                       (tls-stream/read tls-conn 100)
                       (tls-stream/write tls-conn "key-updated")
                       (ev/sleep 0.1)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost"
                                           {:verify false :min-version :TLS1_3})]
            (tls-stream/write tls-conn "test")
            # Try key-update
            (try
              (tls-stream/key-update tls-conn)
              ([err] nil))
            (let [data (tls-stream/read tls-conn 100)]
              (assert (= (string data) "key-updated") "Key-update test completed"))))

        (ev/take done))))

  (def-test "handshake timing measurement"
    :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "localhost"}))}]
    (let [server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [tls-conn (tls-stream/wrap conn
                                                      {:cert (certs :cert) :key (certs :key) :handshake-timing true})]
                       (tls-stream/write tls-conn "timing")
                       (ev/sleep 0.1)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls-stream/wrap conn "localhost"
                                           {:verify false :handshake-timing true})]
            (tls-stream/read tls-conn 100)
            # Test get-handshake-time directly
            (let [hs-time (tls-stream/get-handshake-time tls-conn)]
              (assert (or (nil? hs-time) (number? hs-time))
                      "get-handshake-time returns number or nil")
              (when hs-time
                (assert (> hs-time 0) "handshake time is positive")))))

        (ev/take done)))))
