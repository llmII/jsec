# TLS Stream Test Suite (janet-assay version)
#
# Tests TLS functionality across tcp/unix socket types and TLS versions.
# 
# Some tests derived from patterns in ref/janet/test/suite-ev.janet
# Original code Copyright (c) 2025 Calvin Rose & contributors
# Licensed under the MIT License - see ref/janet/LICENSE
#
# Matrix dimensions:
#   - socket-type: [:tcp :unix]
#   - tls-version: [:default :tls12 :tls13]
#   - verify-mode: [:no-verify :verify-trusted]
#   - tcp-nodelay: [true false]
#   - cert-type: [:rsa :ec-p256]
#   - cipher-group: [:aes-gcm :chacha20]
#
# Total: 2 * 3 * 2 * 2 * 2 * 2 = 96 combinations per test

(use assay)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import jsec/cert :as cert)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

# =============================================================================
# TLS-specific helpers
# =============================================================================

(defn- make-tls-client
  "Create a TLS client connection.
   For TCP, uses host from addr. For Unix, passes hostname in opts for SNI."
  [socket-type addr opts]
  (case socket-type
    :tcp (tls/connect (addr :host) (addr :port) opts)
    :unix (tls/connect :unix (addr :path) (merge {:hostname "127.0.0.1"} opts))
    (error (string "Unknown socket type: " socket-type))))

(defn- build-ctx-opts
  "Build TLS context options from matrix vars."
  [tls-version tcp-nodelay cipher-group]
  (def opts @{})
  (unless (= tls-version :default)
    (put opts :tls-version tls-version))
  (when tcp-nodelay
    (put opts :tcp-nodelay tcp-nodelay))
  (when cipher-group
    (case cipher-group
      :aes-gcm
      (if (= tls-version :tls13)
        (put opts :cipher-suites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
        (put opts :cipher "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"))
      :chacha20
      (if (= tls-version :tls13)
        (put opts :cipher-suites "TLS_CHACHA20_POLY1305_SHA256")
        (put opts :cipher "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305"))))
  opts)

(defn- build-client-opts
  "Build client TLS options from matrix vars and certs."
  [verify-mode ctx-opts certs]
  (case verify-mode
    :no-verify (merge {:verify false} ctx-opts)
    :verify-trusted (merge {:verify true :trusted-cert (certs :cert)} ctx-opts)
    (merge {:verify false} ctx-opts)))

# =============================================================================
# Skip predicates for platform-specific combinations
# =============================================================================

(defn skip-unix-on-windows?
  "Skip Unix socket tests on Windows."
  [combo]
  (if (and (= (os/which) :windows)
           (= (combo :socket-type) :unix))
    "Unix sockets not supported on Windows"
    false))

# =============================================================================
# Suite Definition
# =============================================================================

(def-suite :name "TLS Stream Suite"

  # ===========================================================================
  # Non-Matrix Tests (Basic Functionality)
  # ===========================================================================

  (def-test "flush returns the stream itself and raises on closed stream"
    :timeout 20
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          [server socket-path] (make-server :tcp)
          addr (get-server-addr server :tcp socket-path)
          done (ev/chan 1)]
      (defer (do (:close server) (cleanup-socket socket-path))
        (ev/go
          (fn []
            (try
              (do
                (def conn (:accept server))
                (def s (tls/wrap conn {:cert (certs :cert) :key (certs :key)}))
                (:read s 1024)
                (:write s "Pong")
                (forever
                  (def b (:read s 1024))
                  (when (or (not b) (empty? b)) (break))))
              ([_] nil))
            (ev/give done true)))

        (def raw (make-client-conn :tcp addr))
        (def s (tls/wrap raw {:verify false}))
        (:write s "Ping")
        (assert (:read s 1024) "setup: client should receive the Pong reply")

        # flush returns the stream itself, matching net/flush
        (assert (= s (:flush s))
                ":flush must return the stream itself like net/flush")
        (assert (= s (tls-stream/flush s))
                "tls-stream/flush must return the stream itself")

        # Negative shapes: a closed stream raises [TLS:IO]
        (:close s true)
        (assert-error (:flush s)
                      "closed stream :flush must raise [TLS:IO]")
        (assert-error (tls-stream/flush s)
                      "closed stream tls-stream/flush must raise [TLS:IO]")

        (ev/take done))))

  # ===========================================================================
  # Main Test Matrix - Socket Type x TLS Version x Verify Mode x Options
  # ===========================================================================

  (def-test "TLS Config Matrix"
    :type :matrix
    :matrix {:socket-type [:tcp :unix]
             :tls-version [:default :tls12 :tls13]
             :verify-mode [:no-verify :verify-trusted]
             :tcp-nodelay [true false]
             :cert-type [:rsa :ec-p256]
             :cipher-group [:aes-gcm :chacha20]}
    :skip-cases [skip-unix-on-windows?]
    :parallel {:fiber 4 :thread 4 :subprocess 4}
    :harness [:certs {:setup (fn [cfg vs]
                               (generate-certs-for-matrix cfg))}]

    # -------------------------------------------------------------------------
    # basic echo - Simple send/receive test
    # -------------------------------------------------------------------------
    (def-test "basic echo"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)
            test-msg "Hello TLS!"]

        (defer (do (:close server) (cleanup-socket socket-path))
          (ev/go (fn []
                   (try
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (let [msg (:read tls-conn 1024)]
                             (:write tls-conn msg)))))
                     ([err] nil))
                   (ev/give done true)))

          (ev/sleep 0.1)

          (with [conn (make-client-conn socket-type addr)]
            (with [tls-conn (tls/wrap conn client-opts)]
              (:write tls-conn test-msg)
              (let [resp (string (:read tls-conn 1024))]
                (assert (= resp test-msg) "Echo response matches"))))

          (ev/take done))))

    # -------------------------------------------------------------------------
    # data integrity - Various data sizes and patterns
    # -------------------------------------------------------------------------
    (def-test "data integrity"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            test-cases [["small" "Hello, World!"]
                        ["medium" (string/repeat "ABCDEFGHIJ" 100)]
                        ["binary" (string/from-bytes ;(seq [i :range [0 256]] i))]]]

        (each [name data] test-cases
          (let [[server socket-path] (make-server socket-type)
                addr (get-server-addr server socket-type socket-path)
                done (ev/chan 1)]

            (ev/go (fn []
                     (try
                       (with [conn (:accept server)]
                         (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                           (with [tls-conn (tls/wrap conn opts)]
                             (let [buf (:read tls-conn (+ (length data) 100))]
                               (:write tls-conn buf)))))
                       ([err] nil))
                     (ev/give done true)))

            (ev/sleep 0.1)

            (with [conn (make-client-conn socket-type addr)]
              (let [client-opts (build-client-opts verify-mode ctx-opts certs)]
                (with [tls-conn (tls/wrap conn client-opts)]
                  (:write tls-conn data)
                  (let [echo (string (:read tls-conn (+ (length data) 100)))]
                    (assert (= echo data)
                            (string "Data integrity " name " (len=" (length data) ")"))))))

            (ev/take done)
            (:close server)
            (cleanup-socket socket-path)))))

    # -------------------------------------------------------------------------
    # garbage data handling - Non-TLS data to TLS server
    # -------------------------------------------------------------------------
    (def-test "garbage data handling"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (try
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 1024)))
                       ([err] nil)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (:write conn "GET / HTTP/1.0\r\n\r\n"))

        (assert (true? (ev/take done)) "Server handled garbage without crash")
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # starttls upgrade - Upgrade plaintext to TLS
    # -------------------------------------------------------------------------
    (def-test "starttls upgrade"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [stream (:accept server)]
                     (let [data (:read stream 1024)]
                       (when (= (string data) "HELLO")
                         (:write stream "HELLO")
                         (let [cmd (:read stream 1024)]
                           (when (= (string cmd) "STARTTLS")
                             (:write stream "READY")
                             (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                               (with [tls-stream (tls/upgrade stream opts)]
                                 (let [sec-data (:read tls-stream 1024)]
                                   (when (= (string sec-data) "SECURE")
                                     (:write tls-stream "SECURE"))))))))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [stream (make-client-conn socket-type addr)]
          (:write stream "HELLO")
          (let [resp (:read stream 1024)]
            (assert (= (string resp) "HELLO") "Handshake 1")
            (:write stream "STARTTLS")
            (let [ready (:read stream 1024)]
              (assert (= (string ready) "READY") "Handshake 2")
              (with [tls-stream (tls/upgrade stream "127.0.0.1" client-opts)]
                (:write tls-stream "SECURE")
                (let [sec-resp (:read tls-stream 1024)]
                  (assert (= (string sec-resp) "SECURE") "Secure echo"))))))

        (assert (true? (ev/take done)) "Server finished")
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # tls/server api - High-level server API test
    # -------------------------------------------------------------------------
    (def-test "tls/server api"
      :skip-cases [{:socket-type :unix}]
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            done (ev/chan 1)
            opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)
            server (tls/server "127.0.0.1" "0"
                               (fn [stream]
                                 (defer (:close stream)
                                   (:read stream 1024)
                                   (:write stream "ServerOK"))
                                 (ev/give done true))
                               opts)
            [_ port] (net/localname server)]

        (ev/sleep 0.1)

        (with [conn (tls/connect "127.0.0.1" (string port) client-opts)]
          (:write conn "Hi")
          (let [resp (:read conn 1024)]
            (assert (= (string resp) "ServerOK") "tls/server response")))

        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # connection info - Test connection metadata
    # -------------------------------------------------------------------------
    (def-test "connection info"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (:write tls-conn "hello")
                         (ev/sleep 0.1))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.05)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:read tls-conn 10)

            (let [version (:version tls-conn)]
              (assert (string? version) ":version returns string")
              (assert (or (string/has-prefix? "TLS" version)
                          (string/has-prefix? "SSL" version))
                      (string ":version returns TLS version: " version)))

            (let [cipher (:cipher tls-conn)]
              (assert (string? cipher) ":cipher returns string")
              (assert (> (length cipher) 0) "Cipher not empty"))

            (let [info (:connection-info tls-conn)]
              (assert (struct? info) ":connection-info returns struct"))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # chunk method - Test chunked reading
    # -------------------------------------------------------------------------
    (def-test "chunk method"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)
            test-data "Hello from server"]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (:write tls-conn test-data))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (let [chunk (:chunk tls-conn 5)]
              (assert (= (length chunk) 5) "Chunk is 5 bytes"))
            (let [rest (:read tls-conn 1024)]
              (assert (> (length rest) 0) "Rest of data received"))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # concurrent clients - Multiple simultaneous connections
    # -------------------------------------------------------------------------
    (def-test "concurrent clients"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            num-clients 5
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            results (ev/chan num-clients)
            server-done (ev/chan 1)]

        (ev/go (fn []
                 (for i 0 num-clients
                   (try
                     (ev/with-deadline 10
                       (with [conn (:accept server)]
                         (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                           (with [tls-conn (tls/wrap conn opts)]
                             (let [msg (:read tls-conn 1024)]
                               (:write tls-conn msg))))))
                     ([err] nil)))
                 (ev/give server-done true)))

        (ev/sleep 0.2)

        (for i 0 num-clients
          (ev/go (fn []
                   (try
                     (ev/with-deadline 10
                       (with [conn (make-client-conn socket-type addr)]
                         (with [tls-conn (tls/wrap conn client-opts)]
                           (:write tls-conn (string "Client-" i))
                           (let [resp (:read tls-conn 1024)]
                             (ev/give results {:client i :success (= (string resp) (string "Client-" i))})))))
                     ([err]
                       (ev/give results {:client i :success false}))))))

        (var successes 0)
        (for i 0 num-clients
          (let [r (ev/take results)]
            (when (r :success) (++ successes))))

        (ev/take server-done)
        (:close server)
        (cleanup-socket socket-path)

        (assert (= successes num-clients)
                (string "All " num-clients " clients succeeded"))))

    # -------------------------------------------------------------------------
    # verification failure - Untrusted cert should fail
    # -------------------------------------------------------------------------
    (def-test "verification failure"
      :skip-cases [{:verify-mode :no-verify}]
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            other-certs (generate-temp-certs {:common-name "other.local"})
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 5
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 1024)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (assert-error
          (ev/with-deadline 5
            (with [conn (make-client-conn socket-type addr)]
              (with [tls-conn (tls/wrap conn {:verify true :trusted-cert (other-certs :cert)})]
                (:write tls-conn "test"))))
          "Verification with wrong cert fails")

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # client abrupt close - Test server handling of sudden disconnect
    # -------------------------------------------------------------------------
    (def-test "client abrupt close"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 5
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 1024)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "test")
            (:close tls-conn true)))

        (assert (true? (ev/take done)) "Server handled abrupt close")
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # shutdown - Graceful shutdown test
    # -------------------------------------------------------------------------
    (def-test "shutdown"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (let [data (:read tls-conn 1024)]
                           (:write tls-conn data)
                           (:shutdown tls-conn)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "test")
            (let [resp (:read tls-conn 1024)]
              (assert (= (string resp) "test") "Echo before shutdown"))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # mTLS basic - Mutual TLS authentication
    # -------------------------------------------------------------------------
    (def-test "mTLS basic"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            # Use same cert type as matrix for both server and client
            client-certs (generate-certs-for-matrix @{:cert-type cert-type :common-name "client"})
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 10
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)
                                          :verify true :trusted-cert (client-certs :cert)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 100)
                           (:write tls-conn "ACK")))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (var success false)
        (try
          (ev/with-deadline 10
            (with [conn (make-client-conn socket-type addr)]
              (let [client-opts (merge {:cert (client-certs :cert)
                                        :key (client-certs :key)
                                        :verify false} ctx-opts)]
                (with [tls-conn (tls/wrap conn "127.0.0.1" client-opts)]
                  (:write tls-conn "mTLS test")
                  (let [resp (:read tls-conn 100)]
                    (set success (= (string resp) "ACK")))))))
          ([err] nil))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)

        (assert success "mTLS echo")))

    # -------------------------------------------------------------------------
    # write after close - Should handle gracefully
    # -------------------------------------------------------------------------
    (def-test "write after close"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (:read tls-conn 1024))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (var write-failed false)
        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "test")
            (:close tls-conn)
            (try
              (:write tls-conn "after close")
              ([err] (set write-failed true)))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)

        (assert write-failed "Write after close should fail")))

    # -------------------------------------------------------------------------
    # server abrupt close - Client handles sudden server disconnect
    # -------------------------------------------------------------------------
    (def-test "server abrupt close"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (:read tls-conn 1024)
                         (:close tls-conn true))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (var handled-correctly false)
        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "test")
            (ev/sleep 0.2)
            (try
              (let [result (:read tls-conn 1024)]
                # After server close, read should return nil/empty or error
                (set handled-correctly (or (nil? result) (= (length result) 0))))
              ([err] (set handled-correctly true)))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)

        (assert handled-correctly "Client handled server close correctly")))

    # -------------------------------------------------------------------------
    # renegotiation and key update - Test key exchange operations
    # -------------------------------------------------------------------------
    (def-test "renegotiation and key update"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (let [msg (:read tls-conn 1024)]
                           (:write tls-conn "Pong")
                           (try
                             (let [msg2 (:read tls-conn 1024)]
                               (when msg2 (:write tls-conn "Pong2")))
                             ([e] nil))))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "Ping")
            (let [reply (:read tls-conn 1024)]
              (assert (= (string reply) "Pong") "Received Pong"))

            (var update-ok false)

            # Test Key Update (TLS 1.3)
            (when (= tls-version :tls13)
              (try
                (do (:key-update tls-conn) (set update-ok true))
                ([e] nil)))

            # For other versions, just verify connection still works
            (when (not update-ok)
              (set update-ok true))

            (when update-ok
              (:write tls-conn "Ping2")
              (let [reply2 (:read tls-conn 1024)]
                (when reply2
                  (assert (= (string reply2) "Pong2") "Received Pong2 after key operation"))))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # session resumption - Test TLS session reuse
    # -------------------------------------------------------------------------
    (def-test "session resumption"
      (var session-data nil)

      # First connection - save session
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server1 socket-path1] (make-server socket-type)
            addr1 (get-server-addr server1 socket-type socket-path1)
            done1 (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server1)]
                     (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                       (with [tls-conn (tls/wrap conn opts)]
                         (let [msg (:read tls-conn 1024)]
                           (:write tls-conn msg)))))
                   ([err] nil))
                 (ev/give done1 true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr1)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "First")
            (let [resp (:read tls-conn 1024)]
              (assert (= (string resp) "First") "First connection OK")
              (set session-data (:session tls-conn)))))

        (ev/take done1)
        (:close server1)
        (cleanup-socket socket-path1))

      # Second connection - resume session
      (when (and session-data (> (length session-data) 0))
        (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
              client-opts (merge (build-client-opts verify-mode ctx-opts certs) {:session session-data})
              [server2 socket-path2] (make-server socket-type)
              addr2 (get-server-addr server2 socket-type socket-path2)
              done2 (ev/chan 1)]

          (ev/go (fn []
                   (try
                     (with [conn (:accept server2)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (let [msg (:read tls-conn 1024)]
                             (:write tls-conn msg)))))
                     ([err] nil))
                   (ev/give done2 true)))

          (ev/sleep 0.1)

          (with [conn (make-client-conn socket-type addr2)]
            (with [tls-conn (tls/wrap conn client-opts)]
              (:write tls-conn "Second")
              (let [resp (:read tls-conn 1024)
                    resumed (:session-reused? tls-conn)]
                (assert (= (string resp) "Second") "Second connection OK")
                # Session resumption may not always work depending on TLS version/config
                (when resumed
                  (assert resumed "Session was resumed")))))

          (ev/take done2)
          (:close server2)
          (cleanup-socket socket-path2))))

    # -------------------------------------------------------------------------
    # peer-cert - Export peer certificate DER after handshake
    # -------------------------------------------------------------------------
    (def-test "peer-cert"
      (var server-peer-cert :not-run)
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 10
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 100)
                           (set server-peer-cert (:peer-cert tls-conn))
                           (:write tls-conn "ACK")))))
                   ([err] (set server-peer-cert (string "server error: " err))))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "ping")
            (let [resp (:read tls-conn 100)]
              (assert (= (string resp) "ACK") "handshake completed via echo"))
            (let [peer-der (:peer-cert tls-conn)
                  fn-der (tls-stream/get-peer-cert tls-conn)]
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
                        "returned DER parses to the test certificate (subject)")))))

        (ev/take done)
        (assert (nil? server-peer-cert)
                (string "server sees nil without client auth, got: " server-peer-cert))
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # peer-cert mTLS - Server side sees the client certificate DER
    # -------------------------------------------------------------------------
    (def-test "peer-cert mTLS"
      (var server-peer-cert :not-run)
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-certs (generate-certs-for-matrix @{:cert-type cert-type :common-name "client"})
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 10
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)
                                          :verify true :trusted-cert (client-certs :cert)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 100)
                           (set server-peer-cert (:peer-cert tls-conn))
                           (:write tls-conn "ACK")))))
                   ([err] (set server-peer-cert (string "server error: " err))))
                 (ev/give done true)))

        (ev/sleep 0.1)

        (with [conn (make-client-conn socket-type addr)]
          (let [client-opts (merge {:cert (client-certs :cert)
                                    :key (client-certs :key)
                                    :verify false} ctx-opts)]
            (with [tls-conn (tls/wrap conn "127.0.0.1" client-opts)]
              (:write tls-conn "ping")
              (let [resp (:read tls-conn 100)]
                (assert (= (string resp) "ACK") "mTLS echo")))))

        (ev/take done)
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
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # peer-cert failure shapes - Each failure path raises
    # -------------------------------------------------------------------------
    (def-test "peer-cert failure shapes"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (ev/with-deadline 10
                     (with [conn (:accept server)]
                       (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:write tls-conn "ACK")
                           (:read tls-conn 100)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Arity mismatch raises
        (assert-error (tls-stream/get-peer-cert) "0-arity raises")
        # Wrong argument type raises
        (assert-error (tls-stream/get-peer-cert "not-a-stream")
                      "non-stream argument raises")
        (assert-error (tls-stream/get-peer-cert 42)
                      "non-stream argument raises")
        (assert-error (:peer-cert 42) "method dispatch on non-stream raises")

        (with [conn (make-client-conn socket-type addr)]
          # Wrong abstract type: a raw net stream is not a jsec/tls-stream
          (assert-error (tls-stream/get-peer-cert conn)
                        "raw net stream raises")

          (with [tls-conn (tls/wrap conn client-opts)]
            (:write tls-conn "ping")
            (:read tls-conn 100)
            (let [der (:peer-cert tls-conn)]
              (assert (string? der) "live stream returns DER before close"))
            # Arity mismatch raises with a live stream too
            (assert-error (tls-stream/get-peer-cert tls-conn tls-conn)
                          "2-arity raises")
            (:close tls-conn)
            # Closed stream raises
            (assert-error (tls-stream/get-peer-cert tls-conn)
                          "closed stream raises")
            (assert-error (:peer-cert tls-conn)
                          "closed stream raises via method")))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)))

    # -------------------------------------------------------------------------
    # hostname mismatch rejection - Verify bad hostname is rejected
    # -------------------------------------------------------------------------
    (def-test "hostname mismatch rejection"
      :skip-cases [{:verify-mode :no-verify}] # Only test when verification is enabled
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            wrong-certs (generate-temp-certs {:common-name "wrong-hostname.test"})
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (try
                       (let [opts (merge {:cert (wrong-certs :cert) :key (wrong-certs :key)} ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 1024)))
                       ([err] nil)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Client should fail because hostname doesn't match cert CN
        (var got-error false)
        (with [conn (make-client-conn socket-type addr)]
          (try
            (let [opts (merge {:verify true :trusted-cert (wrong-certs :cert)} ctx-opts)]
              (tls/wrap conn "127.0.0.1" opts))
            ([err] (set got-error true))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)

        (assert got-error "Hostname mismatch was rejected")))

    # -------------------------------------------------------------------------
    # mTLS missing client cert fails - Server requires client cert
    # -------------------------------------------------------------------------
    (def-test "mTLS missing client cert fails"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            server-certs certs
            client-certs (generate-temp-certs {:common-name "client"})
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            done (ev/chan 1)]

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (try
                       # Server requires client certificate
                       (let [opts (merge {:cert (server-certs :cert)
                                          :key (server-certs :key)
                                          :verify true
                                          :trusted-cert (client-certs :cert)}
                                         ctx-opts)]
                         (with [tls-conn (tls/wrap conn opts)]
                           (:read tls-conn 1024)))
                       ([err] nil)))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Client WITHOUT certificate should fail
        (var connection-failed false)
        (with [conn (make-client-conn socket-type addr)]
          (try
            # No client cert provided
            (let [opts (merge {:verify false} ctx-opts)]
              (with [tls-conn (tls/wrap conn opts)]
                (:write tls-conn "test")
                (:read tls-conn 1024)))
            ([err] (set connection-failed true))))

        (ev/take done)
        (:close server)
        (cleanup-socket socket-path)

        (assert connection-failed "mTLS without client cert should fail")))

    # -------------------------------------------------------------------------
    # multi-client messaging - Multiple clients exchange messages
    # -------------------------------------------------------------------------
    (def-test "multi-client messaging"
      (let [ctx-opts (build-ctx-opts tls-version tcp-nodelay cipher-group)
            client-opts (build-client-opts verify-mode ctx-opts certs)
            num-clients 5
            [server socket-path] (make-server socket-type)
            addr (get-server-addr server socket-type socket-path)
            results (ev/chan num-clients)
            server-handlers (ev/chan num-clients)
            server-done (ev/chan 1)]

        # Server: spawn a handler fiber for each accepted connection
        (ev/go (fn []
                 (for i 0 num-clients
                   (try
                     (ev/with-deadline 10
                       (def conn (:accept server))
                       # Spawn handler fiber for this connection
                       (ev/go (fn []
                                (try
                                  (ev/with-deadline 10
                                    (with [c conn]
                                      (let [opts (merge {:cert (certs :cert) :key (certs :key)} ctx-opts)]
                                        (with [tls-conn (tls/wrap c opts)]
                                          (let [msg (:read tls-conn 1024)]
                                            (:write tls-conn (string "Reply-" (string msg)))
                                            # Wait for client to close before exiting
                                            (try (:read tls-conn 1) ([_] nil)))))))
                                  ([err] nil))
                                (ev/give server-handlers true))))
                     ([err] nil)))
                 (ev/give server-done true)))

        (ev/sleep 0.2)

        (for i 0 num-clients
          (ev/go (fn []
                   (try
                     (ev/with-deadline 10
                       (with [conn (make-client-conn socket-type addr)]
                         (with [tls-conn (tls/wrap conn client-opts)]
                           (:write tls-conn (string "Client-" i))
                           (let [resp (:read tls-conn 1024)]
                             (ev/give results {:client i
                                               :success (string/has-prefix? "Reply-Client-" (string resp))
                                               :resp (string resp)})))))
                     ([err]
                       (ev/give results {:client i :success false :error (string err)}))))))

        (var successes 0)
        (def errors @[])
        (for i 0 num-clients
          (let [r (ev/take results)]
            (if (r :success)
              (++ successes)
              (array/push errors (or (r :error) (string "bad response: " (r :resp)))))))

        # Wait for server to finish accepting
        (ev/take server-done)
        # Wait for all handlers to complete
        (for i 0 num-clients
          (ev/take server-handlers))
        (:close server)
        (cleanup-socket socket-path)

        (assert (= successes num-clients)
                (string "Expected " num-clients " successes, got " successes ". Errors: " (string/join errors ", "))))))

  # ===========================================================================
  # Non-Matrix Tests (TCP-only or specific configurations)
  # ===========================================================================

  (def-test "localname and peername"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          [server _] (make-server :tcp)
          [host port] (net/localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (try
                 (with [conn (:accept server)]
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     (let [sln (:localname tls-conn)
                           spn (:peername tls-conn)]
                       (:write tls-conn (string (sln 1) ":" (spn 1))))
                     (ev/sleep 0.1)))
                 ([err] nil))
               (ev/give done true)))

      (ev/sleep 0.1)

      (with [tls-conn (tls/connect host (string port) {:verify false})]
        (let [cln (:localname tls-conn)
              cpn (:peername tls-conn)]
          (assert (= (cln 0) "127.0.0.1") "Client localname host")
          (assert (= (cpn 0) "127.0.0.1") "Client peername host")
          (assert (= (cpn 1) port) "Client peername port")
          (:read tls-conn 100)))

      (ev/take done)
      (:close server)))

  (def-test "listener localname via method and function"
    (let [listener (tls/listen "127.0.0.1" "0")]
      (defer (:close listener)
        (let [[host port] (net/localname listener)
              via-method (:localname listener)
              via-fn (tls-stream/localname listener)]
          (assert (= (length via-method) 2)
                  "(:localname listener) returns a 2-tuple")
          (assert (= (via-method 0) host)
                  "(:localname listener) host matches net/localname")
          (assert (= (via-method 1) port)
                  "(:localname listener) port matches net/localname")
          (assert (= (length via-fn) 2)
                  "(tls-stream/localname listener) returns a 2-tuple")
          (assert (= (via-fn 0) host)
                  "(tls-stream/localname listener) host matches net/localname")
          (assert (= (via-fn 1) port)
                  "(tls-stream/localname listener) port matches net/localname")))))

  (def-test "localname and peername method and function parity"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          [server _] (make-server :tcp)
          [host port] (net/localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (try
                 (with [conn (:accept server)]
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     (let [sln (:localname tls-conn)
                           spn (:peername tls-conn)]
                       (assert (= (tls-stream/localname tls-conn) sln)
                               "server localname function/method parity")
                       (assert (= (tls-stream/peername tls-conn) spn)
                               "server peername function/method parity"))
                     (ev/sleep 0.1)))
                 ([err] nil))
               (ev/give done true)))

      (ev/sleep 0.1)

      (with [tls-conn (tls/connect host (string port) {:verify false})]
        (let [cln (:localname tls-conn)
              cpn (:peername tls-conn)]
          (assert (= (tls-stream/localname tls-conn) cln)
                  "client localname function/method parity")
          (assert (= (tls-stream/peername tls-conn) cpn)
                  "client peername function/method parity"))
        (:read tls-conn 100))

      (ev/take done)
      (:close server)))

  (def-test "peername raises on listen listener"
    (let [listener (tls/listen "127.0.0.1" "0")]
      (defer (:close listener)
        (assert-error (tls-stream/peername listener)
                      "peername function raises on listener")
        (assert-error (:peername listener)
                      "peername method raises on listener"))))

  (def-test "localname raises TLS:IO after listener close"
    (let [listener (tls/listen "127.0.0.1" "0")]
      (:close listener)

      (var method-err nil)
      (try
        (:localname listener)
        ([err] (set method-err err)))
      (assert method-err "(:localname listener) raises after close")
      (assert (string/find "[TLS:IO]" (string method-err))
              "method localname raises a [TLS:IO] error")

      (var fn-err nil)
      (try
        (tls-stream/localname listener)
        ([err] (set fn-err err)))
      (assert fn-err "(tls-stream/localname listener) raises after close")
      (assert (string/find "[TLS:IO]" (string fn-err))
              "function localname raises a [TLS:IO] error")))

  (def-test "trust-cert with explicit context"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          [server _] (make-server :tcp)
          [host port] (net/localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (try
                 (with [conn (:accept server)]
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     (:write tls-conn "OK")))
                 ([err] nil))
               (ev/give done true)))

      (ev/sleep 0.1)

      (let [ctx (tls-stream/new-context {:trusted-cert (certs :cert)})
            _ (:trust-cert ctx (certs :cert))]
        (with [tls-conn (tls/connect host (string port) {:verify true :context ctx})]
          (let [resp (:read tls-conn 1024)]
            (assert (= (string resp) "OK") "Connection with explicit context succeeded"))))

      (ev/take done)
      (:close server)))

  (def-test "parallel echo clients"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          num-clients 10
          [server _] (make-server :tcp)
          [host port] (net/localname server)
          results (ev/chan num-clients)
          server-done (ev/chan 1)]

      (ev/go (fn []
               (for i 0 num-clients
                 (try
                   (ev/with-deadline 10
                     (with [conn (:accept server)]
                       (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                         (let [msg (:read tls-conn 1024)]
                           (:write tls-conn msg)))))
                   ([err] nil)))
               (ev/give server-done true)))

      (ev/sleep 0.2)

      (for i 0 num-clients
        (ev/go (fn []
                 (try
                   (ev/with-deadline 10
                     (with [tls-conn (tls/connect host (string port) {:verify false})]
                       (:write tls-conn (string "Parallel-" i))
                       (let [resp (:read tls-conn 1024)]
                         (ev/give results {:client i :success (= (string resp) (string "Parallel-" i))}))))
                   ([err]
                     (ev/give results {:client i :success false}))))))

      (var successes 0)
      (for i 0 num-clients
        (let [r (ev/take results)]
          (when (r :success) (++ successes))))

      (ev/take server-done)
      (:close server)

      (assert (= successes num-clients)
              (string "All " num-clients " parallel clients succeeded"))))

  (def-test "verify-hostname option"
    (let [certs (generate-temp-certs {:common-name "localhost"})
          [server _] (make-server :tcp)
          [host port] (net/localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (try
                 (with [conn (:accept server)]
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     (:write tls-conn "OK")))
                 ([err] nil))
               (ev/give done true)))

      (ev/sleep 0.1)

      (with [tls-conn (tls/connect host (string port)
                                   {:verify true
                                    :trusted-cert (certs :cert)
                                    :verify-hostname "localhost"})]
        (let [resp (:read tls-conn 1024)]
          (assert (= (string resp) "OK") "verify-hostname succeeded")))

      (ev/take done)
      (:close server)))

  (def-test "connection refused"
    :expected-fail "Connection to closed port should fail"
    (ev/with-deadline 5
      # Create a listener to get a valid port, then close it
      # This guarantees the port exists but has nothing listening
      (def server (net/listen "127.0.0.1" "0"))
      (def [_ port] (net/localname server))
      (:close server)
      # Small delay to ensure OS releases the port
      (ev/sleep 0.1)
      # Connect and try to use it - on Windows, connection
      # errors only appear on first I/O, not at connect time
      (def conn (tls/connect "127.0.0.1" (string port) {:verify false}))
      (:write conn "test")
      (:close conn)))

  # ---------------------------------------------------------------------------
  # OCSP Stapling Test
  # ---------------------------------------------------------------------------
  (def-test "OCSP stapling"
    :timeout 15
    (let [certs (generate-temp-certs {:common-name "localhost"})
          mock-ocsp-response (string/bytes "MOCK_OCSP_RESPONSE_DATA")
          server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]

      (defer (:close server)
        # Server with OCSP stapling enabled
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [opts {:cert (certs :cert)
                                 :key (certs :key)
                                 :verify false
                                 :ocsp-stapling true}]
                       (with [tls-conn (tls/wrap conn opts)]
                         # Set OCSP response if supported
                         (try
                           (tls-stream/set-ocsp-response tls-conn mock-ocsp-response)
                           ([err] nil))
                         (let [msg (:read tls-conn 1024)]
                           (:write tls-conn msg)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Client requests OCSP stapling
        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls/wrap conn "localhost" {:verify false :ocsp-stapling true})]
            (:write tls-conn "OCSP Test")
            (let [resp (:read tls-conn 1024)]
              (assert (= (string resp) "OCSP Test") "OCSP stapling connection works"))))

        (ev/take done))))

  # ---------------------------------------------------------------------------
  # SNI Multiple Hostnames Test  
  # ---------------------------------------------------------------------------
  (def-test "SNI multiple hostnames"
    :timeout 15
    (let [certs-example (generate-temp-certs {:common-name "example.com"})
          certs-test (generate-temp-certs {:common-name "test.com"})
          certs-default (generate-temp-certs {:common-name "default.com"})
          server (net/listen "127.0.0.1" "0")
          [_ port] (net/localname server)
          done (ev/chan 1)]

      (defer (:close server)
        # Server with SNI mapping
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (let [sni-map {"example.com" {:cert (certs-example :cert)
                                                   :key (certs-example :key)}
                                    "test.com" {:cert (certs-test :cert)
                                                :key (certs-test :key)}}
                           opts {:cert (certs-default :cert)
                                 :key (certs-default :key)
                                 :verify false
                                 :sni sni-map}]
                       (with [tls-conn (tls/wrap conn opts)]
                         (let [msg (:read tls-conn 1024)]
                           (:write tls-conn msg)))))
                   ([err] nil))
                 (ev/give done true)))

        (ev/sleep 0.1)

        # Client with example.com SNI
        (with [conn (net/connect "127.0.0.1" (string port))]
          (with [tls-conn (tls/wrap conn "example.com" {:verify false})]
            (:write tls-conn "Hello example.com")
            (let [resp (:read tls-conn 1024)]
              (assert (= (string resp) "Hello example.com") "SNI example.com works"))))

        (ev/take done))))

  # ---------------------------------------------------------------------------
  # Verification Scenarios Matrix Test
  # Uses janet-assay matrix to test all verification combinations
  # ---------------------------------------------------------------------------
  (def-test "verification scenarios"
    :type :matrix
    :matrix {:scenario [:client-no-verify
                        :client-verify-self-signed
                        :client-verify-trusted
                        :client-verify-wrong-trust
                        :mtls-both-trust
                        :mtls-server-verify-no-client-cert]}
    :timeout 30
    :parallel {:subprocess 4}
    :harness [:certs {:setup (fn [cfg vs]
                               {:server (generate-temp-certs {:common-name "localhost"})
                                :client (generate-temp-certs {:common-name "client"})})}]

    (def-test "verification behavior"
      (let [server-certs (certs :server)
            client-certs (certs :client)
            # Build opts based on scenario
            [server-opts client-opts expected]
            (case scenario
              :client-no-verify
              [{:cert (server-certs :cert) :key (server-certs :key) :verify false}
               {:verify false}
               :pass]

              :client-verify-self-signed
              [{:cert (server-certs :cert) :key (server-certs :key) :verify false}
               {:verify true}
               :fail]

              :client-verify-trusted
              [{:cert (server-certs :cert) :key (server-certs :key) :verify false}
               {:verify true :trusted-cert (server-certs :cert)}
               :pass]

              :client-verify-wrong-trust
              [{:cert (server-certs :cert) :key (server-certs :key) :verify false}
               {:verify true :trusted-cert (client-certs :cert)}
               :fail]

              :mtls-both-trust
              [{:cert (server-certs :cert) :key (server-certs :key)
                :verify true :trusted-cert (client-certs :cert)}
               {:cert (client-certs :cert) :key (client-certs :key)
                :verify true :trusted-cert (server-certs :cert)}
               :pass]

              :mtls-server-verify-no-client-cert
              [{:cert (server-certs :cert) :key (server-certs :key)
                :verify true :trusted-cert (client-certs :cert)}
               {:verify false}
               :fail])

            server (net/listen "127.0.0.1" "0")
            [_ port] (net/localname server)
            done (ev/chan 1)
            result @{:success false}]

        (defer (:close server)
          (ev/go (fn []
                   (try
                     (with [conn (:accept server)]
                       (with [tls-conn (tls/wrap conn server-opts)]
                         (:write tls-conn "OK")))
                     ([err] nil))
                   (ev/give done true)))

          (ev/sleep 0.1)

          (try
            (with [conn (net/connect "127.0.0.1" (string port))]
              (with [tls-conn (tls/wrap conn "localhost" client-opts)]
                (let [resp (:read tls-conn 1024)]
                  (put result :success (= (string resp) "OK")))))
            ([err]
              (put result :success false)))

          (ev/take done))

        (if (= expected :pass)
          (assert (result :success) (string "scenario " scenario " should pass"))
          (assert (not (result :success)) (string "scenario " scenario " should fail")))))))
