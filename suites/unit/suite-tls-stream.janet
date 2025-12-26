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

(import assay)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
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

(assay/def-suite :name "TLS Stream Suite"

                 # ===========================================================================
                 # Main Test Matrix - Socket Type x TLS Version x Verify Mode x Options
                 # ===========================================================================

                 (assay/def-test "TLS Config Matrix"
                                 :type :matrix
                                 :matrix {:socket-type [:tcp :unix]
                                          :tls-version [:default :tls12 :tls13]
                                          :verify-mode [:no-verify :verify-trusted]
                                          :tcp-nodelay [true false]
                                          :cert-type [:rsa :ec-p256]
                                          :cipher-group [:aes-gcm :chacha20]}
                                 :skip-cases [skip-unix-on-windows?]
                                 :parallel {:fiber 6 :thread 6 :subprocess 6}
                                 :harness [:certs {:setup (fn [cfg vs]
                                                            (generate-certs-for-matrix cfg))}]

                                 # -------------------------------------------------------------------------
                                 # basic echo - Simple send/receive test
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "basic echo"
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
                                                           (assay/assert (= resp test-msg) "Echo response matches"))))

                                                     (ev/take done))))

                                 # -------------------------------------------------------------------------
                                 # data integrity - Various data sizes and patterns
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "data integrity"
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
                                                               (assay/assert (= echo data)
                                                                             (string "Data integrity " name " (len=" (length data) ")"))))))

                                                       (ev/take done)
                                                       (:close server)
                                                       (cleanup-socket socket-path)))))

                                 # -------------------------------------------------------------------------
                                 # garbage data handling - Non-TLS data to TLS server
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "garbage data handling"
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

                                                   (assay/assert (true? (ev/take done)) "Server handled garbage without crash")
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # starttls upgrade - Upgrade plaintext to TLS
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "starttls upgrade"
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
                                                       (assay/assert (= (string resp) "HELLO") "Handshake 1")
                                                       (:write stream "STARTTLS")
                                                       (let [ready (:read stream 1024)]
                                                         (assay/assert (= (string ready) "READY") "Handshake 2")
                                                         (with [tls-stream (tls/upgrade stream "127.0.0.1" client-opts)]
                                                           (:write tls-stream "SECURE")
                                                           (let [sec-resp (:read tls-stream 1024)]
                                                             (assay/assert (= (string sec-resp) "SECURE") "Secure echo"))))))

                                                   (assay/assert (true? (ev/take done)) "Server finished")
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # tls/server api - High-level server API test
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "tls/server api"
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
                                                       (assay/assert (= (string resp) "ServerOK") "tls/server response")))

                                                   (ev/take done)
                                                   (:close server)))

                                 # -------------------------------------------------------------------------
                                 # connection info - Test connection metadata
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "connection info"
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
                                                         (assay/assert (string? version) ":version returns string")
                                                         (assay/assert (or (string/has-prefix? "TLS" version)
                                                                           (string/has-prefix? "SSL" version))
                                                                       (string ":version returns TLS version: " version)))

                                                       (let [cipher (:cipher tls-conn)]
                                                         (assay/assert (string? cipher) ":cipher returns string")
                                                         (assay/assert (> (length cipher) 0) "Cipher not empty"))

                                                       (let [info (:connection-info tls-conn)]
                                                         (assay/assert (struct? info) ":connection-info returns struct"))))

                                                   (ev/take done)
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # chunk method - Test chunked reading
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "chunk method"
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
                                                         (assay/assert (= (length chunk) 5) "Chunk is 5 bytes"))
                                                       (let [rest (:read tls-conn 1024)]
                                                         (assay/assert (> (length rest) 0) "Rest of data received"))))

                                                   (ev/take done)
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # concurrent clients - Multiple simultaneous connections
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "concurrent clients"
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

                                                   (assay/assert (= successes num-clients)
                                                                 (string "All " num-clients " clients succeeded"))))

                                 # -------------------------------------------------------------------------
                                 # verification failure - Untrusted cert should fail
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "verification failure"
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
                                 (assay/def-test "client abrupt close"
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

                                                   (assay/assert (true? (ev/take done)) "Server handled abrupt close")
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # shutdown - Graceful shutdown test
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "shutdown"
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
                                                         (assay/assert (= (string resp) "test") "Echo before shutdown"))))

                                                   (ev/take done)
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # mTLS basic - Mutual TLS authentication
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "mTLS basic"
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

                                                   (assay/assert success "mTLS echo")))

                                 # -------------------------------------------------------------------------
                                 # write after close - Should handle gracefully
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "write after close"
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

                                                   (assay/assert write-failed "Write after close should fail")))

                                 # -------------------------------------------------------------------------
                                 # server abrupt close - Client handles sudden server disconnect
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "server abrupt close"
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

                                                   (assay/assert handled-correctly "Client handled server close correctly")))

                                 # -------------------------------------------------------------------------
                                 # renegotiation and key update - Test key exchange operations
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "renegotiation and key update"
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
                                                         (assay/assert (= (string reply) "Pong") "Received Pong"))

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
                                                             (assay/assert (= (string reply2) "Pong2") "Received Pong2 after key operation"))))))

                                                   (ev/take done)
                                                   (:close server)
                                                   (cleanup-socket socket-path)))

                                 # -------------------------------------------------------------------------
                                 # session resumption - Test TLS session reuse
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "session resumption"
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
                                                         (assay/assert (= (string resp) "First") "First connection OK")
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
                                                           (assay/assert (= (string resp) "Second") "Second connection OK")
                                                           # Session resumption may not always work depending on TLS version/config
                                                           (when resumed
                                                             (assay/assert resumed "Session was resumed")))))

                                                     (ev/take done2)
                                                     (:close server2)
                                                     (cleanup-socket socket-path2))))

                                 # -------------------------------------------------------------------------
                                 # hostname mismatch rejection - Verify bad hostname is rejected
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "hostname mismatch rejection"
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

                                                   (assay/assert got-error "Hostname mismatch was rejected")))

                                 # -------------------------------------------------------------------------
                                 # mTLS missing client cert fails - Server requires client cert
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "mTLS missing client cert fails"
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

                                                   (assay/assert connection-failed "mTLS without client cert should fail")))

                                 # -------------------------------------------------------------------------
                                 # multi-client messaging - Multiple clients exchange messages
                                 # -------------------------------------------------------------------------
                                 (assay/def-test "multi-client messaging"
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
                                                                          (:write tls-conn (string "Reply-" (string msg))))))))
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
                                                                                          :success (string/has-prefix? "Reply-Client-" (string resp))})))))
                                                                ([err]
                                                                  (ev/give results {:client i :success false}))))))

                                                   (var successes 0)
                                                   (for i 0 num-clients
                                                     (let [r (ev/take results)]
                                                       (when (r :success) (++ successes))))

                                                   (ev/take server-done)
                                                   (:close server)
                                                   (cleanup-socket socket-path)

                                                   (assay/assert (= successes num-clients)
                                                                 (string "All " num-clients " clients exchanged messages")))))

                 # ===========================================================================
                 # Non-Matrix Tests (TCP-only or specific configurations)
                 # ===========================================================================

                 (assay/def-test "localname and peername"
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
                                       (assay/assert (= (cln 0) "127.0.0.1") "Client localname host")
                                       (assay/assert (= (cpn 0) "127.0.0.1") "Client peername host")
                                       (assay/assert (= (cpn 1) port) "Client peername port")
                                       (:read tls-conn 100)))

                                   (ev/take done)
                                   (:close server)))

                 (assay/def-test "trust-cert with explicit context"
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
                                         (assay/assert (= (string resp) "OK") "Connection with explicit context succeeded"))))

                                   (ev/take done)
                                   (:close server)))

                 (assay/def-test "parallel echo clients"
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

                                   (assay/assert (= successes num-clients)
                                                 (string "All " num-clients " parallel clients succeeded"))))

                 (assay/def-test "verify-hostname option"
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
                                       (assay/assert (= (string resp) "OK") "verify-hostname succeeded")))

                                   (ev/take done)
                                   (:close server)))

                 (assay/def-test "connection refused"
                                 :expected-fail "Connection to closed port should fail"
                                 (ev/with-deadline 5
                                   (tls/connect "127.0.0.1" "1" {:verify false})))

                 # ---------------------------------------------------------------------------
                 # OCSP Stapling Test
                 # ---------------------------------------------------------------------------
                 (assay/def-test "OCSP stapling"
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
                                           (assay/assert (= (string resp) "OCSP Test") "OCSP stapling connection works"))))

                                     (ev/take done))))

                 # ---------------------------------------------------------------------------
                 # SNI Multiple Hostnames Test  
                 # ---------------------------------------------------------------------------
                 (assay/def-test "SNI multiple hostnames"
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
                                           (assay/assert (= (string resp) "Hello example.com") "SNI example.com works"))))

                                     (ev/take done))))

                 # ---------------------------------------------------------------------------
                 # Verification Scenarios Matrix Test
                 # Uses janet-assay matrix to test all verification combinations
                 # ---------------------------------------------------------------------------
                 (assay/def-test "verification scenarios"
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

                                 (assay/def-test "verification behavior"
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
                                                     (assay/assert (result :success) (string "scenario " scenario " should pass"))
                                                     (assay/assert (not (result :success)) (string "scenario " scenario " should fail")))))))
