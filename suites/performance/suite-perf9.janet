###
### suites/performance/suite-perf9.janet - Performance Testing Suite (perf9)
###
### Uses janet-assay's coordinated matrix tests for TLS/TCP performance benchmarking.
###
### ARCHITECTURE:
### - Server participant: ONE server per participant instance
###   - Assay controls how many server instances via coordinated participant count
###   - All servers listen on same address/port (SO_REUSE* for TCP)
###   - Server does NOT aggregate - just ships raw metrics to runner
###
### - Client Host participant: Spawns multiple internal clients
###   - client-count matrix value controls how many clients per host
###   - Assay controls how many client hosts via coordinated participant count
###   - Clients send raw metrics: bytes_sent, start_time, end_time
###   - NO calculations in clients - perf9-analyze does all aggregation
###
### CODE PATH UNIFICATION:
### - TCP+TLS use SAME code path - only initialization differs
### - This ensures we're testing jsec, not Janet
###
### Matrix dimensions:
###   - protocol: :tls, :tcp
###   - tls-version: "1.2", "1.3" (only for TLS)
###   - chunk-size: buffer sizes
###   - client-count: clients per host (10, 50, 100, 500, 1000)
###   - duration: test duration in seconds
###
### Coordinated participant counts (via filter):
###   - server participant count: 1-4 (controlled by assay)
###   - client-host participant count: 1-4 (controlled by assay)
###
### Skip conditions:
###   - unix/unix-tls/dtls + server-count > 1: SO_REUSE* not supported
###

(import assay :prefix "")
(import ./lib/metrics :as metrics)
(import ./lib/protocol/echo-tcp :as echo-tcp)
(import jsec/tls :as tls)
(import jsec/cert :as cert)

# --------------------------------------------------------------------------
# Helper to normalize protocol value to keyword
# Filter may pass string "tls" or keyword :tls - normalize to keyword
# --------------------------------------------------------------------------
(defn- normalize-protocol
  "Convert protocol to keyword form. Handles both string and keyword inputs."
  [proto]
  (cond
    (keyword? proto) proto
    (string? proto) (keyword proto)
    (nil? proto) :tcp
    proto))

# --------------------------------------------------------------------------
# Certificate Generation - generate once at suite load time
# --------------------------------------------------------------------------

(def test-certs (cert/generate-self-signed-cert
                  {:common-name "perf9-test"
                   :days-valid 1
                   :san ["DNS:localhost" "IP:127.0.0.1"]}))

# --------------------------------------------------------------------------
# Skip predicates for invalid combinations
# --------------------------------------------------------------------------

(defn skip-invalid-combo?
  "Skip invalid protocol/config combinations with descriptive reason."
  [combo]
  (let [proto (combo :protocol)
        tls-ver (combo :tls-version)]
    (cond
      # Unix sockets not supported on Windows
      (and (= (os/which) :windows)
           (or (= proto :unix) (= proto :unix-tls)))
      "Unix sockets not supported on Windows"

      # TLS version specified on non-TLS protocol - skip
      (and tls-ver
           (not (or (= proto :tls) (= proto :unix-tls))))
      "TLS version only applies to TLS protocols"

      # TLS protocol WITHOUT tls-version - skip (use nil combo separately)
      # Actually no - nil tls-version means "default" for TLS tests

      # High client count needs adequate duration
      (and (>= (or (combo :client-count) 1) 500)
           (< (or (combo :duration) 60) 30))
      "High client counts (500+) require at least 30s duration"

      # Default: no skip
      false)))

# --------------------------------------------------------------------------
# Unified Echo Test - Same code path for TCP and TLS
# --------------------------------------------------------------------------
# 
# The key insight: TCP and TLS use IDENTICAL code paths after initialization.
# Only the make-server/make-client calls differ. This ensures we're measuring
# jsec performance, not Janet performance.
#

(defn make-server-config
  "Build server config table for either TCP or TLS.
   Only initialization differs - rest of code is identical."
  [protocol tls-version chunk-size scratch-dir server-index]
  (def config
    @{:protocol protocol
      :buffer-size chunk-size
      :backlog 4096
      :host "127.0.0.1"
      :port "0"}) # Ephemeral port - OS assigns

  # Add TLS-specific config
  (when (or (= protocol :tls) (= protocol :unix-tls))
    (put config :cert (test-certs :cert))
    (put config :key (test-certs :key))
    (put config :handshake-timing true)
    (when tls-version
      (if (= tls-version "1.2")
        (put config :ciphers "ECDHE-RSA-AES256-GCM-SHA384")
        (put config :ciphersuites "TLS_AES_256_GCM_SHA384"))))

  # Unix socket path
  (when (or (= protocol :unix) (= protocol :unix-tls))
    (put config :socket-path (string scratch-dir "/perf9-server-" server-index ".sock")))

  config)

(defn make-client-config
  "Build client config table for either TCP or TLS.
   Only initialization differs - rest of code is identical."
  [protocol tls-version chunk-size duration server-info]
  (def config
    @{:protocol protocol
      :chunk-size chunk-size
      :duration duration
      :buffer-size chunk-size})

  # Set connection target
  (case protocol
    :tls
    (do
      (put config :host (server-info :host))
      (put config :port (server-info :port))
      (put config :handshake-timing true)
      (when (server-info :ciphers) (put config :ciphers (server-info :ciphers)))
      (when (server-info :ciphersuites) (put config :ciphersuites (server-info :ciphersuites))))

    :tcp
    (do
      (put config :host (server-info :host))
      (put config :port (server-info :port)))

    :unix-tls
    (do
      (put config :socket-path (server-info :socket-path))
      (put config :handshake-timing true)
      (when (server-info :ciphers) (put config :ciphers (server-info :ciphers)))
      (when (server-info :ciphersuites) (put config :ciphersuites (server-info :ciphersuites))))

    :unix
    (put config :socket-path (server-info :socket-path)))

  config)

# --------------------------------------------------------------------------
# Suite Definition
# --------------------------------------------------------------------------

(def-suite :name "perf9"
  :category "performance"

  # --------------------------------------------------------------------------
  # Unified Echo Performance Test - TCP and TLS use same code path
  # --------------------------------------------------------------------------
  (def-test "echo"
    :type :coordinated
    :timeout 300
    :graceful-timeout -10

    # Matrix dimensions - protocol is just another parameter
    # Server participant count and client-host participant count are
    # controlled by assay's coordinated filter, not matrix
    :matrix {:protocol [:tcp :tls]
             :tls-version [nil "1.2" "1.3"]
             :chunk-size [65536 131072 262144]
             :client-count [10 50 100 500 1000]
             :duration [10 30 45]} # Added 10s and 30s for quick tests

    :skip-cases [skip-invalid-combo?]

    # --------------------------------------------------------------------------
    # Server Participant
    # - ONE server per participant instance (assay controls count)
    # - Ships raw metrics only - NO calculations
    # - All servers listen on same address:port (SO_REUSE* for TCP)
    # --------------------------------------------------------------------------
    (def-test "server"
      # Get matrix values (bound by assay macro)
      # Normalize protocol since filter may pass string "tls" instead of keyword :tls
      (def proto (normalize-protocol protocol))
      (def tls-ver tls-version)
      (def chunk-sz (or chunk-size 65536))
      (def test-duration (or duration 45))

      # Create metrics collector for raw data only
      (def server-metrics (metrics/new-metrics))

      # Build server config - same function for TCP and TLS
      (def server-config (make-server-config proto tls-ver chunk-sz scratch-dir 0))

      # Start server using unified factory
      (def server (echo-tcp/make-server server-config
                                        (fn [conn] (echo-tcp/echo-handler conn server-metrics))))

      # Get bound port for client connection info
      (def server-info @{:protocol proto})
      (case proto
        :tls
        (when-let [name (net/localname server)]
          (put server-info :host "127.0.0.1")
          (put server-info :port (get name 1)))

        :tcp
        (when-let [name (net/localname server)]
          (put server-info :host "127.0.0.1")
          (put server-info :port (get name 1)))

        :unix-tls
        (put server-info :socket-path (server-config :socket-path))

        :unix
        (put server-info :socket-path (server-config :socket-path)))

      # Add TLS config to server-info for client matching
      (when tls-ver
        (if (= tls-ver "1.2")
          (put server-info :ciphers "ECDHE-RSA-AES256-GCM-SHA384")
          (put server-info :ciphersuites "TLS_AES_256_GCM_SHA384")))

      # Signal ready to clients
      (emit :server-ready server-info)

      # Wait for clients to finish
      (await :client-host :done (+ test-duration 60))

      # Small delay for final data
      (ev/sleep 0.2)

      # Cleanup
      (try (:close server) ([_] nil))
      (when (or (= proto :unix-tls) (= proto :unix))
        (when-let [path (server-config :socket-path)]
          (when (os/stat path)
            (try (os/rm path) ([_] nil)))))

      # Ship RAW metrics only - no aggregation, no calculations
      # perf9-analyze handles all that
      (report-data @{:role :server
                     :protocol proto
                     :tls-version tls-ver
                     :chunk-size chunk-sz
                     :metrics (:to-table server-metrics)}))

    # --------------------------------------------------------------------------
    # Client Host Participant
    # - Spawns client-count clients internally (matrix value)
    # - Assay controls how many client hosts via coordinated participant count
    # - Clients send raw metrics only - NO calculations
    # --------------------------------------------------------------------------
    (def-test "client-host"
      # Get matrix values
      # Normalize protocol since filter may pass string "tls" instead of keyword :tls
      (def proto (normalize-protocol protocol))
      (def tls-ver tls-version)
      (def chunk-sz (or chunk-size 65536))
      (def test-duration (or duration 45))
      (def num-clients (or client-count 10))

      # Threshold values from environment (nil = no check)
      # PERF9_MIN_THROUGHPUT: bytes/sec (e.g., 100000000 for 100MB/s)
      # PERF9_MAX_HANDSHAKE_P95: milliseconds (e.g., 2000 for 2s)
      # PERF9_MIN_CONNECTED_PCT: percentage (e.g., 99)
      (def min-tp (when-let [v (os/getenv "PERF9_MIN_THROUGHPUT")]
                    (scan-number v)))
      (def max-hs (when-let [v (os/getenv "PERF9_MAX_HANDSHAKE_P95")]
                    (scan-number v)))
      (def min-conn-pct (or (when-let [v (os/getenv "PERF9_MIN_CONNECTED_PCT")]
                              (scan-number v))
                            100)) # 100% by default

      # Create metrics collector for raw data
      (def host-metrics (metrics/new-metrics))

      # Wait for server ready
      (def server-info (await :server :server-ready 30))
      (unless server-info
        (error "Timeout waiting for server"))

      # Build client config - same function for TCP and TLS
      (def client-config (make-client-config proto tls-ver chunk-sz test-duration server-info))

      # Spawn clients - same code path for TCP and TLS
      (def done-ch (ev/chan num-clients))
      (def start-time (os/clock :monotonic))

      (for i 0 num-clients
        (ev/spawn
          (defer (ev/give done-ch true)
            (try
              (do
                # Unified client creation - only init differs
                (def conn (echo-tcp/make-client client-config))
                (echo-tcp/run-client conn client-config start-time host-metrics)
                (try (:close conn) ([_] nil)))
              ([err]
                (:add-error host-metrics (metrics/categorize-error err)))))))

      # Wait for all clients
      (for _ 0 num-clients
        (ev/take done-ch))

      # Signal done to server
      (emit :done true)

      # Calculate metrics for threshold checks
      (def end-time (os/clock :monotonic))
      (def actual-duration (- end-time start-time))
      (def metrics-table (:to-table host-metrics))
      (def bytes-total (+ (or (metrics-table :bytes-sent) 0)
                          (or (metrics-table :bytes-recv) 0)))
      (def throughput (if (> actual-duration 0) (/ bytes-total actual-duration) 0))
      (def connected (or (metrics-table :connected) 0))
      (def connected-pct (* 100 (/ connected num-clients)))

      # Check handshake p95 if applicable
      (def hs-times (or (metrics-table :handshake-times) @[]))
      (def hs-p95 (when (> (length hs-times) 0)
                    (let [sorted (sort (array/slice hs-times))
                          idx (math/floor (* 0.95 (length sorted)))]
                      (* 1000 (sorted (min idx (- (length sorted) 1))))))) # convert to ms

      # Ship metrics first
      (report-data @{:role :client-host
                     :protocol proto
                     :tls-version tls-ver
                     :chunk-size chunk-sz
                     :client-count num-clients
                     :duration test-duration
                     :start-time start-time
                     :end-time end-time
                     :throughput throughput
                     :connected-pct connected-pct
                     :handshake-p95-ms hs-p95
                     :metrics metrics-table})

      # Check thresholds and fail if not met
      (var failures @[])

      (when (and min-tp (< throughput min-tp))
        (array/push failures
                    (string/format "Throughput %.2f MB/s below minimum %.2f MB/s"
                                   (/ throughput (* 1024 1024))
                                   (/ min-tp (* 1024 1024)))))

      (when (and max-hs hs-p95 (> hs-p95 max-hs))
        (array/push failures
                    (string/format "Handshake p95 %.2f ms exceeds maximum %.2f ms"
                                   hs-p95 max-hs)))

      (when (< connected-pct min-conn-pct)
        (array/push failures
                    (string/format "Connected %.1f%% below minimum %.1f%%"
                                   connected-pct min-conn-pct)))

      # Fail test if any thresholds not met
      (when (> (length failures) 0)
        (error (string/join failures "\n"))))))

# --------------------------------------------------------------------------
# Quick smoke tests for fast validation
# --------------------------------------------------------------------------
(def-test "tls-quick"
  :type :coordinated
  :timeout 30

  (def-test "server"
    (def server-metrics (metrics/new-metrics))
    (def server-config (make-server-config :tls "1.3" 65536 scratch-dir 0))
    (def server (echo-tcp/make-server server-config
                                      (fn [conn] (echo-tcp/echo-handler conn server-metrics))))

    (def server-info @{:protocol :tls :host "127.0.0.1"})
    (when-let [name (net/localname server)]
      (put server-info :port (get name 1)))
    (put server-info :ciphersuites "TLS_AES_256_GCM_SHA384")

    (emit :server-ready server-info)
    (await :client :done 20)
    (ev/sleep 0.1)
    (try (:close server) ([_] nil))
    (report-data @{:role :server :metrics (:to-table server-metrics)}))

  (def-test "client"
    (def client-metrics (metrics/new-metrics))
    (def server-info (await :server :server-ready 10))
    (unless server-info (error "Timeout waiting for server"))

    (def client-config (make-client-config :tls "1.3" 65536 5 server-info))
    (def start (os/clock :monotonic))
    (def conn (echo-tcp/make-client client-config))
    (echo-tcp/run-client conn client-config start client-metrics)
    (try (:close conn) ([_] nil))

    (emit :done true)
    (report-data @{:role :client :metrics (:to-table client-metrics)})))

(def-test "tcp-quick"
  :type :coordinated
  :timeout 30

  (def-test "server"
    (def server-metrics (metrics/new-metrics))
    (def server-config (make-server-config :tcp nil 65536 scratch-dir 0))
    (def server (echo-tcp/make-server server-config
                                      (fn [conn] (echo-tcp/echo-handler conn server-metrics))))

    (def server-info @{:protocol :tcp :host "127.0.0.1"})
    (when-let [name (net/localname server)]
      (put server-info :port (get name 1)))

    (emit :server-ready server-info)
    (await :client :done 20)
    (ev/sleep 0.1)
    (try (:close server) ([_] nil))
    (report-data @{:role :server :protocol :tcp :metrics (:to-table server-metrics)}))

  (def-test "client"
    (def client-metrics (metrics/new-metrics))
    (def server-info (await :server :server-ready 10))
    (unless server-info (error "Timeout waiting for server"))

    (def client-config (make-client-config :tcp nil 65536 5 server-info))
    (def start (os/clock :monotonic))
    (def conn (echo-tcp/make-client client-config))
    (echo-tcp/run-client conn client-config start client-metrics)
    (try (:close conn) ([_] nil))

    (emit :done true)
    (report-data @{:role :client :protocol :tcp :metrics (:to-table client-metrics)})))
