###
### Echo Protocol for Datagram (UDP and DTLS)
###
### Both UDP and DTLS use recv-from/send-to pattern for servers
### Client uses read/write for DTLS, recv-from/send-to for UDP
### Each message is a complete datagram - no streaming
###

(import jsec/tls :as tls)
(import ../metrics :as metrics)

# =============================================================================
# Error Categorization
# =============================================================================

# Re-export from metrics for backwards compatibility
(def categorize-error metrics/categorize-error)

# =============================================================================
# Server Creation
# =============================================================================

(defn make-server
  "Create datagram echo server (DTLS or UDP).
   config should contain: :host, :port
   For DTLS: :cert, :key, :encrypted true
   For UDP: :encrypted false or omitted
   Returns the server object (uses recv-from/send-to pattern)."
  [config]
  (let [host (or (config :host) "127.0.0.1")
        port (string (config :port))
        encrypted (config :encrypted)]
    (if encrypted
      # DTLS server
      (let [opts @{:cert (config :cert)
                   :key (config :key)
                   :datagram true}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/listen host port opts))
      # UDP server
      (net/listen host port :datagram))))

# =============================================================================
# Client Creation
# =============================================================================

(defn make-client
  "Create datagram client connection (DTLS or UDP).
   config should contain: :host, :port
   For DTLS: :encrypted true
   For UDP: :encrypted false or omitted
   Returns the connection object."
  [config]
  (let [host (or (config :host) "127.0.0.1")
        port (string (config :port))
        encrypted (config :encrypted)]
    (if encrypted
      # DTLS client
      (let [opts @{:verify false
                   :datagram true
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/connect host port opts))
      # UDP client
      (net/connect host port :datagram))))

# =============================================================================
# Server Echo Handler (runs in fiber)
# =============================================================================

(defn- get-peer-key [peer-addr]
  "Get a string key for tracking unique peers.
   Works with both Janet socket-address and DTLS address."
  (if (abstract? peer-addr)
    # Janet socket-address - use string representation
    (string peer-addr)
    # DTLS address struct with host/port
    (string (tls/address-host peer-addr) ":" (tls/address-port peer-addr))))

(defn run-server-loop
  "Run datagram server echo loop (UDP or DTLS).
   server: server from make-server
   metrics: metrics object
   running-fn: function that returns true while server should run
   Returns when running-fn returns false."
  [server metrics running-fn]
  (let [buf @""
        seen-peers @{}]
    (while (running-fn)
      (buffer/clear buf)
      (try
        (let [peer-addr (:recv-from server 65536 buf 1.0)] # 1s timeout to check shutdown
          (when (and peer-addr (> (length buf) 0))
            # Track unique peers
            (let [peer-key (get-peer-key peer-addr)]
              (unless (seen-peers peer-key)
                (put seen-peers peer-key true)
                (:add-connection metrics @{:peer peer-key})))
            # Echo back
            (:send-to server peer-addr buf)
            (:add-bytes metrics (length buf) (length buf))))
        ([err]
          (let [err-str (string err)]
            (unless (string/find "timeout" err-str)
              (:add-error metrics (categorize-error err)))))))))

# =============================================================================
# Client Echo Loop
# =============================================================================

(defn run-client
  "Run datagram client echo loop (UDP or DTLS).
   conn: connection from make-client
   config: should have :datagram-size, :duration or :iterations, :encrypted
   start-time: shared start timestamp for duration mode
   metrics: metrics object
   Returns true if client completed successfully."
  [conn config start-time metrics]
  (let [datagram-size (or (config :datagram-size) 1400)
        datagram (buffer/new-filled datagram-size (chr "X"))
        iteration-mode (not (nil? (config :iterations)))
        target-iterations (or (config :iterations) 0)
        duration (config :duration)
        encrypted (config :encrypted)]

    # Mark as connected
    (:mark-connected metrics)

    # Capture handshake time if available (DTLS only)
    (when (and encrypted (config :handshake-timing))
      (when-let [hs (:handshake-time conn)]
        (:add-handshake-time metrics hs)))

    (var iterations 0)
    (var bytes-sent 0)
    (var bytes-recv 0)
    (var success true)
    (def client-start (os/clock :monotonic))

    (try
      (while true
        (let [now (os/clock :monotonic)
              elapsed (- now start-time)]

          # Check termination conditions
          (when (and (not iteration-mode) (>= elapsed duration))
            (break))
          (when (and iteration-mode (>= iterations target-iterations))
            (break))

          # Send datagram - both UDP and DTLS clients support :write
          (:write conn datagram)
          (+= bytes-sent datagram-size)

          # Receive echo - both UDP and DTLS clients support :read
          (let [buf @""]
            (when-let [data (:read conn datagram-size buf 5.0)]
              (+= bytes-recv (length buf))))

          (++ iterations)))
      ([err]
        (set success false)
        (:add-error metrics (categorize-error err))))

    # Record stats
    (let [client-duration (- (os/clock :monotonic) client-start)]
      (:add-bytes metrics bytes-sent bytes-recv)
      (:add-runtime metrics client-duration)
      (for _ 0 iterations (:add-iteration metrics))
      (:increment-count metrics))

    # Close connection
    (try (:close conn) ([_] nil))

    success))
