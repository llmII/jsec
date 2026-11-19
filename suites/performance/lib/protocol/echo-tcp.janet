###
### lib/protocol/echo-tcp.janet - TCP/TLS Echo Protocol
###
### Provides factory functions that return standard Janet streams.
### The streams are used directly with their :read, :write, :chunk, :close methods.
### Works with both raw TCP (net/*) and TLS (tls/*).
###

(import jsec/tls :as tls)
(import ../metrics :as metrics)

# Re-export categorize-error from metrics for backwards compatibility
(def categorize-error metrics/categorize-error)

# --------------------------------------------------------------------------
# Server Implementation
# --------------------------------------------------------------------------

(defn- run-datagram-echo-loop
  "Receive datagrams and echo them back using a pre-allocated buffer"
  [server metrics]
  (def buf (buffer/new 65536))
  (while (try (not (get server :closed)) ([_] true))
    (buffer/clear buf)
    (try
      (when-let [peer-addr (:recv-from server 65536 buf 1.0)]
        (when (> (length buf) 0)
          (:send-to server peer-addr buf)
          (when metrics
            (:add-bytes metrics (length buf) 0))))
      ([err]
        (let [err-str (string err)]
          (if (or (string/find "closed" err-str)
                  (string/find "Bad file descriptor" err-str))
            (break)
            (unless (string/find "timeout" err-str)
              (when metrics
                (:add-error metrics (categorize-error err))))))))))

(defn make-server
  "Create echo server listener.
   config should contain: :protocol (:tcp, :tls, :unix, :unix-tls, :udp, or :dtls), :host, :port, :backlog
   For TLS/DTLS: :cert, :key, :handshake-timing, :buffer-size, :ciphers, :ciphersuites
   For unix: :socket-path instead of :host/:port
   handler-fn receives (conn) for each connection (streams only).
   Returns the listener object."
  [config handler-fn]
  (let [protocol (or (config :protocol) :tls)
        backlog (or (config :backlog) 4096)]
    (case protocol
      :tls
      (let [host (or (config :host) "127.0.0.1")
            port (config :port)
            opts @{:cert (config :cert)
                   :key (config :key)
                   :buffer-size (or (config :buffer-size) (* 256 1024))
                   :backlog backlog
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/server host port handler-fn opts))

      :dtls
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))
            opts @{:cert (config :cert)
                   :key (config :key)
                   :datagram true
                   :handshake-timing (or (config :handshake-timing) false)}
            server (tls/listen host port opts)]
        (ev/go (fn [] (run-datagram-echo-loop server (config :metrics))))
        server)

      :udp
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))
            server (net/listen host port :datagram)]
        (ev/go (fn [] (run-datagram-echo-loop server (config :metrics))))
        server)

      :unix
      (let [sock-path (config :socket-path)]
        (when (os/stat sock-path) (os/rm sock-path))
        (net/server :unix sock-path handler-fn))

      :unix-tls
      (let [sock-path (config :socket-path)
            opts @{:cert (config :cert)
                   :key (config :key)
                   :buffer-size (or (config :buffer-size) (* 256 1024))
                   :backlog backlog
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (when (os/stat sock-path) (os/rm sock-path))
        (tls/server :unix sock-path handler-fn opts))

      # Default: Raw TCP
      (let [host (or (config :host) "127.0.0.1")
            port (config :port)]
        (net/server host port handler-fn)))))

(defn echo-handler
  "Standard echo handler for server.
   Reads data, echoes it back, parses final DONE message from client.
   metrics should be a metrics object with :add-bytes, :add-connection, :add-handshake-time, :add-error methods."
  [conn metrics]
  (var hs-captured false)
  (var bytes-echoed 0)
  (var client-completed false)
  (def conn-start (os/clock :monotonic))
  (def buf (buffer/new 65536))
  (defer (:close conn)
    (try
      (while true
        (buffer/clear buf)
        (unless (:read conn 65536 buf) (break))
        # Capture handshake time after first read (TLS only)
        (when (and (not hs-captured) (> (length buf) 0))
          (set hs-captured true)
          (when (get conn :handshake-time)
            (when-let [hs (:handshake-time conn)]
              (:add-handshake-time metrics hs))))
        (when (> (length buf) 0)
          (if (string/has-prefix? "DONE:" buf)
            (do
              (set client-completed true)
              (break))
            (do
              (+= bytes-echoed (length buf))
              (:write conn buf)))))
      ([err]
        (:add-error metrics (categorize-error err))))
    # Record connection
    (let [conn-duration (- (os/clock :monotonic) conn-start)]
      (:add-connection metrics @{:start conn-start :duration conn-duration :bytes bytes-echoed})
      (:add-bytes metrics bytes-echoed 0))))

(defn make-client
  "Create client connection stream.
   config should contain: :protocol, :host, :port
   For TLS/DTLS: :handshake-timing, :buffer-size, :ciphers, :ciphersuites
   For unix: :socket-path instead of :host/:port
   Returns the stream directly."
  [config]
  (let [protocol (or (config :protocol) :tls)]
    (case protocol
      :tls
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))
            opts @{:verify false
                   :buffer-size (or (config :buffer-size) (* 256 1024))
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/connect host port opts))

      :dtls
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))
            opts @{:verify false
                   :datagram true
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/connect host port opts))

      :udp
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))]
        (net/connect host port :datagram))

      :unix
      (let [sock-path (config :socket-path)]
        (net/connect :unix sock-path))

      :unix-tls
      (let [sock-path (config :socket-path)
            opts @{:verify false
                   :buffer-size (or (config :buffer-size) (* 256 1024))
                   :handshake-timing (or (config :handshake-timing) false)}]
        (when (config :ciphers) (put opts :ciphers (config :ciphers)))
        (when (config :ciphersuites) (put opts :ciphersuites (config :ciphersuites)))
        (tls/connect :unix sock-path opts))

      # Default: Raw TCP
      (let [host (or (config :host) "127.0.0.1")
            port (string (config :port))]
        (net/connect host port)))))

(defn run-client
  "Run a single client echo loop using serial write-chunk pattern.
   Uses :chunk / :read method to read exactly N bytes (the echo response).
   conn: stream from make-client
   config: should have :chunk-size, :duration or :iterations, :handshake-timing
   start-time: shared start timestamp for duration mode
   metrics: metrics object to accumulate into
   Returns true if client completed successfully."
  [conn config start-time metrics]
  (let [proto (config :protocol)
        is-datagram (or (= proto :udp) (= proto :dtls))
        chunk-size (or (config :chunk-size) (if is-datagram 1024 (* 256 1024)))
        chunk (buffer/new-filled chunk-size (chr "X"))
        recv-buf (buffer/new chunk-size)
        iteration-mode (not (nil? (config :iterations)))
        target-iterations (or (config :iterations) 0)]

    (var bytes-sent 0)
    (var bytes-recv 0)
    (var iterations 0)
    (var hs-captured false)
    (var success true)

    # In duration mode, check if we have enough time (need at least 2s)
    (when (not iteration-mode)
      (let [time-remaining (- (or (config :duration) 30) (- (os/clock :monotonic) start-time))]
        (when (< time-remaining 2)
          (:mark-skipped metrics)
          (:increment-count metrics)
          (break false))))

    (let [run-start (os/clock :monotonic)
          my-duration (if iteration-mode
                        nil
                        (max 0 (- (or (config :duration) 30) (- (os/clock :monotonic) start-time))))
          end-time (when (not iteration-mode) (+ (os/clock :monotonic) my-duration))]

      (try
        (do
          # Performance loop - serial write then chunk (read exactly N bytes)
          (while (if iteration-mode
                   (< iterations target-iterations)
                   (< (os/clock :monotonic) end-time))
            (:write conn chunk)
            (+= bytes-sent chunk-size)
            # Capture handshake time after first I/O (TLS only)
            (when (and (not hs-captured) (config :handshake-timing))
              (set hs-captured true)
              (when (get conn :handshake-time)
                (when-let [hs (:handshake-time conn)]
                  (:add-handshake-time metrics hs))))
            (buffer/clear recv-buf)
            (if (if is-datagram
                  (:read conn chunk-size recv-buf 5.0)
                  (:chunk conn chunk-size recv-buf))
              (do
                (+= bytes-recv (length recv-buf))
                (++ iterations))
              (do
                (set success false)
                (break))))

          # Send final stats (outside perf measurement) - streams only
          (unless is-datagram
            (let [runtime (- (os/clock :monotonic) run-start)
                  msg (string/format "DONE:%d:%d:%.3f:%d\n" bytes-sent bytes-recv runtime iterations)]
              (try (:write conn msg) ([_] nil)))))
        ([err]
          (set success false)
          (:add-error metrics (categorize-error err))))

      # Record metrics
      (let [runtime (- (os/clock :monotonic) run-start)]
        (:add-bytes metrics bytes-sent bytes-recv)
        (:add-runtime metrics runtime)
        (for _ 0 iterations (:add-iteration metrics))
        (:increment-count metrics)
        (when success
          (:mark-connected metrics)))

      success)))
