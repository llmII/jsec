###
### lib/metrics.janet - Metrics collection and calculation (OO design)
###

# Metrics prototype - all metrics objects inherit from this
(def Metrics-proto
  @{:add-bytes
    (fn [self sent recv]
      (put self :bytes-sent (+ (self :bytes-sent) sent))
      (put self :bytes-recv (+ (self :bytes-recv) recv))
      self)

    :add-connection
    (fn [self &opt timing]
      (put self :connections (+ (self :connections) 1))
      (when timing
        (array/push (self :conn-timings) timing))
      self)

    :add-error
    (fn [self err-type]
      (let [errs (self :errors)]
        (put errs err-type (+ (get errs err-type 0) 1)))
      self)

    :add-handshake-time
    (fn [self hs-time]
      (array/push (self :handshake-times) hs-time)
      self)

    :add-iteration
    (fn [self]
      (put self :iterations (+ (self :iterations) 1))
      self)

    :add-runtime
    (fn [self runtime]
      (put self :total-runtime (+ (self :total-runtime) runtime))
      self)

    :mark-connected
    (fn [self]
      (put self :connected (+ (self :connected) 1))
      self)

    :mark-skipped
    (fn [self]
      (put self :skipped (+ (self :skipped) 1))
      self)

    :increment-count
    (fn [self]
      (put self :count (+ (self :count) 1))
      self)

    :add-memory-sample
    (fn [self rss vsz]
      "Add a memory sample (RSS and VSZ in KB)"
      (array/push (self :memory-samples) @{:rss rss :vsz vsz :time (os/clock :monotonic)})
      self)

    :add-buffer-wait
    (fn [self wait-type]
      "Track when we had to wait for a buffer (ring buffer contention)"
      (let [waits (or (self :buffer-waits) @{})]
        (put waits wait-type (+ (get waits wait-type 0) 1))
        (put self :buffer-waits waits))
      self)

    :add-echo-wait
    (fn [self wait-time]
      "Track time spent waiting for echo response"
      (unless (self :echo-waits) (put self :echo-waits @[]))
      (array/push (self :echo-waits) wait-time)
      self)

    :add-stat
    (fn [self stat-name value]
      "Add an arbitrary statistic"
      (unless (self :extra-stats) (put self :extra-stats @{}))
      (put (self :extra-stats) stat-name
           (+ (get (self :extra-stats) stat-name 0) value))
      self)

    :merge
    (fn [self other]
      "Merge another metrics object into this one"
      (put self :bytes-sent (+ (self :bytes-sent) (or (other :bytes-sent) 0)))
      (put self :bytes-recv (+ (self :bytes-recv) (or (other :bytes-recv) 0)))
      (put self :connections (+ (self :connections) (or (other :connections) 0)))
      (put self :iterations (+ (self :iterations) (or (other :iterations) 0)))
      (put self :total-runtime (+ (self :total-runtime) (or (other :total-runtime) 0)))
      (put self :count (+ (self :count) (or (other :count) 0)))
      (put self :connected (+ (self :connected) (or (other :connected) 0)))
      (put self :skipped (+ (self :skipped) (or (other :skipped) 0)))
      (when (other :conn-timings)
        (array/concat (self :conn-timings) (other :conn-timings)))
      (when (other :handshake-times)
        (array/concat (self :handshake-times) (other :handshake-times)))
      (when (other :errors)
        (each [k v] (pairs (other :errors))
          (put (self :errors) k (+ (get (self :errors) k 0) v))))
      (when (other :memory-samples)
        (array/concat (self :memory-samples) (other :memory-samples)))
      (when (other :buffer-waits)
        (unless (self :buffer-waits) (put self :buffer-waits @{}))
        (each [k v] (pairs (other :buffer-waits))
          (put (self :buffer-waits) k (+ (get (self :buffer-waits) k 0) v))))
      (when (other :echo-waits)
        (unless (self :echo-waits) (put self :echo-waits @[]))
        (array/concat (self :echo-waits) (other :echo-waits)))
      (when (other :extra-stats)
        (unless (self :extra-stats) (put self :extra-stats @{}))
        (each [k v] (pairs (other :extra-stats))
          (put (self :extra-stats) k (+ (get (self :extra-stats) k 0) v))))
      self)

    :to-table
    (fn [self]
      "Convert to plain table for serialization"
      @{:bytes-sent (self :bytes-sent)
        :bytes-recv (self :bytes-recv)
        :connections (self :connections)
        :iterations (self :iterations)
        :total-runtime (self :total-runtime)
        :count (self :count)
        :connected (self :connected)
        :skipped (self :skipped)
        :conn-timings (self :conn-timings)
        :handshake-times (self :handshake-times)
        :errors (self :errors)
        :memory-samples (self :memory-samples)
        :buffer-waits (self :buffer-waits)
        :echo-waits (self :echo-waits)
        :extra-stats (self :extra-stats)})})

(defn new-metrics
  "Create a new metrics object with OO methods."
  []
  (table/setproto
    @{:bytes-sent 0
      :bytes-recv 0
      :connections 0
      :iterations 0
      :total-runtime 0
      :count 0
      :connected 0
      :skipped 0
      :conn-timings @[]
      :handshake-times @[]
      :errors @{}
      :memory-samples @[]}
    Metrics-proto))

# Legacy factory functions for compatibility
(defn create-client-stats
  "Create empty client stats table (legacy, use new-metrics instead)."
  []
  (new-metrics))

(defn create-server-stats
  "Create empty server stats table (legacy, use new-metrics instead)."
  []
  (new-metrics))

(defn merge-error-counts
  "Merge error count tables into dst."
  [dst src]
  (each [k v] (pairs src)
    (put dst k (+ (get dst k 0) v)))
  dst)

(defn categorize-error
  "Categorize error string into type keyword."
  [err]
  (let [err-str (string/ascii-lower (string err))]
    (cond
      (string/find "timeout" err-str) :timeout
      (string/find "connection refused" err-str) :connection-refused
      (string/find "connection reset" err-str) :connection-reset
      (string/find "could not connect" err-str) :connection-failed
      (string/find "broken pipe" err-str) :broken-pipe
      (string/find "too many open files" err-str) :fd-exhaustion
      (string/find "emfile" err-str) :fd-exhaustion
      (string/find "enfile" err-str) :fd-exhaustion
      (string/find "resource temporarily unavailable" err-str) :resource-busy
      (string/find "eagain" err-str) :resource-busy
      (string/find "ssl" err-str) :ssl-error
      (string/find "handshake" err-str) :handshake-error
      (string/find "address already in use" err-str) :address-in-use
      (string/find "network unreachable" err-str) :network-error
      (string/find "host unreachable" err-str) :network-error
      :other)))

(defn calc-memory-stats
  "Calculate memory statistics from array of samples.
   Returns table with :peak-rss, :peak-vsz, :avg-rss in KB."
  [samples]
  (when (and samples (> (length samples) 0))
    (var peak-rss 0)
    (var peak-vsz 0)
    (var sum-rss 0)
    (each s samples
      (let [rss (or (s :rss) 0)
            vsz (or (s :vsz) 0)]
        (when (> rss peak-rss) (set peak-rss rss))
        (when (> vsz peak-vsz) (set peak-vsz vsz))
        (+= sum-rss rss)))
    @{:peak-rss peak-rss
      :peak-vsz peak-vsz
      :avg-rss (/ sum-rss (length samples))
      :sample-count (length samples)}))

(defn calc-handshake-stats
  "Calculate handshake statistics from array of times."
  [times]
  (when (and times (> (length times) 0))
    (let [sorted-times (sorted times)
          n (length sorted-times)
          sum-hs (sum sorted-times)
          avg-hs (/ sum-hs n)
          min-hs (first sorted-times)
          max-hs (last sorted-times)
          median-hs (get sorted-times (math/floor (/ n 2)))
          p95-idx (math/floor (* n 0.95))
          p95-hs (get sorted-times (min p95-idx (- n 1)))]
      @{:count n :avg avg-hs :min min-hs :max max-hs :median median-hs :p95 p95-hs})))

(defn get-memory-usage
  "Get memory usage for current process or specified PID using ps command.
   Returns table with :rss (resident set size in KB) and :vsz (virtual size in KB).
   Returns nil on error."
  [&opt pid]
  (let [target-pid (or pid (os/getenv "PERF9_PID") (string (os/getpid)))]
    (try
      (let [proc (os/spawn ["ps" "-o" "rss=,vsz=" "-p" (string target-pid)]
                           :p {:out :pipe})
            out (get proc :out)
            output (:read out :all)]
        (:close out)
        (os/proc-wait proc)
        (when output
          (let [trimmed (string/trim output)
                parts (string/split " " trimmed)]
            (when (>= (length parts) 2)
              # Filter out empty strings from multiple spaces
              (let [nums (filter |(not= "" $) parts)]
                (when (>= (length nums) 2)
                  @{:rss (scan-number (get nums 0))
                    :vsz (scan-number (get nums 1))}))))))
      ([err] nil))))

(defn calculate-throughput-phases
  "Calculate ramp-up, peak, and ramp-down throughput from connection timings.
   Divides test duration into 3 equal phases."
  [all-timings duration]
  (if (or (nil? all-timings) (= 0 (length all-timings)) (<= duration 0))
    @{:ramp-up 0 :peak 0 :ramp-down 0}
    (do
      (let [phase-duration (/ duration 3.0)
            phase1-end phase-duration
            phase2-end (* 2 phase-duration)]

        # Find the earliest start time to normalize all times
        (var min-start math/inf)
        (each t all-timings
          (let [start-val (or (get t :start) (get t "start") 0)]
            (when (< start-val min-start)
              (set min-start start-val))))

        # Accumulate bytes per phase
        (var phase1-bytes 0)
        (var phase2-bytes 0)
        (var phase3-bytes 0)

        (each t all-timings
          (let [start-val (or (get t :start) (get t "start") 0)
                conn-start (- start-val min-start)
                conn-duration (or (get t :duration) (get t "duration") 0)
                conn-end (+ conn-start conn-duration)
                bytes (or (get t :bytes) (get t "bytes") 0)]

            (when (and (> conn-duration 0) (> bytes 0))
              (let [bytes-per-sec (/ bytes conn-duration)]

                # Phase 1: 0 to phase1-end
                (when (and (< conn-start phase1-end) (> conn-end 0))
                  (let [overlap-start (max conn-start 0)
                        overlap-end (min conn-end phase1-end)]
                    (when (> overlap-end overlap-start)
                      (+= phase1-bytes (* bytes-per-sec (- overlap-end overlap-start))))))

                # Phase 2: phase1-end to phase2-end
                (when (and (< conn-start phase2-end) (> conn-end phase1-end))
                  (let [overlap-start (max conn-start phase1-end)
                        overlap-end (min conn-end phase2-end)]
                    (when (> overlap-end overlap-start)
                      (+= phase2-bytes (* bytes-per-sec (- overlap-end overlap-start))))))

                # Phase 3: phase2-end to duration
                (when (> conn-end phase2-end)
                  (let [overlap-start (max conn-start phase2-end)
                        overlap-end conn-end]
                    (when (> overlap-end overlap-start)
                      (+= phase3-bytes (* bytes-per-sec (- overlap-end overlap-start))))))))))

        @{:ramp-up (/ phase1-bytes phase-duration)
          :peak (/ phase2-bytes phase-duration)
          :ramp-down (/ phase3-bytes phase-duration)}))))
