#!/usr/bin/env janet
###
### perf9-analyze - Performance test results analyzer
###
### Analyzes JSON output from assay perf9 tests, provides:
### - Summary statistics (throughput, latency, etc.)
### - Comparison between two test runs
### - Grouping by protocol, TLS version, client count
###

(import spork/argparse)
(import spork/json)

#
# Formatting utilities
#

(defn format-bytes
  "Format byte count in human-readable form."
  [bytes]
  (cond
    (>= bytes (* 1024 1024 1024))
    (string/format "%.2f GB" (/ bytes (* 1024 1024 1024)))

    (>= bytes (* 1024 1024))
    (string/format "%.2f MB" (/ bytes (* 1024 1024)))

    (>= bytes 1024)
    (string/format "%.2f KB" (/ bytes 1024))

    (string/format "%d B" (math/floor bytes))))

(defn format-throughput
  "Format throughput in bytes/sec as human-readable."
  [bps]
  (cond
    (>= bps (* 1024 1024 1024))
    (string/format "%.2f GB/s" (/ bps (* 1024 1024 1024)))

    (>= bps (* 1024 1024))
    (string/format "%.2f MB/s" (/ bps (* 1024 1024)))

    (>= bps 1024)
    (string/format "%.2f KB/s" (/ bps 1024))

    (string/format "%.2f B/s" bps)))

(defn format-time
  "Format time in seconds as human-readable."
  [secs]
  (cond
    (< secs 0.001)
    (string/format "%.2f µs" (* secs 1000000))

    (< secs 1)
    (string/format "%.2f ms" (* secs 1000))

    (< secs 60)
    (string/format "%.2f s" secs)

    (string/format "%.1f m" (/ secs 60))))

(defn format-percentage
  "Format percentage with +/- sign for comparison."
  [pct &opt show-sign]
  (if show-sign
    (if (>= pct 0)
      (string/format "+%.1f%%" pct)
      (string/format "%.1f%%" pct))
    (string/format "%.1f%%" pct)))

#
# Statistics utilities
#

(defn mean
  "Calculate mean of array."
  [arr]
  (if (empty? arr)
    0
    (/ (sum arr) (length arr))))

(defn median
  "Calculate median of array."
  [arr]
  (if (empty? arr)
    0
    (let [sorted (sort (array/slice arr))
          n (length sorted)
          mid (math/floor (/ n 2))]
      (if (odd? n)
        (sorted mid)
        (/ (+ (sorted (- mid 1)) (sorted mid)) 2)))))

(defn percentile
  "Calculate nth percentile of array."
  [arr n]
  (if (empty? arr)
    0
    (let [sorted (sort (array/slice arr))
          idx (math/floor (* (/ n 100) (length sorted)))]
      (sorted (min idx (- (length sorted) 1))))))

(defn stddev
  "Calculate standard deviation of array."
  [arr]
  (if (< (length arr) 2)
    0
    (let [m (mean arr)
          variance (mean (map |(math/pow (- $ m) 2) arr))]
      (math/sqrt variance))))

#
# JSON loading
#

(defn load-json
  "Load and parse JSON file."
  [path]
  (try
    (json/decode (slurp path))
    ([err]
      (eprintf "Error loading %s: %s" path err)
      nil)))

#
# Test result extraction
#

(defn extract-test-results
  "Extract performance data from test results."
  [json-data]
  (def results @[])
  (each suite json-data
    (each test (suite "tests")
      (when (test "reported-data")
        (def data @{:name (test "name")
                    :status (test "status")
                    :duration (test "duration")
                    :spawn-type (or (test "spawn-type") "sequential")
                    :server-reports @[]
                    :client-reports @[]})

        # Extract combo info from name or reported data
        (each report (test "reported-data")
          (def d (report "data"))
          (when d
            (when (d "protocol") (put data :protocol (keyword (d "protocol"))))
            (when (d "tls-version") (put data :tls-version (d "tls-version")))
            (when (d "client-count") (put data :client-count (d "client-count")))
            (when (d "chunk-size") (put data :chunk-size (d "chunk-size")))
            (when (d "duration") (put data :test-duration (d "duration")))

            (when (= (d "role") "server")
              (def m (d "metrics"))
              (when m
                (array/push (data :server-reports)
                            @{:connections (m "connections")
                              :bytes-sent (m "bytes-sent")
                              :conn-timings (m "conn-timings")
                              :handshake-times (m "handshake-times")})))

            (when (or (= (d "role") "client-host") (= (d "role") "client"))
              (def m (d "metrics"))
              (when m
                (array/push (data :client-reports)
                            @{:bytes-sent (m "bytes-sent")
                              :bytes-recv (m "bytes-recv")
                              :iterations (m "iterations")
                              :connected (m "connected")
                              :count (m "count")
                              :total-runtime (m "total-runtime")
                              :handshake-times (m "handshake-times")
                              :errors (m "errors")})

                # Accumulate totals
                (put data :bytes-sent (+ (or (data :bytes-sent) 0) (or (m "bytes-sent") 0)))
                (put data :bytes-recv (+ (or (data :bytes-recv) 0) (or (m "bytes-recv") 0)))
                (put data :iterations (+ (or (data :iterations) 0) (or (m "iterations") 0)))
                (put data :connected (+ (or (data :connected) 0) (or (m "connected") 0)))
                (put data :count (+ (or (data :count) 0) (or (m "count") 0)))
                (put data :total-runtime (+ (or (data :total-runtime) 0) (or (m "total-runtime") 0)))

                # Merge handshake times
                (unless (data :handshake-times)
                  (put data :handshake-times @[]))
                (when (m "handshake-times")
                  (array/concat (data :handshake-times) (m "handshake-times")))))))

        # Calculate throughput from accumulated data
        (let [bytes-total (+ (or (data :bytes-sent) 0) (or (data :bytes-recv) 0))
              test-dur (or (data :test-duration) (data :duration) 45)]
          (when (> test-dur 0)
            (put data :throughput (/ bytes-total test-dur))))

        # Record server/client host counts
        (put data :server-count (length (data :server-reports)))
        (put data :client-host-count (length (data :client-reports)))

        # Extract per-client throughputs from server conn-timings for fastest/slowest
        (def client-throughputs @[])
        (each sr (data :server-reports)
          (when (sr :conn-timings)
            (each ct (sr :conn-timings)
              (when (and (ct "bytes") (ct "duration") (> (ct "duration") 0))
                (array/push client-throughputs
                            (/ (* 2 (ct "bytes")) (ct "duration"))))))) # *2 for send+recv
        (when (> (length client-throughputs) 0)
          (def sorted-tp (sort (array/slice client-throughputs)))
          (put data :client-tp-min (first sorted-tp))
          (put data :client-tp-max (last sorted-tp))
          (put data :client-tp-median (median client-throughputs))
          (put data :client-tp-p5 (percentile client-throughputs 5))
          (put data :client-tp-p95 (percentile client-throughputs 95)))

        (array/push results data))))
  results)

#
# Grouping and analysis
#

(defn group-by-key
  "Group results by a key."
  [results key]
  (def groups @{})
  (each r results
    (def k (or (r key) (if (= key :tls-version) "default" "none")))
    (unless (groups k)
      (put groups k @[]))
    (array/push (groups k) r))
  groups)

(defn compute-stats
  "Compute statistics for a group of results."
  [results]
  (def throughputs (filter truthy? (map |($ :throughput) results)))
  (def hs-arrays (filter truthy? (map |($ :handshake-times) results)))
  (def handshake-times (if (empty? hs-arrays) @[] (apply array/concat hs-arrays)))
  (def total-bytes (sum (filter truthy? (map |(+ (or ($ :bytes-sent) 0) (or ($ :bytes-recv) 0)) results))))
  (def total-iterations (sum (filter truthy? (map |($ :iterations) results))))
  (def total-connected (sum (filter truthy? (map |($ :connected) results))))
  (def total-count (sum (filter truthy? (map |($ :count) results))))

  # Per-client throughput stats (fastest/slowest)
  (def client-mins (filter truthy? (map |($ :client-tp-min) results)))
  (def client-maxs (filter truthy? (map |($ :client-tp-max) results)))
  (def client-medians (filter truthy? (map |($ :client-tp-median) results)))

  # Server/client-host counts
  (def server-counts (filter truthy? (map |($ :server-count) results)))
  (def client-host-counts (filter truthy? (map |($ :client-host-count) results)))

  @{:throughput-mean (mean throughputs)
    :throughput-median (median throughputs)
    :throughput-p95 (percentile throughputs 95)
    :throughput-stddev (stddev throughputs)
    :handshake-mean (when (> (length handshake-times) 0) (mean handshake-times))
    :handshake-p95 (when (> (length handshake-times) 0) (percentile handshake-times 95))
    :total-bytes total-bytes
    :total-iterations total-iterations
    :connected total-connected
    :client-count total-count
    :test-count (length results)
    # Per-client stats
    :client-tp-slowest (when (> (length client-mins) 0) (apply min client-mins))
    :client-tp-fastest (when (> (length client-maxs) 0) (apply max client-maxs))
    :client-tp-median (when (> (length client-medians) 0) (mean client-medians))
    # Participant counts
    :server-count (when (> (length server-counts) 0) (math/round (mean server-counts)))
    :client-host-count (when (> (length client-host-counts) 0) (math/round (mean client-host-counts)))})

#
# Display functions
#

(defn print-separator
  [&opt char width]
  (default char "=")
  (default width 80)
  (print (string/repeat char width)))

(defn print-header
  [title]
  (print)
  (print-separator)
  (printf "  %s" title)
  (print-separator))

(defn print-subheader
  [title]
  (print)
  (print-separator "-" 60)
  (printf "  %s" title)
  (print-separator "-" 60))

(defn print-test-result
  "Print detailed result for a single test."
  [r &opt idx]
  (when idx
    (printf "\n  [Test #%d]" idx))
  (printf "  Name:          %s" (r :name))
  (printf "  Status:        %s" (or (r :status) "unknown"))

  # Configuration
  (print "  Configuration:")
  (printf "    Protocol:      %s" (or (r :protocol) "n/a"))
  (when (r :tls-version)
    (printf "    TLS Version:   %s" (r :tls-version)))
  (printf "    Clients:       %d" (or (r :client-count) 0))
  (printf "    Chunk Size:    %s" (format-bytes (or (r :chunk-size) 0)))
  (printf "    Duration:      %s" (format-time (or (r :test-duration) (r :duration) 0)))
  (printf "    Worker Type:   %s" (or (r :spawn-type) "sequential"))

  # Participant counts
  (when (or (r :server-count) (r :client-host-count))
    (printf "    Servers:       %d" (or (r :server-count) 0))
    (printf "    Client Hosts:  %d" (or (r :client-host-count) 0)))

  # Performance metrics
  (print "  Performance:")
  (when (r :throughput)
    (printf "    Throughput:    %s" (format-throughput (r :throughput))))
  (when (and (r :bytes-sent) (r :bytes-recv))
    (printf "    Data Sent:     %s" (format-bytes (r :bytes-sent)))
    (printf "    Data Recv:     %s" (format-bytes (r :bytes-recv)))
    (printf "    Total Data:    %s" (format-bytes (+ (r :bytes-sent) (r :bytes-recv)))))
  (when (r :iterations)
    (printf "    Iterations:    %d" (r :iterations)))
  (when (r :connected)
    (printf "    Connected:     %d/%d" (r :connected) (or (r :count) (r :client-count) 0)))

  # Per-client throughput range
  (when (and (r :client-tp-min) (r :client-tp-max))
    (printf "    Slowest Client: %s" (format-throughput (r :client-tp-min)))
    (printf "    Fastest Client: %s" (format-throughput (r :client-tp-max)))
    (when (r :client-tp-median)
      (printf "    Median Client:  %s" (format-throughput (r :client-tp-median)))))

  # Handshake timings
  (when (r :handshake-times)
    (def hs (r :handshake-times))
    (when (> (length hs) 0)
      (print "  Handshake Timings:")
      (printf "    Mean:          %s" (format-time (mean hs)))
      (printf "    Median:        %s" (format-time (median hs)))
      (printf "    P5:            %s" (format-time (percentile hs 5)))
      (printf "    P95:           %s" (format-time (percentile hs 95)))
      (printf "    Min:           %s" (format-time (apply min hs)))
      (printf "    Max:           %s" (format-time (apply max hs))))))

(defn print-stats
  "Print statistics for a result group."
  [label stats]
  (printf "\n  %s:" label)
  (printf "    Throughput:    %s (mean), %s (median), %s (p95)"
          (format-throughput (stats :throughput-mean))
          (format-throughput (stats :throughput-median))
          (format-throughput (stats :throughput-p95)))
  (when (and (stats :client-tp-slowest) (stats :client-tp-fastest))
    (printf "    Client range:  %s (slowest) → %s (fastest)"
            (format-throughput (stats :client-tp-slowest))
            (format-throughput (stats :client-tp-fastest))))
  (when (stats :handshake-mean)
    (printf "    Handshake:     %s (mean), %s (p95)"
            (format-time (stats :handshake-mean))
            (format-time (stats :handshake-p95))))
  (printf "    Total bytes:   %s" (format-bytes (stats :total-bytes)))
  (printf "    Iterations:    %d" (stats :total-iterations))
  (printf "    Connected:     %d/%d" (stats :connected) (stats :client-count))
  (when (and (stats :server-count) (stats :client-host-count))
    (printf "    Participants:  %d server(s), %d client-host(s)"
            (stats :server-count) (stats :client-host-count)))
  (printf "    Tests:         %d" (stats :test-count)))

(defn print-comparison
  "Print comparison between two stat sets."
  [label stats1 stats2]
  (def tp1 (stats1 :throughput-mean))
  (def tp2 (stats2 :throughput-mean))
  (def diff-pct (if (> tp1 0)
                  (* 100 (/ (- tp2 tp1) tp1))
                  0))

  (printf "\n  %s:" label)
  (printf "    Throughput:  %s → %s (%s)"
          (format-throughput tp1)
          (format-throughput tp2)
          (format-percentage diff-pct true))

  (when (and (stats1 :handshake-mean) (stats2 :handshake-mean))
    (def hs1 (stats1 :handshake-mean))
    (def hs2 (stats2 :handshake-mean))
    (def hs-diff-pct (if (> hs1 0) (* 100 (/ (- hs2 hs1) hs1)) 0))
    (printf "    Handshake:   %s → %s (%s)"
            (format-time hs1)
            (format-time hs2)
            (format-percentage hs-diff-pct true))))

#
# Commands
#

(defn cmd-summary
  "Print summary of a test run."
  [json-path &opt show-individual]
  (def data (load-json json-path))
  (unless data (os/exit 1))

  (def results (extract-test-results data))
  (when (empty? results)
    (print "No test results found")
    (os/exit 1))

  (print-header "Performance Test Summary")
  (printf "  File: %s" json-path)
  (printf "  Total tests: %d" (length results))

  # Show individual test results first (if requested or by default)
  (when (or show-individual (nil? show-individual))
    (print-header "Individual Test Results")
    (var idx 0)
    (each r (sort-by |($ :name) results)
      (++ idx)
      (print-test-result r idx)))

  # Group by protocol
  (print-header "Results by Protocol")
  (def by-proto (group-by-key results :protocol))
  (eachp [proto group] by-proto
    (print-stats (string proto) (compute-stats group)))

  # Group by TLS version (for TLS tests)
  (def tls-results (filter |(or (= ($ :protocol) :tls) (= ($ :protocol) :unix-tls)) results))
  (when (> (length tls-results) 0)
    (print-header "Results by TLS Version")
    (def by-version (group-by-key tls-results :tls-version))
    (eachp [ver group] by-version
      (print-stats (string "TLS " ver) (compute-stats group))))

  # Group by client count
  (print-header "Results by Client Count")
  (def by-clients (group-by-key results :client-count))
  (each count (sort (keys by-clients))
    (def group (by-clients count))
    (print-stats (string count " clients") (compute-stats group)))

  # Group by worker type
  (print-header "Results by Worker Type")
  (def by-spawn (group-by-key results :spawn-type))
  (each spawn-type (sort (keys by-spawn))
    (def group (by-spawn spawn-type))
    (print-stats (string spawn-type) (compute-stats group)))

  # Group by server count
  (def server-counts (distinct (filter truthy? (map |($ :server-count) results))))
  (when (> (length server-counts) 1)
    (print-header "Results by Server Count")
    (def by-servers (group-by-key results :server-count))
    (each cnt (sort (keys by-servers))
      (when cnt
        (def group (by-servers cnt))
        (print-stats (string cnt " server(s)") (compute-stats group)))))

  # Group by client-host count
  (def ch-counts (distinct (filter truthy? (map |($ :client-host-count) results))))
  (when (> (length ch-counts) 1)
    (print-header "Results by Client-Host Count")
    (def by-ch (group-by-key results :client-host-count))
    (each cnt (sort (keys by-ch))
      (when cnt
        (def group (by-ch cnt))
        (print-stats (string cnt " client-host(s)") (compute-stats group)))))

  # Overall stats
  (print-header "Overall Statistics")
  (print-stats "All tests" (compute-stats results))

  (print))

(defn cmd-compare
  "Compare two test runs."
  [json-path1 json-path2]
  (def data1 (load-json json-path1))
  (def data2 (load-json json-path2))
  (unless (and data1 data2) (os/exit 1))

  (def results1 (extract-test-results data1))
  (def results2 (extract-test-results data2))

  (print-header "Performance Comparison")
  (printf "  File 1: %s" json-path1)
  (printf "  File 2: %s" json-path2)

  # Compare by protocol
  (print-header "Comparison by Protocol")
  (def by-proto1 (group-by-key results1 :protocol))
  (def by-proto2 (group-by-key results2 :protocol))
  (each proto (distinct (array/concat (keys by-proto1) (keys by-proto2)))
    (when (and (by-proto1 proto) (by-proto2 proto))
      (print-comparison (string proto)
                        (compute-stats (by-proto1 proto))
                        (compute-stats (by-proto2 proto)))))

  # Compare by client count
  (print-header "Comparison by Client Count")
  (def by-clients1 (group-by-key results1 :client-count))
  (def by-clients2 (group-by-key results2 :client-count))
  (each count (sort (distinct (array/concat (keys by-clients1) (keys by-clients2))))
    (when (and (by-clients1 count) (by-clients2 count))
      (print-comparison (string count " clients")
                        (compute-stats (by-clients1 count))
                        (compute-stats (by-clients2 count)))))

  # Overall comparison
  (print-header "Overall Comparison")
  (print-comparison "All tests"
                    (compute-stats results1)
                    (compute-stats results2))

  (print))

(defn cmd-detail
  "Print detailed results for all tests."
  [json-path]
  (def data (load-json json-path))
  (unless data (os/exit 1))

  (def results (extract-test-results data))

  (print-header "Detailed Test Results")
  (printf "  File: %s" json-path)

  (each r (sort-by |($ :name) results)
    (print)
    (printf "  Test: %s" (r :name))
    (printf "    Status: %s" (r :status))
    (printf "    Protocol: %s" (or (r :protocol) "n/a"))
    (when (r :tls-version)
      (printf "    TLS Version: %s" (r :tls-version)))
    (printf "    Clients: %s" (or (r :client-count) "n/a"))
    (when (r :throughput)
      (printf "    Throughput: %s" (format-throughput (r :throughput))))
    (printf "    Duration: %s" (format-time (or (r :duration) 0)))
    (when (and (r :bytes-sent) (r :bytes-recv))
      (printf "    Data: %s sent, %s recv"
              (format-bytes (r :bytes-sent))
              (format-bytes (r :bytes-recv))))
    (when (r :handshake-times)
      (def hs (r :handshake-times))
      (when (> (length hs) 0)
        (printf "    Handshake: %s (mean), %s (p95)"
                (format-time (mean hs))
                (format-time (percentile hs 95))))))

  (print))

#
# Main
#

(def argparse-params
  ["perf9-analyze - Performance test results analyzer"
   :default {:kind :option}
   "summary" {:kind :flag
              :short "s"
              :help "Print summary of a test run"}
   "compare" {:kind :flag
              :short "c"
              :help "Compare two test runs"}
   "detail" {:kind :flag
             :short "d"
             :help "Print detailed results"}
   "no-individual" {:kind :flag
                    :short "n"
                    :help "Skip individual test results in summary"}
   "output" {:kind :option
             :short "o"
             :help "Output file (default: stdout)"}
   :default {:kind :accumulate}])

(defn main
  [& args]
  (def parsed (argparse/argparse ;argparse-params))
  (unless parsed
    (os/exit 1))

  (def files (parsed :default))

  (cond
    (parsed "compare")
    (if (< (length files) 2)
      (do
        (eprint "Compare requires two JSON files")
        (os/exit 1))
      (cmd-compare (files 0) (files 1)))

    (parsed "detail")
    (if (empty? files)
      (do
        (eprint "Detail requires a JSON file")
        (os/exit 1))
      (cmd-detail (files 0)))

    # Default: summary
    (if (empty? files)
      (do
        (eprint "Summary requires a JSON file")
        (os/exit 1))
      (cmd-summary (files 0) (not (parsed "no-individual"))))))
