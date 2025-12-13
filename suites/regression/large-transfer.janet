###
### Large data transfer regression test
###
### Tests that large data transfers complete within reasonable time.
### This verifies TLS performance doesn't regress.
###
### Uses janet-assay coordinated test type for clean server/client separation.
###

(import assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Configuration from environment or defaults
(def data-size
  (if-let [env-size (os/getenv "JSEC_LARGE_TRANSFER_SIZE")]
    (scan-number env-size)
    (* 10 1024 1024))) # 10MB default (reduced for faster tests)

(def deadline
  (if-let [env-deadline (os/getenv "JSEC_LARGE_TRANSFER_DEADLINE")]
    (scan-number env-deadline)
    60)) # 60 seconds default

(def chunk-size 65536)

# Generate certs at suite load time (shared by all tests in this module)
(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(assay/def-suite :name "Large Transfer Regression"
                 :timeout (+ deadline 30) # Add buffer beyond transfer deadline

                 (assay/def-test "large data transfer completes within deadline"
                                 :type :coordinated

                                 # Server participant - receives all data, sends acknowledgment
                                 (assay/def-test "server"
                                                 (def start-time (os/clock))
                                                 (with [server (tls/listen "127.0.0.1" "0")]
                                                   (let [[_ port] (net/localname server)]
                                                     # Signal ready with our port
                                                     (emit :ready {:port (string port)})

                                                     (try
                                                       (with [client (tls/accept server {:cert (certs :cert) :key (certs :key)})]
                                                         # Receive all data
                                                         (var total 0)
                                                         (while (< total data-size)
                                                           (if-let [chunk (:read client chunk-size)]
                                                             (+= total (length chunk))
                                                             (break)))

                                                         # Send acknowledgment back
                                                         (:write client (string/format "received:%d" total))

                                                         # Report data for metrics
                                                         (report-data {:server-bytes total
                                                                       :elapsed (- (os/clock) start-time)})

                                                         (assay/assert (= total data-size)
                                                                       (string/format "Server should receive all data: %d/%d" total data-size)))
                                                       ([err]
                                                         (error (string "Server error: " err)))))))

                                 # Client participant - sends all data, reads acknowledgment
                                 (assay/def-test "client"
                                                 (def start-time (os/clock))
                                                 # Wait for server to be ready and get port
                                                 (def server-info (await :server :ready))
                                                 (def port (server-info :port))

                                                 (try
                                                   (with [conn (tls/connect "127.0.0.1" port {:verify false})]
                                                     (def chunk (string/repeat "X" chunk-size))

                                                     # Send all data
                                                     (var sent 0)
                                                     (while (< sent data-size)
                                                       (let [to-send (min chunk-size (- data-size sent))]
                                                         (if (= to-send chunk-size)
                                                           (:write conn chunk)
                                                           (:write conn (string/slice chunk 0 to-send)))
                                                         (+= sent to-send)))

                                                     # Read acknowledgment
                                                     (def ack (string (:read conn 256)))
                                                     (def elapsed (- (os/clock) start-time))

                                                     # Report data for metrics
                                                     (report-data {:client-bytes sent
                                                                   :elapsed elapsed
                                                                   :ack ack})

                                                     (assay/assert (= sent data-size)
                                                                   (string/format "Client should send all data: %d/%d" sent data-size))
                                                     (assay/assert (string/has-prefix? "received:" ack)
                                                                   "Should receive acknowledgment")
                                                     (assay/assert (< elapsed deadline)
                                                                   (string/format "Transfer took %.2fs, deadline was %ds" elapsed deadline)))
                                                   ([err]
                                                     (error (string "Client error: " err)))))))
