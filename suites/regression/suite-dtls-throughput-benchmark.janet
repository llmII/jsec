(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn run-dtls-benchmark
  "Run an in-process DTLS echo benchmark of n datagrams with chunk-size payload.
   Returns {:count count :elapsed elapsed :rate rate :mbps mbps}."
  [&opt n chunk-size]
  (default n 1000)
  (default chunk-size 1024)

  (def server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                          :key (certs :key)}))
  (def port (get (dtls/localname server) 1))
  (def server-done (ev/chan 1))

  # Server echo fiber
  (ev/go
    (fn []
      (def buf (buffer/new (+ chunk-size 256)))
      (for i 0 n
        (def addr (dtls/recv-from server (+ chunk-size 256) buf 10))
        (unless addr (break))
        (dtls/send-to server addr buf)
        (buffer/clear buf))
      (ev/give server-done true)))

  # Client connection
  (def client (dtls/connect "127.0.0.1" port {:verify false}))
  (def payload (string/repeat "x" chunk-size))
  (def recv-buf (buffer/new (+ chunk-size 256)))

  (def start (os/clock :monotonic))
  (for i 0 n
    (dtls/write client payload)
    (buffer/clear recv-buf)
    (dtls/read client (+ chunk-size 256) recv-buf 10))
  (def elapsed (- (os/clock :monotonic) start))

  (try (:close client) ([_] nil))
  (ev/take server-done)
  (try (:close server) ([_] nil))

  (def rate (/ n elapsed))
  (def total-bytes (* n chunk-size 2)) # sent + received
  (def mbps (/ total-bytes (* elapsed 1048576.0)))

  {:count n
   :chunk-size chunk-size
   :elapsed elapsed
   :rate rate
   :mbps mbps})

(def-suite :name "suite-dtls-throughput-benchmark"
  :category "regression"

  (def-test "dtls-echo-throughput"
    (def res (run-dtls-benchmark 1000 1024))
    (assert (> (res :rate) 50.0) "DTLS throughput rate should be reasonable")))
