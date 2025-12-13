#!/usr/bin/env janet
#
# Chunked Reading Example
#
# Demonstrates the difference between tls/read and tls/chunk:
# - tls/read returns as soon as any data is available (up to n bytes)
# - tls/chunk blocks until exactly n bytes are received (or EOF)
#
# This is useful for protocols that require fixed-size message headers
# or exact byte counts.
#
# Usage: janet examples/chunk_read.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (print "TLS Chunk Read Example")
  (print "======================\n")

  # Generate test certificates
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))

  # Start server that sends data in small pieces
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (print "Server listening on port " port "\n")

  # Server sends 100 bytes in 10 pieces of 10 bytes each
  (ev/go (fn []
           (try
             (when-let [conn (:accept server)]
               (defer (:close conn)
                 (try
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     (print "Server: Sending 100 bytes in 10 chunks of 10...")
                     (for i 0 10
                       (def chunk (string/repeat (string (% i 10)) 10))
                       (:write tls-conn chunk)
                       (ev/sleep 0.05)) # Small delay between chunks
                     (print "Server: All chunks sent")
                     (ev/sleep 0.2))
                   ([err] nil))))
             ([err] nil))))

  (ev/sleep 0.1)

  # Client demonstrates chunk vs read
  (with [conn (tls/connect "127.0.0.1" (string port) {:verify false})]
    # Example 1: Using chunk to read exactly 50 bytes
    (print "Client: Reading exactly 50 bytes with :chunk...")
    (def buf1 @"")
    (:chunk conn 50 buf1)
    (print "  Received " (length buf1) " bytes: " (string buf1))
    (assert (= (length buf1) 50) "chunk should return exactly 50 bytes")

    # Example 2: Read remaining data
    (print "\nClient: Reading remaining data with :read...")
    (def buf2 @"")
    (:read conn 100 buf2)
    (print "  Received " (length buf2) " bytes: " (string buf2))

    (print "\nTotal bytes received: " (+ (length buf1) (length buf2))))

  (:close server)
  (print "\nDone!"))
