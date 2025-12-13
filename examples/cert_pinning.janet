#!/usr/bin/env janet
#
# Certificate Pinning Example
#
# Demonstrates how to verify connections using a specific trusted certificate
# without a full CA chain. This is useful for:
# - Peer-to-peer connections with known certificates
# - Certificate pinning for enhanced security
# - Testing with self-signed certificates
#
# Note: When using certificate pinning with verification, the certificate's
# Common Name (CN) must match the hostname used for connection.
#
# Usage: janet examples/cert_pinning.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (print "Certificate Pinning Example")
  (print "===========================\n")

  # Generate a self-signed certificate for localhost
  # The CN must match the hostname we'll use to connect
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))
  (def server-cert (certs :cert))
  (def server-key (certs :key))

  (print "Generated server certificate for 'localhost'\n")

  # Start a simple server on localhost
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (print "Server listening on port " port)

  # Server handler
  (ev/go (fn []
           (while true
             (try
               (when-let [conn (:accept server)]
                 (ev/go (fn []
                          (defer (:close conn)
                            (try
                              (with [tls-conn (tls/wrap conn {:cert server-cert :key server-key})]
                                (:write tls-conn "Hello from pinned server!")
                                (ev/sleep 0.1))
                              ([err] nil))))))
               ([err] (break))))))

  (ev/sleep 0.1)

  # Method 1: Using :trusted-cert option in tls/connect
  # Connect to "localhost" (must match cert CN) but bind to 127.0.0.1
  (print "\nMethod 1: Using :trusted-cert option")
  (print "-------------------------------------")
  (try
    (with [conn (tls/connect "localhost" (string port)
                             {:verify true
                              :trusted-cert server-cert})]
      (def response (string (:read conn 100)))
      (print "  Received: " response)
      (print "  ✓ Connection verified against pinned certificate"))
    ([err]
      (print "  ✗ Error: " err)))

  (ev/sleep 0.1)

  # Method 2: Using tls/new-context + tls/trust-cert
  (print "\nMethod 2: Using explicit context")
  (print "---------------------------------")
  (try
    (let [ctx (tls/new-context {:verify true})]
      (tls/trust-cert ctx server-cert)
      (with [conn (tls/connect "localhost" (string port) {:context ctx})]
        (def response (string (:read conn 100)))
        (print "  Received: " response)
        (print "  ✓ Connection verified with explicit context")))
    ([err]
      (print "  ✗ Error: " err)))

  (ev/sleep 0.1)

  # Method 3: Show what happens without pinning (should fail)
  (print "\nMethod 3: Without certificate pinning (should fail)")
  (print "---------------------------------------------------")
  (try
    (with [conn (tls/connect "localhost" (string port) {:verify true})]
      (def response (string (:read conn 100)))
      (print "  Received: " response)
      (print "  ✗ Should have failed!"))
    ([err]
      (print "  ✓ Connection correctly rejected (no trusted cert)")))

  (:close server)
  (print "\nDone!"))
