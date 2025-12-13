# TLS 1.3 Key Update Example
#
# Demonstrates how to perform TLS 1.3 key updates for perfect forward secrecy.
# Key updates rotate the encryption keys mid-connection without disrupting data flow.
#
# Note: Key updates only work with TLS 1.3 - TLS 1.2 connections will fail.
#
# Usage: janet examples/tls_key_update.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))

  # Start server with TLS 1.3
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (printf "Server listening on port %d" port)

  # Server fiber
  (ev/go (fn []
           (with [conn (:accept server)]
             (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
               # Receive initial message (completes handshake)
               (def msg1 (string (:read tls-conn 100)))
               (printf "Server: Received before key update: %s" msg1)

               # Now get connection info (handshake is complete)
               (def info (:connection-info tls-conn))
               (printf "Server: Connection established with %s" (info :version))

               # Perform key update (server-initiated) using method
               (try
                 (do
                   (:key-update tls-conn)
                   (print "Server: Key update completed successfully"))
                 ([err]
                   (printf "Server: Key update failed (expected for TLS 1.2): %s" err)))

               # Continue receiving after key update
               (def msg2 (string (:read tls-conn 100)))
               (printf "Server: Received after key update: %s" msg2)

               # Send response
               (:write tls-conn "Key update test complete!")))))

  (ev/sleep 0.2)

  # Client with TLS 1.3
  (with [tls-conn (tls/connect "127.0.0.1" port
                               {:verify false
                                :min-version :TLS1_3 # Force TLS 1.3
                                :max-version :TLS1_3})]
    # Send first message (completes handshake)
    (:write tls-conn "Before key update")

    # Now get connection info
    (def info (:connection-info tls-conn))
    (printf "Client: Connected with %s" (info :version))

    (ev/sleep 0.1)

    # Client can also initiate key update using method
    (try
      (do
        (:key-update tls-conn)
        (print "Client: Key update completed successfully"))
      ([err]
        (printf "Client: Key update failed: %s" err)))

    # Send second message
    (:write tls-conn "After key update")

    # Receive response
    (def response (string (:read tls-conn 100)))
    (printf "Client: Server response: %s" response))

  (:close server)
  (print "\nKey update example completed."))
