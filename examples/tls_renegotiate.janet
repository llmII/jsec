# TLS 1.2 Renegotiation Example
#
# Demonstrates TLS 1.2 renegotiation. Note that renegotiation is disabled by
# default in jsec for security reasons (CVE-2009-3555). Enable only if required.
#
# WARNING: Renegotiation has known security issues and is deprecated in TLS 1.3.
# Only use this for compatibility with legacy systems that require it.
#
# Usage: janet examples/tls_renegotiate.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))

  # Start server with TLS 1.2 and renegotiation enabled
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (printf "Server listening on port %d" port)

  # Server fiber
  (ev/go (fn []
           (with [conn (:accept server)]
             # Enable renegotiation for this context
             (with [tls-conn (tls/wrap conn {:cert (certs :cert)
                                             :key (certs :key)
                                             :allow-renegotiation true # Enable renegotiation
                                             :min-version :TLS1_2
                                             :max-version :TLS1_2})]
               # Receive initial message (completes handshake)
               (def msg1 (string (:read tls-conn 100)))
               (printf "Server: Received before renegotiation: %s" msg1)

               # Now get connection info
               (def info (:connection-info tls-conn))
               (printf "Server: Connection established with %s" (info :version))

               # Wait for potential client-initiated renegotiation
               (ev/sleep 0.2)

               # Continue receiving
               (def msg2 (string (:read tls-conn 100)))
               (printf "Server: Received after renegotiation: %s" msg2)

               (:write tls-conn "Renegotiation test complete!")))))

  (ev/sleep 0.2)

  # Client with TLS 1.2 and renegotiation enabled
  (with [tls-conn (tls/connect "127.0.0.1" port
                               {:verify false
                                :allow-renegotiation true # Enable renegotiation
                                :min-version :TLS1_2
                                :max-version :TLS1_2})]
    # Send first message (completes handshake)
    (:write tls-conn "Before renegotiation")

    # Now get connection info
    (def info (:connection-info tls-conn))
    (printf "Client: Connected with %s" (info :version))

    (ev/sleep 0.1)

    # Attempt renegotiation using method
    (try
      (do
        (:renegotiate tls-conn)
        (print "Client: Renegotiation completed successfully"))
      ([err]
        (printf "Client: Renegotiation failed: %s" err)
        (print "Client: (This is expected - renegotiation is often disabled)")))

    # Send second message
    (:write tls-conn "After renegotiation")

    # Receive response
    (def response (string (:read tls-conn 100)))
    (printf "Client: Server response: %s" response))

  (:close server)
  (print "\nRenegotiation example completed.")
  (print "Note: Renegotiation is deprecated and disabled by default for security."))
