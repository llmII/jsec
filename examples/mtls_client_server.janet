# Mutual TLS (mTLS) Example
# Demonstrates client certificate authentication using in-memory certificates.
# No certificates are written to disk.

(import jsec/tls :as jtls)
(import jsec/cert)

(defn main [& args]
  # 1. Generate Server and Client Certs (in memory)
  (print "Generating certificates in memory...")
  (def server-certs (cert/generate-self-signed-cert {:common-name "localhost"}))
  (def client-certs (cert/generate-self-signed-cert {:common-name "client-user"}))

  (def server-cert-pem (server-certs :cert))
  (def server-key-pem (server-certs :key))
  (def client-cert-pem (client-certs :cert))
  (def client-key-pem (client-certs :key))

  # 2. Start Server with mTLS (requires client certificate)
  (def server-done (ev/chan 1))
  (ev/go
    (fn []
      # Create a TCP listener
      (with [listener (net/listen "127.0.0.1" "9443")]
        (print "Server listening on 9443 (requiring client cert)...")

        # Accept one connection for demo
        (try
          (with [tcp-conn (:accept listener)]
            # Wrap with TLS, requiring client certificate
            (with [tls-conn (jtls/wrap tcp-conn {:cert server-cert-pem
                                                 :key server-key-pem
                                                 # Enable mTLS: require client certificate
                                                 :verify true
                                                 # Trust the specific client certificate
                                                 :trusted-cert client-cert-pem})]
              (print "Server accepted mTLS connection (client cert verified).")
              (:write tls-conn "Hello Authenticated Client!\n")
              (def client-msg (:read tls-conn 1024))
              (print "Server received: " (string client-msg))))
          ([err] (print "Server error: " err))))
      (ev/give server-done true)))

  (ev/sleep 0.5)

  # 3. Start Client with certificate
  (print "Client connecting with certificate...")
  (try
    (with [tcp-conn (net/connect "127.0.0.1" "9443")]
      # Client provides its certificate for mTLS
      (with [tls-conn (jtls/wrap tcp-conn "localhost" {:cert client-cert-pem
                                                       :key client-key-pem
                                                       # Don't verify server for this demo
                                                       # In production, set :verify true and use
                                                       # :trusted-cert with the server's cert
                                                       :verify false})]
        (print "Client connected with certificate!")
        (def server-msg (:read tls-conn 1024))
        (print "Server says: " (string/trim (string server-msg)))
        (:write tls-conn "Hello from authenticated client!")))
    ([err] (print "Client connect error: " err)))

  # Wait for server to complete
  (ev/take server-done)
  (print "mTLS example complete.")
  (os/exit 0))
