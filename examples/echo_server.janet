# TLS Echo Server Example
# Listens on localhost:8443 and echoes back received data.
# Generates a self-signed certificate on startup.

(import jsec/tls :as jtls)
(import jsec/cert)

# 1. Generate a temporary self-signed certificate
(print "Generating temporary self-signed certificate...")
(let [certs (cert/generate-self-signed-cert {:common-name "localhost"})]

  # Write to temp files (jsec accepts file paths)
  (spit "server.crt" (certs :cert))
  (spit "server.key" (certs :key))

  (defer (do (os/rm "server.crt") (os/rm "server.key"))

    # 2. Create the listener
    (let [host "127.0.0.1"
          port "8443"
          listener (jtls/listen host port)]

      (print "Listening on " host ":" port " (TLS)...")
      (print "Use 'openssl s_client -connect 127.0.0.1:8443' to test.")

      # 3. Accept loop
      (forever
        (try
          (let [client (jtls/accept listener {:cert "server.crt"
                                              :key "server.key"})]

            (print "Accepted connection from " (client :peer-name))

            # Handle client in a fiber
            (ev/go (fn []
                     (defer (:close client)
                       (try
                         (do
                           (:write client "Welcome to the Secure Echo Server!\n")
                           (while (let [data (:read client 1024)]
                                    (if data
                                      (do (:write client data) true)
                                      false))))
                         ([err] (print "Client error: " err)))))))

          ([err] (print "Accept error: " err)))))))
