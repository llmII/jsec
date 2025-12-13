# STARTTLS Example (SMTP)
# Connects to an SMTP server, initiates STARTTLS, and upgrades the connection.
# Note: This example connects to gmail.com's SMTP server.
#
# Usage: janet examples/starttls_smtp.janet

(import jsec/tls :as tls)

(defn main [& args]
  (let [host "smtp.gmail.com"
        port "587"]

    (print "Connecting to " host ":" port " (Plaintext)...")
    (let [stream (net/connect host port)]

      # Read initial greeting
      (print "Server: " (:read stream 1024))

      # Send EHLO
      (print "Client: EHLO localhost")
      (:write stream "EHLO localhost\r\n")
      (print "Server: " (:read stream 4096))

      # Send STARTTLS
      (print "Client: STARTTLS")
      (:write stream "STARTTLS\r\n")
      (let [response (:read stream 1024)]
        (print "Server: " response)

        (if (string/find "220" response)
          (do
            (print "--- Upgrading to TLS ---")
            (let [tls-stream (tls/upgrade stream host {:verify true})]

              (print "TLS Handshake Complete!")
              (print "Cipher: " (:cipher tls-stream))

              # Now we are encrypted. Send EHLO again as required by SMTP
              (:write tls-stream "EHLO localhost\r\n")
              (print "Server (Encrypted): " (:read tls-stream 4096))

              (:close tls-stream)))
          (print "Server did not accept STARTTLS"))))))
