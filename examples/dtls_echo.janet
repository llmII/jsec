# DTLS Echo Example (UDP)
# Demonstrates secure UDP communication.
# API follows Janet's net/recv-from and net/send-to conventions.

(import jsec/dtls)
(import jsec/cert)

(defn main [& args]
  (print "Generating certs...")
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))

  # Channel for server readiness
  (def ready-ch (ev/chan 1))
  # Channel to signal shutdown  
  (def done-ch (ev/chan 1))

  # Server Fiber - UDP-style API
  (ev/go (fn []
           (print "DTLS Server starting...")
           (def server (dtls/listen "127.0.0.1" "4444"
                                    {:cert (certs :cert)
                                     :key (certs :key)}))

           (print "DTLS Server listening on 127.0.0.1:4444")
           (ev/give ready-ch true)

           (def buf @"")
           (try
             (while true
               # Receive from any peer - handles handshakes transparently
               # API: (dtls/recv-from server nbytes buf &opt timeout)
               (def peer-addr (dtls/recv-from server 1024 buf 5))
               (when (nil? peer-addr)
                 (break))

               (print "Server received from " (dtls/address-host peer-addr) ":"
                      (dtls/address-port peer-addr) ": " buf)

               # Echo back to the same peer
               (dtls/send-to server peer-addr (string "Echo: " buf))
               (buffer/clear buf))

             ([err]
               (if (string/find "timeout" (string err))
                 (print "Server: Timeout waiting for data (normal)")
                 (print "Server error: " err))))

           (dtls/close-server server)
           (ev/give done-ch true)))

  # Wait for server to be ready
  (ev/take ready-ch)
  (ev/sleep 0.1)

  # Client - 1:1 connection style
  (print "Client connecting...")
  # SECURITY NOTE: :verify false for self-signed certs. In production, verify properly.
  (def client (dtls/connect "127.0.0.1" "4444" {:verify false}))

  (print "Client: Handshake complete")
  (dtls/write client "Hello DTLS!")

  (def response (dtls/read client 1024))
  (print "Client received: " response)

  (try
    (dtls/close client)
    ([err] (print "Client close (ignored): " err)))

  # Wait for server to finish
  (ev/take done-ch)
  (print "Done!"))
