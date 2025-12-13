# DTLS Multi-Client Server Example
#
# Demonstrates a DTLS server handling multiple simultaneous clients.
# Each client is handled in its own fiber, showing concurrent peer management.
#
# Usage: janet examples/dtls_multi_client.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (def certs (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))
  (def clients-handled @[])
  (def done (ev/chan 1))

  # Start DTLS server using tls/listen with :datagram option
  (def server (tls/listen "127.0.0.1" "0"
                          {:datagram true :cert (certs :cert) :key (certs :key)}))
  (def [_ port] (:localname server))
  (printf "DTLS Server listening on port %d" port)

  # Server handler - handle multiple clients via recv-from/send-to
  (ev/go (fn []
           (def buf (buffer/new 1024))
           (for i 0 3 # Handle 3 messages
             (try
               (do
                 (buffer/clear buf)
                 (let [addr (:recv-from server 1024 buf)]
                   (when addr
                     (printf "Server: Received from %s:%d: %s"
                             (tls/address-host addr) (tls/address-port addr) (string buf))
                     (:send-to server addr (string "Echo: " buf))
                     (array/push clients-handled (+ i 1)))))
               ([err] (printf "Server: Error: %v" err))))

           # Wait for all clients to be handled
           (ev/sleep 0.5)
           (ev/give done true)))

  (ev/sleep 0.1)

  # Spawn multiple clients concurrently
  (def client-fibers @[])
  (for i 0 3
    (def f (ev/go (fn []
                    (ev/sleep (* i 0.05)) # Stagger connections slightly
                    (try
                      (let [client (tls/connect "127.0.0.1" (string port)
                                                {:datagram true :verify false})]
                        (defer (:close client true)
                          (printf "Client %d: Connected" (+ i 1))

                          # Send a message
                          (:write client (string "Hello from client " (+ i 1)))

                          # Receive response
                          (let [response (:read client 1024)]
                            (printf "Client %d: Received: %s" (+ i 1) (string response)))))
                      ([err] (printf "Client %d: Error: %v" (+ i 1) err))))))
    (array/push client-fibers f))

  # Wait for done signal
  (ev/take done)

  (:close server)
  (printf "\nServer handled %d clients: %v" (length clients-handled) clients-handled)
  (print "Multi-client DTLS example completed."))
