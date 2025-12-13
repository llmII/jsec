# DTLS Session Resumption Example
#
# Demonstrates DTLS session resumption to avoid full handshake overhead.
# Session resumption reuses cryptographic parameters from a previous connection.
#
# Usage: janet examples/dtls_session_resumption.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (def certs (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))

  # Start server
  (def server (tls/listen "127.0.0.1" "0"
                          {:datagram true :cert (certs :cert) :key (certs :key)}))
  (def [_ port] (:localname server))
  (printf "DTLS Server listening on port %d" port)

  # Server handler using recv-from/send-to pattern
  (def done (ev/chan 1))
  (def buf (buffer/new 1024))
  (ev/go (fn []
           (for i 0 3
             (try
               (do
                 (buffer/clear buf)
                 (let [addr (:recv-from server 1024 buf)]
                   (when addr
                     (printf "Server: Received '%s' from %s:%d"
                             (string buf) (tls/address-host addr) (tls/address-port addr))
                     (:send-to server addr (string "Response " (+ i 1))))))
               ([err] nil)))
           (ev/give done true)))

  (ev/sleep 0.1)

  # First connection - establishes new session
  (print "\n--- First Connection (new session) ---")
  (var saved-session nil)
  (try
    (let [client (tls/connect "127.0.0.1" port
                              {:datagram true :verify false})]
      (defer (:close client true)
        # Send message
        (:write client "First message")

        # Receive response
        (let [response (:read client 1024)]
          (printf "Client: Server says: %s" (string response)))

        # Save the session for resumption using method call
        (set saved-session (:get-session client))
        (if saved-session
          (print "Client: Session saved for resumption")
          (print "Client: Could not get session"))))
    ([err] (printf "First connection error: %v" err)))

  (ev/sleep 0.2)

  # Second connection - attempts to resume session
  (print "\n--- Second Connection (resume attempt) ---")
  (try
    (let [client (tls/connect "127.0.0.1" port
                              {:datagram true
                               :verify false
                               :session saved-session})] # Pass saved session
      (defer (:close client true)
        # Check if session was reused
        (printf "Client: Session reused: %v" (:session-reused? client))

        (:write client "Second message")

        (let [response (:read client 1024)]
          (printf "Client: Server says: %s" (string response)))))
    ([err] (printf "Second connection error: %v" err)))

  (ev/sleep 0.2)

  # Third connection without session - should be new
  (print "\n--- Third Connection (no session) ---")
  (try
    (let [client (tls/connect "127.0.0.1" port
                              {:datagram true :verify false})]
      (defer (:close client true)
        (printf "Client: Session reused: %v" (:session-reused? client))

        (:write client "Third message")

        (let [response (:read client 1024)]
          (printf "Client: Server says: %s" (string response)))))
    ([err] (printf "Third connection error: %v" err)))

  (ev/take done)
  (:close server)

  (print "\nSession resumption benefits:")
  (print "  - Faster connection (no full handshake)")
  (print "  - Lower latency (fewer round trips)")
  (print "  - Reduced CPU usage (no asymmetric crypto)"))
