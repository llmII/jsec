# DTLS Reusable Context Example
#
# Demonstrates creating and reusing a DTLS context for multiple connections.
# Reusing contexts improves performance by avoiding repeated SSL_CTX setup.
#
# Note: DTLS server listen currently requires cert/key in options directly.
# Client context reuse works for multiple connect operations.
#
# Usage: janet examples/dtls_reusable_context.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (def certs (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))

  # Create a reusable client context
  # This context can be used for multiple connect operations
  (def client-ctx (tls/new-context {:datagram true :verify false}))
  (print "Created reusable client context")

  # Start server (DTLS listen requires cert/key in options)
  (def server (tls/listen "127.0.0.1" "0"
                          {:datagram true :cert (certs :cert) :key (certs :key)}))
  (def [_ port] (:localname server))
  (printf "Server listening on port %d" port)

  # Handle multiple clients with recv-from/send-to pattern
  (def done (ev/chan 1))
  (def buf (buffer/new 1024))
  (ev/go (fn []
           (for i 0 3
             (try
               (do
                 (buffer/clear buf)
                 (let [addr (:recv-from server 1024 buf)]
                   (when addr
                     (printf "Server: Client %d sent: %s" (+ i 1) (string buf))
                     (:send-to server addr (string "Response " (+ i 1))))))
               ([err] nil)))
           (ev/give done true)))

  (ev/sleep 0.1)

  # Multiple clients reusing the same client context
  (for i 0 3
    (ev/sleep 0.05)
    (try
      (let [client (tls/connect "127.0.0.1" port {:datagram true :context client-ctx})]
        (defer (:close client true)
          (:write client (string "Hello " (+ i 1)))
          (let [response (:read client 1024)]
            (printf "Client %d received: %s" (+ i 1) (string response)))))
      ([err] (printf "Client %d error: %v" (+ i 1) err))))

  (ev/take done)
  (:close server)

  # Contexts are automatically freed when no longer referenced
  (print "\nReusable context example completed.")
  (print "Benefits of context reuse:")
  (print "  - Faster connection setup (no certificate parsing overhead)")
  (print "  - Lower memory usage (shared state)")
  (print "  - Consistent configuration across connections"))
