#!/usr/bin/env janet
# Custom BIO Transport Example
#
# Demonstrates using jsec/bio to implement TLS over a custom transport
# (in this case, simulated with in-memory buffers for demonstration)

(import jsec/bio)

(defn main [&]
  (print "Custom BIO Transport Example")
  (print "============================\n")

  # Create memory BIOs for demonstration
  (with [client-to-server (bio/new-mem)
         server-to-client (bio/new-mem)]

    (print "Created bidirectional memory BIOs")

    # Write some data to demonstrate
    (let [test-data "Hello from custom transport!"]
      (:write client-to-server test-data)
      (print "Client wrote: " test-data)

      # Read on server side
      (let [received (:read server-to-client 1024)]
        (if received
          (print "Server received: " (string received))
          (print "No data received"))))

    (print "\nBIOs automatically closed via 'with'")))
