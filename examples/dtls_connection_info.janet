#!/usr/bin/env janet
###
### dtls_connection_info.janet - DTLS Connection Information Example
###
### This example demonstrates how to retrieve connection information
### from an established DTLS connection, including protocol version,
### cipher suite, and peer address.
###

(import jsec/dtls :as dtls)
(import jsec/cert)

(defn main [& args]
  # Generate self-signed certificate for testing
  (print "Generating test certificate...")
  (def certs (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))

  # Start DTLS server
  (def server (dtls/listen "127.0.0.1" 0
                           {:cert (certs :cert)
                            :key (certs :key)}))
  (def [host port] (dtls/localname server))
  (print "Server listening on " host ":" port)

  # Server fiber - echo messages
  (def server-done (ev/chan 1))
  (ev/go
    (fn []
      (def buf (buffer/new 1024))
      (def addr (dtls/recv-from server 1024 buf))
      (when addr
        (print "Server received: " (string buf) " from " addr)
        (dtls/send-to server addr (string "Echo: " (string buf))))
      (ev/give server-done true)))

  (ev/sleep 0.2)

  # Connect client
  (print "\nConnecting client...")
  (def client (dtls/connect "127.0.0.1" port {:verify false}))
  (print "Connected!\n")

  # Display connection information
  (print "=== DTLS Connection Information ===")
  (print "Protocol Version: " (dtls/get-version client))
  (print "Cipher Suite:     " (dtls/get-cipher client))
  (print "Cipher Bits:      " (dtls/get-cipher-bits client))

  # Get all info as struct
  (print "\nFull connection info:")
  (def info (dtls/get-connection-info client))
  (each k (keys info)
    (print "  " k ": " (info k)))

  # Peer address information
  (def peer (dtls/peername client))
  (print "\nPeer Address: " peer)
  (print "  Host: " (dtls/address-host peer))
  (print "  Port: " (dtls/address-port peer))

  # Session information
  (print "\nSession reused? " (dtls/session-reused? client))
  (def session (dtls/get-session client))
  (print "Session data size: " (length session) " bytes")

  # Send/receive a message
  (print "\n=== Data Exchange ===")
  (dtls/write client "Hello, DTLS!")
  (def reply (dtls/read client 1024))
  (print "Received: " (string reply))

  # Cleanup
  (dtls/close client true)
  (ev/take server-done)
  (dtls/close-server server)

  (print "\nDone!"))
