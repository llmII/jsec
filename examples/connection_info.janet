#!/usr/bin/env janet
#
# Connection Info Example
#
# Demonstrates how to retrieve TLS connection details:
# - Protocol version (TLSv1.2, TLSv1.3)
# - Cipher suite
# - Cipher strength
# - Full connection info struct
#
# Usage: janet examples/connection_info.janet

(import jsec/tls :as tls)
(import jsec/cert)

(defn main [&]
  (print "TLS Connection Info Example")
  (print "===========================\n")

  # Generate test certificates
  (def certs (cert/generate-self-signed-cert {:common-name "localhost"}))

  # Start server
  (def server (net/listen "127.0.0.1" "0"))
  (def [_ port] (net/localname server))
  (print "Server listening on port " port "\n")

  # Server handler
  (ev/go (fn []
           (try
             (when-let [conn (:accept server)]
               (defer (:close conn)
                 (try
                   (with [tls-conn (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
                     # Also get server-side connection info
                     (let [info (tls/get-connection-info tls-conn)]
                       (print "Server-side connection info:")
                       (print "  Version: " (info :version))
                       (print "  Cipher: " (info :cipher))
                       (print ""))
                     (:write tls-conn "Connection info available!")
                     (ev/sleep 0.2))
                   ([err] nil))))
             ([err] nil))))

  (ev/sleep 0.1)

  # Connect and retrieve info
  (with [conn (tls/connect "127.0.0.1" (string port) {:verify false})]
    # Read to ensure handshake is complete
    (def msg (:read conn 100))
    (print "Client received: " (string msg) "\n")

    # Get individual info items
    (print "Individual Connection Details:")
    (print "------------------------------")
    (print "  Protocol Version: " (tls/get-version conn))
    (print "  Cipher Suite:     " (tls/get-cipher conn))
    (print "  Cipher Strength:  " (tls/get-cipher-bits conn) " bits")

    # Get full connection info struct
    (print "\nFull Connection Info Struct:")
    (print "----------------------------")
    (def info (tls/get-connection-info conn))
    (each [k v] (pairs info)
      (print "  " k ": " v)))

  (:close server)
  (print "\nDone!"))
