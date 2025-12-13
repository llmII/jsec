# Simple HTTPS Client Example
# Connects to example.com and fetches the homepage

(import jsec/tls :as jtls)

(print "Connecting to example.com:443...")

# Connect to server with TLS verification enabled (default)
(with [stream (jtls/connect "example.com" "443" {:verify true})]
  (print "Connected! Sending HTTP request...")

  # Send minimal HTTP/1.1 request
  (:write stream
          "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

  # Read response
  (var response @"")
  (while (let [chunk (:read stream 4096)]
           (if chunk
             (do (buffer/push response chunk) true)
             false)))

  (print "\n--- Response Headers (Preview) ---")
  (print (string/slice response 0 300))
  (print "...\n")

  (print "Connection automatically closed via 'with' macro"))
