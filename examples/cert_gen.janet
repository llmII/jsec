# Certificate Generation Example
# Generates a self-signed certificate and saves it to disk.

(import jsec/cert)

(print "Generating 4096-bit RSA certificate...")

(let [result (cert/generate-self-signed-cert {:common-name "myserver.local"
                                              :organization "My Company Inc."
                                              :country "US"
                                              :days-valid 365
                                              :bits 4096})]

  (print "Certificate generated successfully!")
  (print "Certificate length: " (length (result :cert)) " bytes")
  (print "Private Key length: " (length (result :key)) " bytes")

  (spit "mycert.pem" (result :cert))
  (spit "mykey.pem" (result :key))

  (print "Saved to mycert.pem and mykey.pem"))
