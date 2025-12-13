#!/usr/bin/env janet
#
# CA Operations Example
#
# Demonstrates the jsec/ca module for certificate authority management.
# Run with: janet examples/ca_operations.janet

(import jsec/ca)

(defn main [&]
  (print "=== jsec/ca Certificate Authority Example ===\n")

  # -----------------------------------------------------
  # 1. Generate a Root CA
  # -----------------------------------------------------
  (print "1. Generating Root CA...")
  (def root-ca (ca/generate {:common-name "Example Root CA"
                             :days-valid 3650
                             :organization "Example Org"
                             :country "US"
                             :track-issued true}))
  (print "   Root CA created")
  (print (string "   Serial starts at: " (:get-serial root-ca)))
  (print (string "   Tracking enabled: " (:is-tracking root-ca)))
  (print)

  # -----------------------------------------------------
  # 2. Generate an Intermediate CA
  # -----------------------------------------------------
  (print "2. Generating Intermediate CA...")
  (def intermediate (ca/generate-intermediate root-ca
                                              {:common-name "Example Intermediate CA"
                                               :path-length 0
                                               :days-valid 1825}))
  (print "   Intermediate CA created")
  (print (string "   Root serial now: " (:get-serial root-ca)))
  (print)

  # -----------------------------------------------------
  # 3. Issue Server Certificate (simple method)
  # -----------------------------------------------------
  (print "3. Issuing server certificate...")
  (def server (:issue intermediate
                      {:common-name "server.example.com"
                       :san ["DNS:server.example.com"
                             "DNS:localhost"
                             "IP:127.0.0.1"]
                       :extended-key-usage "serverAuth"
                       :days-valid 365}))
  (print "   Server certificate issued")
  (print (string "   Intermediate serial now: " (:get-serial intermediate)))
  (print)

  # -----------------------------------------------------
  # 4. Issue Client Certificate
  # -----------------------------------------------------
  (print "4. Issuing client certificate...")
  (def client (:issue intermediate
                      {:common-name "client@example.com"
                       :extended-key-usage "clientAuth"
                       :days-valid 365}))
  (print "   Client certificate issued")
  (print)

  # -----------------------------------------------------
  # 5. Check Issued Certificates (tracking demo)
  # -----------------------------------------------------
  (print "5. Checking tracked certificates...")
  (def issued (:get-issued root-ca))
  (print (string "   Root CA has issued " (length issued) " certificate(s)"))
  # Note: intermediate CA was issued by root
  (print)

  # -----------------------------------------------------
  # 6. Revoke a Certificate
  # -----------------------------------------------------
  (print "6. Revoking client certificate...")
  # Get the serial of the client cert (it's the most recent from intermediate)
  (def client-serial (- (:get-serial intermediate) 1))
  (:revoke intermediate client-serial :key-compromise)
  (print (string "   Revoked serial " client-serial " for key-compromise"))
  (print)

  # -----------------------------------------------------
  # 7. Generate CRL
  # -----------------------------------------------------
  (print "7. Generating Certificate Revocation List...")
  (def crl (:generate-crl intermediate {:days-valid 7}))
  (print "   CRL generated (showing first 200 chars):")
  (print (string "   " (string/slice crl 0 (min 200 (length crl))) "..."))
  (print)

  # -----------------------------------------------------
  # 8. Check Revoked List
  # -----------------------------------------------------
  (print "8. Checking revocation list...")
  (def revoked (:get-revoked intermediate))
  (each entry revoked
    (print (string "   Serial " (entry :serial) " - " (entry :reason))))
  (print)

  # -----------------------------------------------------
  # 9. Serial Persistence Demo
  # -----------------------------------------------------
  (print "9. Serial persistence demonstration...")
  (def current-serial (:get-serial intermediate))
  (print (string "   Current serial: " current-serial))

  # Simulate saving and restoring
  (def saved-serial (string current-serial))
  (def restored-serial (scan-number saved-serial))
  (print (string "   Saved serial: " saved-serial))
  (print (string "   Restored serial: " restored-serial))

  # In real use, you would:
  # 1. Save cert, key, and serial to files
  # 2. Load them back with ca/create
  # Example (commented - requires file I/O):
  #   (spit "ca.crt" (:get-cert intermediate))
  #   (spit "ca.key" key-pem)  ; Need to save key when generating
  #   (spit "ca.serial" (string (:get-serial intermediate)))
  #   ...later...
  #   (def ca (ca/create (slurp "ca.crt") (slurp "ca.key")
  #                      {:serial (scan-number (slurp "ca.serial"))}))
  (print "   (Serial persistence pattern demonstrated)")
  (print)

  # -----------------------------------------------------
  # 10. Print Certificates
  # -----------------------------------------------------
  (print "10. Certificate summary:")
  (print "    Root CA cert (first 200 chars):")
  (print (string "    " (string/slice (:get-cert root-ca) 0 200) "..."))
  (print)
  (print "    Server cert available at: (server :cert)")
  (print "    Server key available at: (server :key)")
  (print)

  # -----------------------------------------------------
  # 11. Build Certificate Chain
  # -----------------------------------------------------
  (print "11. Building certificate chain for server...")
  (def chain (string (server :cert)
                     (:get-cert intermediate)))
  (print (string "    Chain length: " (length chain) " bytes"))
  (print "    Chain contains: server cert + intermediate cert")
  (print "    (Root CA typically distributed separately as trust anchor)")
  (print)

  (print "=== CA Example Complete ==="))
