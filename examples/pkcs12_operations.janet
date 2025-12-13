# PKCS#12 Operations Examples
#
# Demonstrates PKCS#12 (PFX) bundle creation and parsing.
# PKCS#12 is commonly used to distribute certificates and private keys
# together in a single encrypted file (often with .p12 or .pfx extension).

(import jsec/crypto :as crypto)
(import jsec/cert)

(defn demo-basic-pkcs12 []
  (print "\n=== Basic PKCS#12 Bundle ===")

  # Generate a key and self-signed certificate
  (def key (crypto/generate-key :rsa 2048))
  (def cert-data (cert/generate-self-signed-cert
                   {:common-name "Test Certificate"
                    :key key}))
  (print "Generated key and certificate")

  # Create a PKCS#12 bundle
  (def pfx (crypto/create-pkcs12
             (cert-data :cert)
             (cert-data :key)
             {:password "secret123"
              :friendly-name "My Test Certificate"}))
  (printf "Created PKCS#12 bundle: %d bytes" (length pfx))

  # Parse the bundle back
  (def parsed (crypto/parse-pkcs12 pfx "secret123"))
  (printf "Parsed bundle:")
  (printf "  Has certificate: %v" (not (nil? (parsed :cert))))
  (printf "  Has private key: %v" (not (nil? (parsed :key))))
  (printf "  Friendly name: %v" (parsed :friendly-name))
  (printf "  CA chain length: %d" (length (or (parsed :chain) []))))

(defn demo-pkcs12-with-chain []
  (print "\n=== PKCS#12 with Certificate Chain ===")

  # Create a simple CA
  (def ca-key (crypto/generate-key :rsa 2048))
  (def ca-cert-data (cert/generate-self-signed-cert
                      {:common-name "Test CA"
                       :key ca-key
                       :is-ca true
                       :valid-days 3650}))
  (print "Created CA certificate")

  # Create an end-entity certificate signed by the CA
  (def ee-key (crypto/generate-key :ec-p256))
  (def ee-cert-data (cert/generate-signed-cert
                      {:common-name "End Entity"
                       :key ee-key
                       :issuer-cert (ca-cert-data :cert)
                       :issuer-key ca-key}))
  (print "Created end-entity certificate signed by CA")

  # Bundle with chain
  (def pfx (crypto/create-pkcs12
             (ee-cert-data :cert)
             ee-key
             {:password "bundlepass"
              :chain [(ca-cert-data :cert)]
              :friendly-name "Server Certificate"}))
  (printf "Created PKCS#12 with chain: %d bytes" (length pfx))

  # Parse and verify chain
  (def parsed (crypto/parse-pkcs12 pfx "bundlepass"))
  (printf "Chain certificates: %d" (length (or (parsed :chain) []))))

(defn demo-save-load-pfx []
  (print "\n=== Save/Load PKCS#12 File ===")

  # Generate credentials
  (def key (crypto/generate-key :ec-p384))
  (def cert-data (cert/generate-self-signed-cert
                   {:common-name "file-test.example.com"
                    :key key}))

  # Create and save bundle
  (def pfx (crypto/create-pkcs12
             (cert-data :cert)
             (cert-data :key)
             {:password "filepass"}))

  # In real usage, you would write to a file:
  # (spit "certificate.p12" pfx)
  # (def loaded (slurp "certificate.p12"))
  # (def parsed (crypto/parse-pkcs12 loaded "filepass"))

  (print "PKCS#12 can be saved with (spit \"file.p12\" pfx)")
  (print "And loaded with (crypto/parse-pkcs12 (slurp \"file.p12\") password)"))

(defn main [&]
  (print "=== PKCS#12 Operations Demo ===")

  (demo-basic-pkcs12)
  (demo-pkcs12-with-chain)
  (demo-save-load-pfx)

  (print "\n=== Demo Complete ==="))
