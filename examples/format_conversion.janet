# Key and Certificate Format Conversion Examples
#
# Demonstrates converting keys and certificates between formats:
# - PEM (text, base64 encoded)
# - DER (binary)
# - PKCS#8 (standardized private key format)

(import jsec/crypto :as crypto)
(import jsec/cert)

(defn demo-key-conversion []
  (print "\n=== Key Format Conversion ===")

  # Generate a key (default output is PEM)
  (def key-pem (crypto/generate-key :ec-p256))
  (print "Generated EC P-256 key in PEM format")
  (printf "PEM starts with: %s..." (string/slice key-pem 0 40))

  # Convert to DER (binary)
  (def key-der (crypto/convert-key key-pem :der))
  (printf "DER format: %d bytes (binary)" (length key-der))

  # Convert back to PEM
  (def key-pem2 (crypto/convert-key key-der :pem))
  (printf "Back to PEM: matches original: %v" (= key-pem key-pem2))

  # Convert to PKCS#8 (standardized format)
  (def key-pkcs8 (crypto/convert-key key-pem :pkcs8))
  (print "\nPKCS#8 format (standardized container):")
  (printf "Starts with: %s..." (string/slice key-pkcs8 0 40))

  # PKCS#8 with password protection
  (def key-pkcs8-enc (crypto/convert-key key-pem :pkcs8 {:password "protect-me"}))
  (print "\nPassword-protected PKCS#8:")
  (printf "Contains ENCRYPTED: %v" (not (nil? (string/find "ENCRYPTED" key-pkcs8-enc)))))

(defn demo-cert-conversion []
  (print "\n=== Certificate Format Conversion ===")

  # Generate a self-signed certificate
  (def key (crypto/generate-key :rsa 2048))
  (def cert-data (cert/generate-self-signed-cert {:common-name "Test" :key key}))
  (def cert-pem (cert-data :cert))
  (print "Generated certificate in PEM format")

  # Convert to DER
  (def cert-der (crypto/convert-cert cert-pem :der))
  (printf "PEM: %d bytes (text)" (length cert-pem))
  (printf "DER: %d bytes (binary)" (length cert-der))

  # Convert back to PEM
  (def cert-pem2 (crypto/convert-cert cert-der :pem))
  (printf "Round-trip matches: %v" (= cert-pem cert-pem2)))

(defn demo-format-detection []
  (print "\n=== Automatic Format Detection ===")

  (def key (crypto/generate-key :rsa 2048))
  (def key-der (crypto/convert-key key :der))

  (printf "Original key format: %v" (crypto/detect-format key))
  (printf "DER key format: %v" (crypto/detect-format key-der)))

(defn demo-password-protected-keys []
  (print "\n=== Password-Protected Keys ===")

  # Generate a key
  (def key (crypto/generate-key :rsa 2048))

  # Export with password protection
  (def key-encrypted (crypto/export-key key {:password "secret" :cipher :aes-256-cbc}))
  (print "Encrypted key with AES-256-CBC:")
  (printf "Contains ENCRYPTED: %v" (not (nil? (string/find "ENCRYPTED" key-encrypted))))

  # Load the encrypted key (requires password)
  (def key-loaded (crypto/load-key key-encrypted "secret"))
  (printf "Loaded encrypted key successfully: %v" (= key key-loaded))

  # Get key info without decrypting
  (def info (crypto/key-info key-encrypted))
  (printf "Key info (without password):")
  (printf "  Type: %v" (info :type))
  (printf "  Bits: %v" (info :bits))
  (printf "  Encrypted: %v" (info :encrypted)))

(defn demo-interop []
  (print "\n=== Interoperability Notes ===")

  (print "PEM format:")
  (print "  - Human readable, base64 with header/footer")
  (print "  - Used by: OpenSSL, most tools, config files")
  (print "  - Can contain multiple items (cert chain)")

  (print "\nDER format:")
  (print "  - Binary, compact")
  (print "  - Used by: Windows, Java keystores, PKCS#12")
  (print "  - Exactly one item per file")

  (print "\nPKCS#8 format:")
  (print "  - Standardized private key container")
  (print "  - Required by some APIs (Java, PKCS#11)")
  (print "  - Supports password protection"))

(defn main [&]
  (print "=== Key/Certificate Conversion Demo ===")

  (demo-key-conversion)
  (demo-cert-conversion)
  (demo-format-detection)
  (demo-password-protected-keys)
  (demo-interop)

  (print "\n=== Demo Complete ==="))
