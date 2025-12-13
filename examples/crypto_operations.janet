# Crypto Operations Examples
#
# Demonstrates the cryptographic operations available in jsec/crypto:
# - CSR generation and parsing
# - HKDF key derivation
# - PBKDF2 password-based key derivation
# - Base64/Base64URL encoding
# - CMS/PKCS#7 operations (for SCEP)

(import jsec/crypto :as crypto)
(import jsec/cert)

(defn demo-csr []
  (print "\n=== Certificate Signing Request (CSR) ===")

  # Generate a key for the CSR
  (def key (crypto/generate-key :ec-p256))
  (print "Generated EC P-256 key")

  # Generate a CSR with various fields
  (def csr (crypto/generate-csr key
                                {:common-name "example.com"
                                 :country "US"
                                 :state "California"
                                 :locality "San Francisco"
                                 :organization "Example Corp"
                                 :organizational-unit "Engineering"
                                 :email "admin@example.com"
                                 :san ["DNS:example.com" "DNS:www.example.com" "DNS:api.example.com"]}))
  (print "Generated CSR:")
  (print (string/slice csr 0 (min 200 (length csr))) "...")

  # Parse the CSR
  (def parsed (crypto/parse-csr csr))
  (print "\nParsed CSR:")
  (printf "  Key type: %v" (parsed :key-type))
  (printf "  Key bits: %v" (parsed :key-bits))
  (printf "  Signature valid: %v" (parsed :signature-valid))
  (printf "  Subject: %v" (parsed :subject)))

(defn demo-hkdf []
  (print "\n=== HKDF Key Derivation ===")

  # HKDF is used in TLS 1.3 and many modern protocols
  (def ikm "shared-secret-from-key-exchange") # Input keying material
  (def salt "optional-salt-value")
  (def info "application-specific-context")

  # Derive multiple keys from the same secret
  (def key1 (crypto/hkdf :sha256 ikm salt "encryption-key" 32))
  (def key2 (crypto/hkdf :sha256 ikm salt "authentication-key" 32))

  (printf "Encryption key (hex): %s"
          (string/join (map |(string/format "%02x" $) key1) ""))
  (printf "Auth key (hex): %s"
          (string/join (map |(string/format "%02x" $) key2) ""))
  (print "Keys are different despite same IKM (different info strings)"))

(defn demo-pbkdf2 []
  (print "\n=== PBKDF2 Password Hashing ===")

  # PBKDF2 for password-based encryption
  (def password "my-secure-password")
  (def salt (crypto/random-bytes 16))
  (def iterations 100000) # OWASP recommends 600k for SHA-256

  (def derived-key (crypto/pbkdf2 :sha256 password salt iterations 32))

  (printf "Password: %s" password)
  (printf "Salt (hex): %s" (string/join (map |(string/format "%02x" $) salt) ""))
  (printf "Iterations: %d" iterations)
  (printf "Derived key (hex): %s"
          (string/join (map |(string/format "%02x" $) derived-key) ""))

  # Verify: same inputs produce same output
  (def verify-key (crypto/pbkdf2 :sha256 password salt iterations 32))
  (printf "Verification matches: %v" (= derived-key verify-key)))

(defn demo-base64 []
  (print "\n=== Base64 Encoding ===")

  # Standard Base64
  (def data "Hello, World!")
  (def encoded (crypto/base64-encode data))
  (def decoded (crypto/base64-decode encoded))

  (printf "Original: %s" data)
  (printf "Base64: %s" encoded)
  (printf "Decoded: %s" decoded)

  # Base64URL (for JWTs and URLs)
  (print "\nBase64URL (URL-safe, no padding):")
  (def binary-data (crypto/random-bytes 24))
  (def url-encoded (crypto/base64url-encode binary-data))
  (def url-decoded (crypto/base64url-decode url-encoded))

  (printf "URL-safe encoding: %s" url-encoded)
  (printf "No '+', '/', or '=' characters: %v"
          (and (not (string/find "+" url-encoded))
               (not (string/find "/" url-encoded))
               (not (string/find "=" url-encoded))))
  (printf "Round-trip matches: %v" (= binary-data url-decoded)))

(defn demo-cms []
  (print "\n=== CMS/PKCS#7 Operations ===")

  # Generate test credentials
  (def key (crypto/generate-key :rsa 2048))
  (def cert-data (cert/generate-self-signed-cert {:common-name "CMS Test"}))
  (def cert (cert-data :cert))

  # Sign data
  (def message "Important signed message")
  (def signed (crypto/cms-sign cert (cert-data :key) message))
  (printf "Signed data: %d bytes" (length signed))

  # Verify signature
  (def result (crypto/cms-verify signed))
  (printf "Signature valid: %v" (result :valid))
  (printf "Content recovered: %s" (result :content))

  # Encrypt data
  (def secret "Confidential data")
  (def encrypted (crypto/cms-encrypt secret cert))
  (printf "\nEncrypted data: %d bytes" (length encrypted))

  # Decrypt data
  (def decrypted (crypto/cms-decrypt encrypted cert (cert-data :key)))
  (printf "Decrypted: %s" decrypted)
  (printf "Round-trip matches: %v" (= secret decrypted))

  # Certificate-only container (used in SCEP)
  (def certs-only (crypto/cms-certs-only cert))
  (def extracted (crypto/cms-get-certs certs-only))
  (printf "\nExtracted %d certificate(s) from certs-only container" (length extracted)))

(defn demo-challenge []
  (print "\n=== Challenge Generation ===")

  # Generate random challenges (for SCEP, CSRF tokens, etc.)
  (def challenge (crypto/generate-challenge))
  (printf "Default challenge (32 bytes, hex): %s" challenge)
  (printf "Length: %d characters" (length challenge))

  (def short-challenge (crypto/generate-challenge 16))
  (printf "Short challenge (16 bytes, hex): %s" short-challenge))

(defn main [&]
  (print "=== jsec/crypto Operations Demo ===")

  (demo-csr)
  (demo-hkdf)
  (demo-pbkdf2)
  (demo-base64)
  (demo-cms)
  (demo-challenge)

  (print "\n=== Demo Complete ==="))
