# RSA Encryption Examples
#
# Demonstrates RSA public-key encryption operations.
# RSA encryption is typically used for:
# - Hybrid encryption (encrypt symmetric key with RSA, bulk data with AES)
# - Key wrapping
# - Small data encryption

(import jsec/crypto :as crypto)

(defn demo-basic-rsa-encryption []
  (print "\n=== Basic RSA Encryption ===")

  # Generate RSA key pair
  (def private-key (crypto/generate-key :rsa 2048))
  (def public-key (crypto/export-public-key private-key))
  (print "Generated 2048-bit RSA key pair")

  # Encrypt with public key
  (def plaintext "Secret message!")
  (def ciphertext (crypto/rsa-encrypt public-key plaintext))
  (printf "Plaintext: %s (%d bytes)" plaintext (length plaintext))
  (printf "Ciphertext: %d bytes" (length ciphertext))

  # Decrypt with private key
  (def decrypted (crypto/rsa-decrypt private-key ciphertext))
  (printf "Decrypted: %s" decrypted)
  (printf "Round-trip successful: %v" (= plaintext decrypted)))

(defn demo-padding-modes []
  (print "\n=== RSA Padding Modes ===")

  (def private-key (crypto/generate-key :rsa 2048))
  (def public-key (crypto/export-public-key private-key))
  (def message "Test padding modes")

  # OAEP-SHA256 (recommended, default)
  (def ct-oaep256 (crypto/rsa-encrypt public-key message {:padding :oaep-sha256}))
  (def pt-oaep256 (crypto/rsa-decrypt private-key ct-oaep256 {:padding :oaep-sha256}))
  (printf "OAEP-SHA256: %d bytes ciphertext, decrypts correctly: %v"
          (length ct-oaep256) (= message pt-oaep256))

  # OAEP-SHA384
  (def ct-oaep384 (crypto/rsa-encrypt public-key message {:padding :oaep-sha384}))
  (def pt-oaep384 (crypto/rsa-decrypt private-key ct-oaep384 {:padding :oaep-sha384}))
  (printf "OAEP-SHA384: %d bytes ciphertext, decrypts correctly: %v"
          (length ct-oaep384) (= message pt-oaep384))

  # OAEP-SHA512
  (def ct-oaep512 (crypto/rsa-encrypt public-key message {:padding :oaep-sha512}))
  (def pt-oaep512 (crypto/rsa-decrypt private-key ct-oaep512 {:padding :oaep-sha512}))
  (printf "OAEP-SHA512: %d bytes ciphertext, decrypts correctly: %v"
          (length ct-oaep512) (= message pt-oaep512))

  (print "\nNote: PKCS#1 v1.5 padding (:pkcs1) is legacy and NOT recommended"))

(defn demo-max-plaintext-size []
  (print "\n=== RSA Maximum Plaintext Size ===")

  # RSA can only encrypt limited data based on key size and padding
  (def key-2048 (crypto/generate-key :rsa 2048))
  (def key-4096 (crypto/generate-key :rsa 4096))

  (printf "2048-bit RSA with OAEP-SHA256: max %d bytes"
          (crypto/rsa-max-plaintext key-2048 {:padding :oaep-sha256}))
  (printf "2048-bit RSA with OAEP-SHA512: max %d bytes"
          (crypto/rsa-max-plaintext key-2048 {:padding :oaep-sha512}))
  (printf "4096-bit RSA with OAEP-SHA256: max %d bytes"
          (crypto/rsa-max-plaintext key-4096 {:padding :oaep-sha256}))

  (print "\nFor larger data, use hybrid encryption (see below)"))

(defn demo-hybrid-encryption []
  (print "\n=== Hybrid Encryption (RSA + AES) ===")

  # Best practice: encrypt data with AES, encrypt AES key with RSA
  (def rsa-private (crypto/generate-key :rsa 2048))
  (def rsa-public (crypto/export-public-key rsa-private))

  # Sender side:
  (def plaintext "This is a much longer message that wouldn't fit in RSA directly. We use AES-256-GCM for the bulk encryption and RSA to protect the AES key. This is how TLS, PGP, and most real-world cryptographic systems work.")

  # 1. Generate random AES key and nonce
  (def aes-key (crypto/random-bytes 32)) # 256-bit key
  (def nonce (crypto/generate-nonce :aes-256-gcm))

  # 2. Encrypt data with AES
  (def aes-result (crypto/encrypt :aes-256-gcm aes-key nonce plaintext))

  # 3. Encrypt AES key with RSA
  (def encrypted-key (crypto/rsa-encrypt rsa-public aes-key))

  (printf "Original: %d bytes" (length plaintext))
  (printf "Encrypted key: %d bytes" (length encrypted-key))
  (printf "Encrypted data: %d bytes" (length (aes-result :ciphertext)))
  (printf "Auth tag: %d bytes" (length (aes-result :tag)))

  # Receiver side:
  # 1. Decrypt AES key with RSA
  (def decrypted-key (crypto/rsa-decrypt rsa-private encrypted-key))

  # 2. Decrypt data with AES
  (def decrypted (crypto/decrypt :aes-256-gcm decrypted-key nonce
                                 (aes-result :ciphertext) (aes-result :tag)))

  (printf "Decrypted: %s" decrypted)
  (printf "Hybrid encryption successful: %v" (= plaintext decrypted)))

(defn main [&]
  (print "=== RSA Encryption Demo ===")

  (demo-basic-rsa-encryption)
  (demo-padding-modes)
  (demo-max-plaintext-size)
  (demo-hybrid-encryption)

  (print "\n=== Demo Complete ==="))
