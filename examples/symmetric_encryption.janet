# Symmetric Encryption Example
#
# This example demonstrates how to use AEAD encryption (AES-GCM and ChaCha20-Poly1305)
# for encrypting and decrypting data.
#
# IMPORTANT SECURITY NOTES:
# - NEVER reuse a nonce with the same key
# - Always store the authentication tag alongside the ciphertext
# - Use AEAD ciphers (GCM, ChaCha20-Poly1305) for authenticated encryption
# - CBC mode does NOT provide authentication - use with HMAC if needed

(import jsec/crypto)

(print "=== Symmetric Encryption Examples ===\n")

# ==============================================================================
# AES-256-GCM Encryption (Recommended)
# ==============================================================================

(print "--- AES-256-GCM ---")

# Get cipher information
(def info (crypto/cipher-info :aes-256-gcm))
(printf "Key length: %d bytes" (info :key-length))
(printf "Nonce length: %d bytes" (info :nonce-length))
(printf "Tag length: %d bytes" (info :tag-length))
(printf "AEAD: %s\n" (if (info :aead) "yes" "no"))

# Generate a random key and nonce
(def key (crypto/random-bytes 32)) # 256 bits
(def nonce (crypto/generate-nonce :aes-256-gcm))

# Encrypt some data
(def plaintext "This is secret data that needs to be encrypted!")
(def result (crypto/encrypt :aes-256-gcm key nonce plaintext))

(printf "Original: %s" plaintext)
(printf "Ciphertext length: %d bytes" (length (result :ciphertext)))
(printf "Authentication tag: %d bytes" (length (result :tag)))

# Decrypt the data
(def decrypted (crypto/decrypt :aes-256-gcm key nonce
                               (result :ciphertext) (result :tag)))
(printf "Decrypted: %s\n" decrypted)

# ==============================================================================
# Encryption with Additional Authenticated Data (AAD)
# ==============================================================================

(print "--- With Additional Authenticated Data (AAD) ---")

# AAD is authenticated but not encrypted - useful for headers/metadata
(def new-nonce (crypto/generate-nonce :aes-256-gcm))
(def aad "public-header-data-that-must-be-authentic")
(def secret "This is the secret payload")

(def result2 (crypto/encrypt :aes-256-gcm key new-nonce secret aad))
(printf "AAD: %s" aad)
(printf "Secret: %s" secret)

# AAD must match exactly during decryption
(def decrypted2 (crypto/decrypt :aes-256-gcm key new-nonce
                                (result2 :ciphertext) (result2 :tag) aad))
(printf "Decrypted: %s\n" decrypted2)

# ==============================================================================
# ChaCha20-Poly1305 (Alternative AEAD)
# ==============================================================================

(print "--- ChaCha20-Poly1305 ---")

# ChaCha20-Poly1305 is often faster on CPUs without AES hardware acceleration
(def chacha-info (crypto/cipher-info :chacha20-poly1305))
(printf "Key length: %d bytes" (chacha-info :key-length))

(def chacha-key (crypto/random-bytes 32))
(def chacha-nonce (crypto/generate-nonce :chacha20-poly1305))

(def chacha-result (crypto/encrypt :chacha20-poly1305 chacha-key chacha-nonce plaintext))
(def chacha-decrypted (crypto/decrypt :chacha20-poly1305 chacha-key chacha-nonce
                                      (chacha-result :ciphertext) (chacha-result :tag)))
(printf "ChaCha20-Poly1305 decrypted: %s\n" chacha-decrypted)

# ==============================================================================
# AES-CBC (Non-AEAD - use with caution)
# ==============================================================================

(print "--- AES-256-CBC (Non-AEAD) ---")

# CBC mode does NOT provide authentication
# If you need to detect tampering, use HMAC separately or prefer AEAD ciphers

(def cbc-info (crypto/cipher-info :aes-256-cbc))
(printf "IV length: %d bytes" (cbc-info :nonce-length))
(printf "AEAD: %s (NO authentication!)" (if (cbc-info :aead) "yes" "no"))

(def cbc-key (crypto/random-bytes 32))
(def iv (crypto/generate-nonce :aes-256-cbc)) # 16 bytes for CBC

(def cbc-result (crypto/encrypt :aes-256-cbc cbc-key iv plaintext))
(printf "Ciphertext length: %d bytes (with PKCS7 padding)" (length (cbc-result :ciphertext)))

# For CBC, tag is nil
(def cbc-decrypted (crypto/decrypt :aes-256-cbc cbc-key iv
                                   (cbc-result :ciphertext) nil))
(printf "Decrypted: %s\n" cbc-decrypted)

# ==============================================================================
# Error Handling
# ==============================================================================

(print "--- Error Handling ---")

# Wrong tag causes authentication failure (AEAD only)
(print "Testing authentication failure with wrong tag...")
(def wrong-tag (crypto/random-bytes 16))
(def [ok err] (protect (crypto/decrypt :aes-256-gcm key nonce
                                       (result :ciphertext) wrong-tag)))
(if ok
  (print "ERROR: Should have failed!")
  (printf "Correctly rejected: %s" err))

# Wrong key causes failure
(print "\nTesting wrong key...")
(def wrong-key (crypto/random-bytes 32))
(def [ok2 err2] (protect (crypto/decrypt :aes-256-gcm wrong-key nonce
                                         (result :ciphertext) (result :tag))))
(if ok2
  (print "ERROR: Should have failed!")
  (printf "Correctly rejected: %s" err2))

(print "\n=== Done ===")
