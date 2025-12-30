# Crypto Test Suite (janet-assay version)
#
# Tests for jsec's cryptographic functions.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import jsec/utils :as utils)
(import ../helpers :prefix "")

(def-suite :name "Crypto Suite"

  (def-test "SHA256 Digest"
    (let [d (crypto/digest :sha256 "hello")]
      (assert (= 32 (length d)) "Digest length is 32")))

  (def-test "Ed25519 Sign/Verify"
    (let [key (crypto/generate-key :ed25519)
          data "important message"
          sig (crypto/sign key data)]
      (assert (crypto/verify key data sig) "Verification succeeds")
      (assert (not (crypto/verify key "wrong data" sig)) "Verification fails on wrong data")))

  (def-test "EC P-256 key generation"
    (let [key (crypto/generate-key :ec-p256)]
      (assert (string/find "BEGIN PRIVATE KEY" key) "EC P-256 key is PEM")))

  (def-test "EC P-384 key generation"
    (let [key (crypto/generate-key :ec-p384)]
      (assert (string/find "BEGIN PRIVATE KEY" key) "EC P-384 key is PEM")))

  (def-test "EC P-256 sign/verify"
    (let [key (crypto/generate-key :p256)
          data "test data"
          sig (crypto/sign key data)]
      (assert (crypto/verify key data sig) "EC verification succeeds")))

  (def-test "RSA 4096-bit key generation"
    (let [key (crypto/generate-key :rsa 4096)]
      (assert (string/find "BEGIN PRIVATE KEY" key) "RSA 4096 key is PEM")))

  (def-test "HMAC-SHA256"
    (let [mac (crypto/hmac :sha256 "secret-key" "data to authenticate")]
      (assert (= 32 (length mac)) "HMAC-SHA256 is 32 bytes")))

  (def-test "HMAC-SHA512"
    (let [mac (crypto/hmac :sha512 "secret-key" "data")]
      (assert (= 64 (length mac)) "HMAC-SHA512 is 64 bytes")))

  (def-test "Random bytes generation"
    (let [r1 (crypto/random-bytes 32)
          r2 (crypto/random-bytes 32)]
      (assert (= 32 (length r1)) "Random bytes correct length")
      (assert (not= r1 r2) "Random bytes are different")))

  (def-test "Base64 encode/decode"
    (let [data "Hello, World!"
          encoded (crypto/base64-encode data)
          decoded (crypto/base64-decode encoded)]
      (assert (= "SGVsbG8sIFdvcmxkIQ==" encoded) "Base64 encoding correct")
      (assert (= data decoded) "Base64 round-trip")))

  (def-test "Base64url encode/decode"
    (let [data "\xff\xfe\xfd"
          encoded (crypto/base64url-encode data)
          decoded (crypto/base64url-decode encoded)]
      (assert (not (string/find "+" encoded)) "No + in base64url")
      (assert (not (string/find "/" encoded)) "No / in base64url")
      (assert (not (string/find "=" encoded)) "No padding in base64url")
      (assert (= data decoded) "Base64url round-trip")))

  (def-test "Export public key"
    (let [privkey (crypto/generate-key :ec-p256)
          pubkey (crypto/export-public-key privkey)]
      (assert (string/find "BEGIN PUBLIC KEY" pubkey) "Public key is PEM")
      (let [sig (crypto/sign privkey "test")]
        (assert (crypto/verify pubkey "test" sig) "Public key verifies"))))

  (def-test "HKDF derivation"
    (let [ikm "input keying material"
          salt "salt value"
          info "context info"
          derived (crypto/hkdf :sha256 ikm salt info 32)]
      (assert (= 32 (length derived)) "HKDF output correct length")
      (let [derived2 (crypto/hkdf :sha256 ikm salt info 32)]
        (assert (= derived derived2) "HKDF is deterministic"))))

  (def-test "PBKDF2 derivation"
    (let [password "my-password"
          salt "random-salt"
          derived (crypto/pbkdf2 :sha256 password salt 10000 32)]
      (assert (= 32 (length derived)) "PBKDF2 output correct length")
      (let [derived2 (crypto/pbkdf2 :sha256 password salt 10000 32)]
        (assert (= derived derived2) "PBKDF2 is deterministic"))
      (let [derived3 (crypto/pbkdf2 :sha256 password salt 5000 32)]
        (assert (not= derived derived3) "Different iterations = different output"))))

  (def-test "CSR generation with RSA"
    (let [key (crypto/generate-key :rsa 2048)
          csr (crypto/generate-csr key
                                   {:common-name "example.com"
                                    :country "US"
                                    :organization "Test Org"
                                    :san ["DNS:example.com" "DNS:www.example.com"]})]
      (assert (string/find "BEGIN CERTIFICATE REQUEST" csr) "CSR is PEM")))

  (def-test "CSR generation with EC key"
    (let [key (crypto/generate-key :ec-p256)
          csr (crypto/generate-csr key {:common-name "test.local"})]
      (assert (string/find "BEGIN CERTIFICATE REQUEST" csr) "EC CSR is PEM")))

  (def-test "Various digest algorithms"
    (let [data "test data"]
      (assert (= 16 (length (crypto/digest :md5 data))) "MD5 is 16 bytes")
      (assert (= 20 (length (crypto/digest :sha1 data))) "SHA1 is 20 bytes")
      (assert (= 28 (length (crypto/digest :sha224 data))) "SHA224 is 28 bytes")
      (assert (= 32 (length (crypto/digest :sha256 data))) "SHA256 is 32 bytes")
      (assert (= 48 (length (crypto/digest :sha384 data))) "SHA384 is 48 bytes")
      (assert (= 64 (length (crypto/digest :sha512 data))) "SHA512 is 64 bytes")))

  (def-test "Error on invalid key type"
    (assert-error (crypto/generate-key :invalid-type)))

  (def-test "Error on invalid digest algorithm"
    (assert-error (crypto/digest :invalid "data")))

  (def-test "RSA key bits boundary"
    # LibreSSL allows 256-bit RSA keys, OpenSSL 3.0+ rejects them
    (when (= :openssl (utils/ssl-backend))
      (assert-error (crypto/generate-key :rsa 256)))
    (assert-no-error (crypto/generate-key :rsa 1024)))

  (def-test "X25519 key exchange"
    (let [alice-priv (crypto/generate-key :x25519)
          alice-pub (crypto/export-public-key alice-priv)
          bob-priv (crypto/generate-key :x25519)
          bob-pub (crypto/export-public-key bob-priv)
          alice-shared (crypto/ecdh-derive alice-priv bob-pub)
          bob-shared (crypto/ecdh-derive bob-priv alice-pub)]
      (assert (= 32 (length alice-shared)) "X25519 shared secret is 32 bytes")
      (assert (= alice-shared bob-shared) "Both parties derive same secret")))

  (def-test "EC P-256 key exchange"
    (let [alice-priv (crypto/generate-key :ec-p256)
          alice-pub (crypto/export-public-key alice-priv)
          bob-priv (crypto/generate-key :ec-p256)
          bob-pub (crypto/export-public-key bob-priv)
          alice-shared (crypto/ecdh-derive alice-priv bob-pub)
          bob-shared (crypto/ecdh-derive bob-priv alice-pub)]
      (assert (= 32 (length alice-shared)) "P-256 shared secret is 32 bytes")
      (assert (= alice-shared bob-shared) "Both parties derive same secret")))

  # ===========================================================================
  # Symmetric Encryption Tests
  # ===========================================================================

  (def-test "cipher-info returns correct metadata"
    (let [info (crypto/cipher-info :aes-256-gcm)]
      (assert (= 32 (info :key-length)) "AES-256 key is 32 bytes")
      (assert (= 12 (info :nonce-length)) "GCM nonce is 12 bytes")
      (assert (= 16 (info :tag-length)) "GCM tag is 16 bytes")
      (assert (info :aead) "AES-GCM is AEAD")))

  (def-test "cipher-info for ChaCha20-Poly1305"
    (let [info (crypto/cipher-info :chacha20-poly1305)]
      (assert (= 32 (info :key-length)) "ChaCha20 key is 32 bytes")
      (assert (= 12 (info :nonce-length)) "ChaCha20 nonce is 12 bytes")
      (assert (info :aead) "ChaCha20-Poly1305 is AEAD")))

  (def-test "cipher-info for AES-CBC"
    (let [info (crypto/cipher-info :aes-256-cbc)]
      (assert (= 32 (info :key-length)) "AES-256-CBC key is 32 bytes")
      (assert (= 16 (info :nonce-length)) "CBC IV is 16 bytes")
      (assert (not (info :aead)) "AES-CBC is NOT AEAD")))

  (def-test "generate-nonce creates correct length"
    (let [nonce-gcm (crypto/generate-nonce :aes-256-gcm)
          nonce-cbc (crypto/generate-nonce :aes-256-cbc)]
      (assert (= 12 (length nonce-gcm)) "GCM nonce is 12 bytes")
      (assert (= 16 (length nonce-cbc)) "CBC IV is 16 bytes")))

  (def-test "AES-256-GCM encrypt/decrypt roundtrip"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          plaintext "Hello, World! Testing AES-256-GCM encryption."
          result (crypto/encrypt :aes-256-gcm key nonce plaintext)
          decrypted (crypto/decrypt :aes-256-gcm key nonce
                                    (result :ciphertext) (result :tag))]
      (assert (result :ciphertext) "Ciphertext exists")
      (assert (result :tag) "Tag exists")
      (assert (= 16 (length (result :tag))) "Tag is 16 bytes")
      (assert (= plaintext (string decrypted)) "Decryption matches original")))

  (def-test "AES-128-GCM encrypt/decrypt roundtrip"
    (let [key (crypto/random-bytes 16)
          nonce (crypto/generate-nonce :aes-128-gcm)
          plaintext "Test AES-128-GCM"
          result (crypto/encrypt :aes-128-gcm key nonce plaintext)
          decrypted (crypto/decrypt :aes-128-gcm key nonce
                                    (result :ciphertext) (result :tag))]
      (assert (= plaintext (string decrypted)) "AES-128-GCM roundtrip")))

  (def-test "ChaCha20-Poly1305 encrypt/decrypt roundtrip"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :chacha20-poly1305)
          plaintext "Testing ChaCha20-Poly1305 authenticated encryption"
          result (crypto/encrypt :chacha20-poly1305 key nonce plaintext)
          decrypted (crypto/decrypt :chacha20-poly1305 key nonce
                                    (result :ciphertext) (result :tag))]
      (assert (= plaintext (string decrypted)) "ChaCha20-Poly1305 roundtrip")))

  (def-test "AES-256-CBC encrypt/decrypt roundtrip"
    (let [key (crypto/random-bytes 32)
          iv (crypto/generate-nonce :aes-256-cbc)
          plaintext "Testing AES-256-CBC mode (non-AEAD)"
          result (crypto/encrypt :aes-256-cbc key iv plaintext)
          decrypted (crypto/decrypt :aes-256-cbc key iv
                                    (result :ciphertext) nil)]
      (assert (nil? (result :tag)) "CBC has no tag")
      (assert (= plaintext (string decrypted)) "AES-256-CBC roundtrip")))

  (def-test "AEAD encryption with AAD"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          plaintext "Secret payload"
          aad "Authenticated header data"
          result (crypto/encrypt :aes-256-gcm key nonce plaintext aad)
          decrypted (crypto/decrypt :aes-256-gcm key nonce
                                    (result :ciphertext) (result :tag) aad)]
      (assert (= plaintext (string decrypted)) "Decryption with AAD works")))

  (def-test "AEAD fails with wrong tag"
    :expected-fail "authentication tag mismatch"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          plaintext "Secret data"
          result (crypto/encrypt :aes-256-gcm key nonce plaintext)
          wrong-tag (crypto/random-bytes 16)]
      (crypto/decrypt :aes-256-gcm key nonce (result :ciphertext) wrong-tag)))

  (def-test "AEAD fails with wrong key"
    :expected-fail "authentication tag mismatch"
    (let [key (crypto/random-bytes 32)
          wrong-key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          plaintext "Secret data"
          result (crypto/encrypt :aes-256-gcm key nonce plaintext)]
      (crypto/decrypt :aes-256-gcm wrong-key nonce (result :ciphertext) (result :tag))))

  (def-test "AEAD fails with wrong AAD"
    :expected-fail "authentication tag mismatch"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          plaintext "Secret data"
          aad "correct aad"
          result (crypto/encrypt :aes-256-gcm key nonce plaintext aad)]
      (crypto/decrypt :aes-256-gcm key nonce (result :ciphertext) (result :tag) "wrong aad")))

  (def-test "encrypt rejects wrong key length"
    :expected-fail "key must be"
    (let [bad-key (crypto/random-bytes 16) # 16 bytes, but AES-256 needs 32
          nonce (crypto/generate-nonce :aes-256-gcm)]
      (crypto/encrypt :aes-256-gcm bad-key nonce "data")))

  (def-test "encrypt rejects wrong nonce length"
    :expected-fail "nonce must be"
    (let [key (crypto/random-bytes 32)
          bad-nonce (crypto/random-bytes 8)] # 8 bytes, but GCM needs 12
      (crypto/encrypt :aes-256-gcm key bad-nonce "data")))

  (def-test "encrypt rejects invalid algorithm"
    :expected-fail "unsupported cipher"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/random-bytes 12)]
      (crypto/encrypt :invalid-cipher key nonce "data")))

  (def-test "encrypt handles empty plaintext"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          result (crypto/encrypt :aes-256-gcm key nonce "")
          decrypted (crypto/decrypt :aes-256-gcm key nonce
                                    (result :ciphertext) (result :tag))]
      (assert (= "" (string decrypted)) "Empty plaintext roundtrip")))

  (def-test "encrypt handles large plaintext"
    (let [key (crypto/random-bytes 32)
          nonce (crypto/generate-nonce :aes-256-gcm)
          # 64KB of data
          plaintext (string/repeat "x" 65536)
          result (crypto/encrypt :aes-256-gcm key nonce plaintext)
          decrypted (crypto/decrypt :aes-256-gcm key nonce
                                    (result :ciphertext) (result :tag))]
      (assert (= 65536 (length decrypted)) "Large plaintext roundtrip")))

  # ===========================================================================
  # PKCS#12 Tests
  # ===========================================================================

  (def-test "PKCS#12 create and parse basic"
    (let [cert-result (cert/generate-self-signed-cert {:common-name "PKCS12 Test"})
          pfx (crypto/create-pkcs12 (cert-result :cert) (cert-result :key)
                                    {:password "testpass"
                                     :friendly-name "Test Cert"})
          parsed (crypto/parse-pkcs12 pfx "testpass")]
      (assert (not (nil? (parsed :cert))) "Parsed cert exists")
      (assert (not (nil? (parsed :key))) "Parsed key exists")
      (assert (= "Test Cert" (parsed :friendly-name)) "Friendly name preserved")))

  (def-test "PKCS#12 wrong password fails"
    :expected-fail "failed to parse"
    (let [cert-result (cert/generate-self-signed-cert {:common-name "Test"})
          pfx (crypto/create-pkcs12 (cert-result :cert) (cert-result :key) {:password "correct"})]
      (crypto/parse-pkcs12 pfx "wrong")))

  # ===========================================================================
  # RSA Encryption Tests
  # ===========================================================================

  (def-test "RSA encrypt/decrypt basic"
    (let [privkey (crypto/generate-key :rsa 2048)
          pubkey (crypto/export-public-key privkey)
          plaintext "Hello RSA!"
          ciphertext (crypto/rsa-encrypt pubkey plaintext)
          decrypted (crypto/rsa-decrypt privkey ciphertext)]
      (assert (not= plaintext ciphertext) "Ciphertext differs from plaintext")
      (assert (= plaintext (string decrypted)) "Decryption matches")))

  (def-test "RSA encrypt with OAEP-SHA384"
    (let [privkey (crypto/generate-key :rsa 2048)
          pubkey (crypto/export-public-key privkey)
          plaintext "Test OAEP-SHA384"
          ciphertext (crypto/rsa-encrypt pubkey plaintext {:padding :oaep-sha384})
          decrypted (crypto/rsa-decrypt privkey ciphertext {:padding :oaep-sha384})]
      (assert (= plaintext (string decrypted)) "OAEP-SHA384 roundtrip")))

  (def-test "RSA encrypt with OAEP-SHA512"
    (let [privkey (crypto/generate-key :rsa 2048)
          pubkey (crypto/export-public-key privkey)
          plaintext "Test OAEP-SHA512"
          ciphertext (crypto/rsa-encrypt pubkey plaintext {:padding :oaep-sha512})
          decrypted (crypto/rsa-decrypt privkey ciphertext {:padding :oaep-sha512})]
      (assert (= plaintext (string decrypted)) "OAEP-SHA512 roundtrip")))

  (def-test "RSA max plaintext size"
    (let [key (crypto/generate-key :rsa 2048)
          max-oaep256 (crypto/rsa-max-plaintext key {:padding :oaep-sha256})
          max-oaep512 (crypto/rsa-max-plaintext key {:padding :oaep-sha512})]
      (assert (> max-oaep256 0) "Max plaintext > 0")
      (assert (> max-oaep256 max-oaep512) "SHA256 allows more than SHA512")))

  (def-test "RSA encrypt too large fails"
    :expected-fail "exceeds maximum"
    (let [key (crypto/generate-key :rsa 2048)
          pubkey (crypto/export-public-key key)
          max-size (crypto/rsa-max-plaintext key)
          too-large (string/repeat "x" (+ max-size 1))]
      (crypto/rsa-encrypt pubkey too-large)))

  (def-test "RSA decrypt wrong key fails"
    :expected-fail "decryption failed"
    (let [key1 (crypto/generate-key :rsa 2048)
          key2 (crypto/generate-key :rsa 2048)
          pubkey1 (crypto/export-public-key key1)
          ciphertext (crypto/rsa-encrypt pubkey1 "secret")]
      (crypto/rsa-decrypt key2 ciphertext)))

  # ===========================================================================
  # Key/Cert Conversion Tests
  # ===========================================================================

  (def-test "Key convert PEM to DER and back"
    (let [key-pem (crypto/generate-key :ec-p256)
          key-der (crypto/convert-key key-pem :der)
          key-pem2 (crypto/convert-key key-der :pem)]
      (assert (not (string/find "BEGIN" key-der)) "DER is binary (no PEM header)")
      (assert (string? key-pem2) "PEM is string")
      (assert (= key-pem key-pem2) "PEM roundtrip matches")))

  (def-test "Key convert to PKCS8"
    (let [key (crypto/generate-key :rsa 2048)
          pkcs8 (crypto/convert-key key :pkcs8)]
      (assert (string/find "BEGIN PRIVATE KEY" pkcs8) "PKCS8 is PEM format")))

  (def-test "Key convert to encrypted PKCS8"
    (let [key (crypto/generate-key :ec-p256)
          pkcs8-enc (crypto/convert-key key :pkcs8 {:password "secret"})]
      (assert (string/find "ENCRYPTED" pkcs8-enc) "PKCS8 is encrypted")))

  (def-test "Cert convert PEM to DER and back"
    (let [cert-result (cert/generate-self-signed-cert {:common-name "Convert Test"})
          cert-pem (cert-result :cert)
          cert-der (crypto/convert-cert cert-pem :der)
          cert-pem2 (crypto/convert-cert cert-der :pem)]
      (assert (not (string/find "BEGIN" cert-der)) "DER is binary (no PEM header)")
      (assert (= cert-pem cert-pem2) "Cert PEM roundtrip")))

  (def-test "Format detection"
    (let [key-pem (crypto/generate-key :ec-p256)
          key-der (crypto/convert-key key-pem :der)]
      (assert (= :pem (crypto/detect-format key-pem)) "Detects PEM")
      (assert (= :der (crypto/detect-format key-der)) "Detects DER")))

  (def-test "Password-protected key export/load"
    (let [key (crypto/generate-key :rsa 2048)
          encrypted (crypto/export-key key {:password "mypass" :cipher :aes-256-cbc})
          loaded (crypto/load-key encrypted "mypass")]
      (assert (string/find "ENCRYPTED" encrypted) "Key is encrypted")
      (assert (= key loaded) "Loaded key matches original")))

  (def-test "Key info on encrypted key"
    (let [key (crypto/generate-key :rsa 2048)
          encrypted (crypto/export-key key {:password "pass"})
          info (crypto/key-info encrypted)]
      # Note: encrypted keys may return :unknown type since we can't decrypt without password
      (assert (or (= :rsa (info :type)) (= :unknown (info :type))) "Key type detected or unknown")
      (assert (info :encrypted) "Detected as encrypted")))

  (def-test "Key info on unencrypted key"
    (let [key (crypto/generate-key :ec-p256)
          info (crypto/key-info key)]
      (assert (= :ec (info :type)) "Key type is EC")
      (assert (not (info :encrypted)) "Not encrypted")
      (assert (info :curve) "Curve info present")))

  # ===========================================================================
  # EC Point Operations Tests
  # ===========================================================================

  (def-test "EC generate scalar"
    (let [scalar (crypto/ec-generate-scalar :p-256)]
      (assert (= 32 (length scalar)) "P-256 scalar is 32 bytes")))

  (def-test "EC point multiplication"
    (let [scalar (crypto/ec-generate-scalar :p-256)
          point (crypto/ec-point-mul :p-256 scalar)]
      (assert (point :x) "Point has x coordinate")
      (assert (point :y) "Point has y coordinate")
      (assert (= 32 (length (point :x))) "x is 32 bytes")
      (assert (= 32 (length (point :y))) "y is 32 bytes")))

  (def-test "EC point addition"
    (let [s1 (crypto/ec-generate-scalar :p-256)
          s2 (crypto/ec-generate-scalar :p-256)
          p1 (crypto/ec-point-mul :p-256 s1)
          p2 (crypto/ec-point-mul :p-256 s2)
          p3 (crypto/ec-point-add :p-256 p1 p2)]
      (assert (p3 :x) "Sum point has x")
      (assert (p3 :y) "Sum point has y")))

  (def-test "EC point serialization uncompressed"
    (let [scalar (crypto/ec-generate-scalar :p-256)
          point (crypto/ec-point-mul :p-256 scalar)
          bytes (crypto/ec-point-to-bytes :p-256 point)
          parsed (crypto/ec-point-from-bytes :p-256 bytes)]
      (assert (= 65 (length bytes)) "Uncompressed is 65 bytes (04 || x || y)")
      (assert (= 0x04 (get bytes 0)) "Starts with 0x04")
      (assert (= (point :x) (parsed :x)) "x roundtrip")
      (assert (= (point :y) (parsed :y)) "y roundtrip")))

  (def-test "EC point serialization compressed"
    (let [scalar (crypto/ec-generate-scalar :p-256)
          point (crypto/ec-point-mul :p-256 scalar)
          bytes (crypto/ec-point-to-bytes :p-256 point {:compressed true})
          parsed (crypto/ec-point-from-bytes :p-256 bytes)]
      (assert (= 33 (length bytes)) "Compressed is 33 bytes")
      (assert (or (= 0x02 (get bytes 0)) (= 0x03 (get bytes 0))) "Starts with 02 or 03")
      (assert (= (point :x) (parsed :x)) "x roundtrip")))

  (def-test "EC manual ECDH matches high-level"
    (let [# Generate keys using both methods
          alice-scalar (crypto/ec-generate-scalar :p-256)
          alice-point (crypto/ec-point-mul :p-256 alice-scalar)
          bob-scalar (crypto/ec-generate-scalar :p-256)
          bob-point (crypto/ec-point-mul :p-256 bob-scalar)
          # Manual ECDH
          alice-shared (crypto/ec-point-mul :p-256 alice-scalar bob-point)
          bob-shared (crypto/ec-point-mul :p-256 bob-scalar alice-point)]
      (assert (= (alice-shared :x) (bob-shared :x)) "Manual ECDH produces same x")))

  (def-test "EC secp256k1 support"
    (let [scalar (crypto/ec-generate-scalar :secp256k1)
          point (crypto/ec-point-mul :secp256k1 scalar)]
      (assert (= 32 (length scalar)) "secp256k1 scalar is 32 bytes")
      (assert (= 32 (length (point :x))) "secp256k1 x is 32 bytes")))

  (def-test "EC P-384 support"
    (let [scalar (crypto/ec-generate-scalar :p-384)
          point (crypto/ec-point-mul :p-384 scalar)]
      (assert (= 48 (length scalar)) "P-384 scalar is 48 bytes")
      (assert (= 48 (length (point :x))) "P-384 x is 48 bytes")))

  (def-test "EC P-521 support"
    (let [scalar (crypto/ec-generate-scalar :p-521)
          point (crypto/ec-point-mul :p-521 scalar)]
      (assert (= 66 (length scalar)) "P-521 scalar is 66 bytes")
      (assert (= 66 (length (point :x))) "P-521 x is 66 bytes"))))
