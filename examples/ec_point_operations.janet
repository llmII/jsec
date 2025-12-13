# Elliptic Curve Point Operations Examples
#
# Demonstrates low-level EC point arithmetic for:
# - Custom ECDH implementations
# - EC signature schemes
# - Threshold cryptography
# - Zero-knowledge proofs
# - Bitcoin/Ethereum cryptography (secp256k1)

(import jsec/crypto :as crypto)

(defn bytes-to-hex [b]
  (string/join (map |(string/format "%02x" $) b) ""))

(defn demo-basic-point-operations []
  (print "\n=== Basic EC Point Operations ===")

  # Generate a random scalar (private key equivalent)
  (def scalar (crypto/ec-generate-scalar :p-256))
  (printf "Random scalar (32 bytes): %s..." (string/slice (bytes-to-hex scalar) 0 32))

  # Multiply generator point by scalar: P = s * G
  (def point (crypto/ec-point-mul :p-256 scalar))
  (printf "Point P = s * G:")
  (printf "  x: %s..." (string/slice (bytes-to-hex (point :x)) 0 32))
  (printf "  y: %s..." (string/slice (bytes-to-hex (point :y)) 0 32)))

(defn demo-point-addition []
  (print "\n=== Point Addition ===")

  # Generate two points
  (def s1 (crypto/ec-generate-scalar :p-256))
  (def s2 (crypto/ec-generate-scalar :p-256))
  (def p1 (crypto/ec-point-mul :p-256 s1))
  (def p2 (crypto/ec-point-mul :p-256 s2))

  # Add them: P3 = P1 + P2
  (def p3 (crypto/ec-point-add :p-256 p1 p2))

  (print "P1 + P2 = P3")
  (printf "P3.x: %s..." (string/slice (bytes-to-hex (p3 :x)) 0 32)))

(defn demo-ecdh-manual []
  (print "\n=== Manual ECDH Key Exchange ===")

  # Alice generates her key pair
  (def alice-private (crypto/ec-generate-scalar :p-256))
  (def alice-public (crypto/ec-point-mul :p-256 alice-private))
  (print "Alice: generated key pair")

  # Bob generates his key pair
  (def bob-private (crypto/ec-generate-scalar :p-256))
  (def bob-public (crypto/ec-point-mul :p-256 bob-private))
  (print "Bob: generated key pair")

  # Alice computes shared secret: S = a * B
  (def alice-shared (crypto/ec-point-mul :p-256 alice-private bob-public))

  # Bob computes shared secret: S = b * A
  (def bob-shared (crypto/ec-point-mul :p-256 bob-private alice-public))

  # They should be equal
  (printf "Alice's shared secret x: %s" (bytes-to-hex (alice-shared :x)))
  (printf "Bob's shared secret x:   %s" (bytes-to-hex (bob-shared :x)))
  (printf "Shared secrets match: %v" (= (alice-shared :x) (bob-shared :x))))

(defn demo-point-serialization []
  (print "\n=== Point Serialization (SEC1 format) ===")

  (def scalar (crypto/ec-generate-scalar :p-256))
  (def point (crypto/ec-point-mul :p-256 scalar))

  # Uncompressed format (0x04 || x || y)
  (def uncompressed (crypto/ec-point-to-bytes :p-256 point))
  (printf "Uncompressed: %d bytes, starts with %02x"
          (length uncompressed) (get uncompressed 0))

  # Compressed format (0x02 or 0x03 || x)
  (def compressed (crypto/ec-point-to-bytes :p-256 point {:compressed true}))
  (printf "Compressed: %d bytes, starts with %02x"
          (length compressed) (get compressed 0))

  # Parse back
  (def parsed-unc (crypto/ec-point-from-bytes :p-256 uncompressed))
  (def parsed-cmp (crypto/ec-point-from-bytes :p-256 compressed))

  (printf "Uncompressed round-trip: %v" (= (point :x) (parsed-unc :x)))
  (printf "Compressed round-trip: %v" (= (point :x) (parsed-cmp :x))))

(defn demo-supported-curves []
  (print "\n=== Supported Curves ===")

  (print "NIST curves:")
  (print "  :p-256 (secp256r1) - 256-bit, widely used")
  (print "  :p-384 (secp384r1) - 384-bit, higher security")
  (print "  :p-521 (secp521r1) - 521-bit, highest security")

  (print "\nOther curves:")
  (print "  :secp256k1 - Bitcoin/Ethereum curve")

  # Demonstrate different curves
  (each curve [:p-256 :p-384 :p-521 :secp256k1]
    (def scalar (crypto/ec-generate-scalar curve))
    (def point (crypto/ec-point-mul curve scalar))
    (printf "  %v: scalar %d bytes, point x %d bytes"
            curve (length scalar) (length (point :x)))))

(defn demo-bitcoin-style []
  (print "\n=== Bitcoin-style Operations (secp256k1) ===")

  # Generate a "private key"
  (def privkey (crypto/ec-generate-scalar :secp256k1))
  (printf "Private key: %s" (bytes-to-hex privkey))

  # Derive "public key"
  (def pubkey-point (crypto/ec-point-mul :secp256k1 privkey))
  (def pubkey-compressed (crypto/ec-point-to-bytes :secp256k1 pubkey-point {:compressed true}))
  (printf "Public key (compressed): %s" (bytes-to-hex pubkey-compressed))

  (print "\nNote: For actual Bitcoin use, you'd also need:")
  (print "  - SHA256 + RIPEMD160 hashing for addresses")
  (print "  - Base58Check encoding")
  (print "  - ECDSA signing (use crypto/sign with EC key instead)"))

(defn main [&]
  (print "=== Elliptic Curve Point Operations Demo ===")

  (demo-basic-point-operations)
  (demo-point-addition)
  (demo-ecdh-manual)
  (demo-point-serialization)
  (demo-supported-curves)
  (demo-bitcoin-style)

  (print "\n=== Demo Complete ==="))
