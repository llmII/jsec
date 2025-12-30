# Error Trigger Tests
# Tests that deliberately trigger error conditions to verify:
# - Error messages are correct
# - Resources are properly cleaned up on error
# - No memory leaks from error paths
#
# Uses janet-assay's :expected-fail for negative testing

(use assay)
(import jsec/tls)
(import jsec/dtls-stream :as dtls)
(import jsec/bio)
(import jsec/crypto)
(import jsec/cert)
(import jsec/ca)

(def-suite :name "errors"
  :description "Error trigger tests - verify correct error handling"

  # ==========================================================================
  # Configuration Errors - Crypto
  # ==========================================================================

  (def-test "config error - random-bytes zero"
    :expected-fail "random-bytes should reject zero byte request"
    (crypto/random-bytes 0))

  (def-test "config error - random-bytes negative"
    :expected-fail "random-bytes should reject negative byte request"
    (crypto/random-bytes -1))

  (def-test "config error - pbkdf2 zero iterations"
    :expected-fail "pbkdf2 should reject zero iterations"
    (crypto/pbkdf2 :sha256 "pass" "salt" 0 32))

  (def-test "config error - pbkdf2 negative iterations"
    :expected-fail "pbkdf2 should reject negative iterations"
    (crypto/pbkdf2 :sha256 "pass" "salt" -1 32))

  (def-test "config error - pbkdf2 invalid hash"
    :expected-fail "pbkdf2 should reject invalid hash algorithm"
    (crypto/pbkdf2 :invalid-hash "pass" "salt" 1000 32))

  (def-test "config error - hkdf zero output"
    :expected-fail "hkdf should reject zero output length"
    (crypto/hkdf :sha256 "secret" "salt" "info" 0))

  (def-test "config error - hkdf invalid hash"
    :expected-fail "hkdf should reject invalid hash algorithm"
    (crypto/hkdf :invalid-hash "secret" "salt" "info" 32))

  (def-test "config error - digest invalid algorithm"
    :expected-fail "digest should reject invalid algorithm"
    (crypto/digest :not-a-hash "data"))

  (def-test "config error - hmac invalid algorithm"
    :expected-fail "hmac should reject invalid algorithm"
    (crypto/hmac :not-a-hash "key" "data"))

  # ==========================================================================
  # State Errors - BIO
  # ==========================================================================

  (def-test "state error - BIO write after close"
    :expected-fail "BIO should error on write after close"
    (def b (bio/new-mem))
    (:close b)
    (:write b "data"))

  (def-test "state error - BIO read after close"
    :expected-fail "BIO should error on read after close"
    (def b (bio/new-mem))
    (:write b "test")
    (:close b)
    (:read b 10))

  # ==========================================================================
  # Configuration Errors - TLS
  # ==========================================================================

  (def-test "config error - TLS invalid cert file"
    :expected-fail "TLS context should fail with invalid cert path"
    (tls/new-context {:cert "/nonexistent/path.pem" :key "/nonexistent/key.pem"}))

  (def-test "config error - TLS malformed cert"
    :expected-fail "TLS context should fail with malformed cert data"
    (tls/new-context {:cert "NOT A VALID CERT" :key "NOT A VALID KEY"}))

  (def-test "config error - TLS cert without key"
    :expected-fail "TLS context should fail with cert but no key"
    (def certs (cert/generate-self-signed-cert {:common-name "test"}))
    (tls/new-context {:cert (certs :cert)}))

  (def-test "config error - TLS invalid protocol version"
    :expected-fail "TLS should reject invalid protocol version"
    (def certs (cert/generate-self-signed-cert {:common-name "test"}))
    (tls/new-context {:cert (certs :cert)
                      :key (certs :key)
                      :security {:min-version :invalid}}))
  # - invalid key type for cert generation (defaults to RSA)
  # - invalid EC curve (silently fails to EC, may error later)

  # ==========================================================================
  # DTLS Errors
  # ==========================================================================

  (def-test "dtls error - listen without cert/key"
    :expected-fail "DTLS listen should require cert/key"
    (dtls/listen "127.0.0.1" "0" {}))

  (def-test "dtls error - connect to non-listening"
    :expected-fail "DTLS connect should fail on non-listening port"
    :timeout 5
    (dtls/connect "127.0.0.1" "59997" {:timeout 1}))

  # ==========================================================================
  # Connection Errors
  # ==========================================================================

  (def-test "conn error - connect to non-listening port"
    :expected-fail "connect should fail on refused port"
    :timeout 5
    # Must write after connect - Windows only detects
    # connection errors on first I/O, not at connect time
    (def conn (tls/connect "127.0.0.1" "59999" {:timeout 1}))
    (:write conn "test")
    (:close conn))

  (def-test "conn error - connect timeout"
    :expected-fail "connect should timeout on non-routable IP"
    :timeout 3
    # Must write after connect - Windows only detects
    # connection errors on first I/O, not at connect time  
    (def conn (tls/connect "127.0.0.1" "59998" {:timeout 0.1}))
    (:write conn "test")
    (:close conn))

  # ==========================================================================
  # Certificate Errors
  # ==========================================================================

  (def-test "cert error - parse invalid PEM"
    :expected-fail "cert/parse should reject invalid PEM"
    (cert/parse "NOT A VALID CERTIFICATE"))

  (def-test "cert error - parse empty string"
    :expected-fail "cert/parse should reject empty string"
    (cert/parse ""))

  (def-test "cert error - verify-chain invalid cert"
    :expected-fail "verify-chain should reject invalid cert"
    (cert/verify-chain "NOT A CERT"))

  (def-test "cert error - generate invalid key type"
    :expected-fail "cert generation should reject invalid key type"
    (cert/generate-self-signed-cert {:key-type :invalid-key-type}))

  # ==========================================================================
  # Crypto Key Errors
  # ==========================================================================

  (def-test "crypto error - sign with invalid key"
    :expected-fail "sign should reject invalid key PEM"
    (crypto/sign :sha256 "NOT A KEY" "data"))

  (def-test "crypto error - verify with invalid key"
    :expected-fail "verify should reject invalid key PEM"
    (crypto/verify :sha256 "NOT A KEY" "signature" "data"))

  (def-test "crypto error - encrypt invalid algorithm"
    :expected-fail "encrypt should reject invalid algorithm"
    (crypto/encrypt :not-an-algo "key" "iv" "data")))
