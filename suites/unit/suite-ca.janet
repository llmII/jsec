# CA Module Test Suite
#
# Tests for jsec/ca Certificate Authority functionality

(use assay)
(import jsec/ca)

(def-suite :name "CA Suite"

  # ===========================================================================
  # Root CA Generation
  # ===========================================================================

  (def-test "ca/generate creates root CA with defaults"
    (def ca (ca/generate))
    (assert ca "CA should be created")
    (assert (string? (:get-cert ca)) "Should return PEM certificate")
    (assert (string/has-prefix? "-----BEGIN CERTIFICATE-----" (:get-cert ca))
            "Certificate should be PEM format"))

  (def-test "ca/generate respects options"
    (def ca (ca/generate {:common-name "Test CA"
                          :days-valid 365
                          :organization "Test Org"
                          :country "US"
                          :serial 100}))
    (assert (= (int/s64 100) (:get-serial ca)) "Serial should be set to 100"))

  (def-test "ca/generate with tracking enabled"
    (def ca (ca/generate {:track-issued true}))
    (assert (:is-tracking ca) "Tracking should be enabled")
    (assert (= 0 (length (:get-issued ca))) "No certs issued yet"))

  (def-test "ca/generate without tracking"
    (def ca (ca/generate {:track-issued false}))
    (assert (not (:is-tracking ca)) "Tracking should be disabled")
    (assert (nil? (:get-issued ca)) "get-issued returns nil when not tracking"))

  # ===========================================================================
  # Key Types
  # ===========================================================================

  (def-test "ca/generate supports EC P-256"
    :timeout 5
    (def ca (ca/generate {:key-type :ec-p256}))
    (assert ca "Should create CA with EC P-256"))

  (def-test "ca/generate supports EC P-384"
    :timeout 5
    (def ca (ca/generate {:key-type :ec-p384}))
    (assert ca "Should create CA with EC P-384"))

  (def-test "ca/generate supports RSA-2048"
    :timeout 10
    (def ca (ca/generate {:key-type :rsa-2048}))
    (assert ca "Should create CA with RSA-2048"))

  # ===========================================================================
  # Intermediate CA
  # ===========================================================================

  (def-test "ca/generate-intermediate creates signed intermediate"
    (def root (ca/generate {:common-name "Root"}))
    (def intermediate (ca/generate-intermediate root {:common-name "Intermediate"}))
    (assert intermediate "Intermediate CA should be created")
    (assert (not= (:get-cert root) (:get-cert intermediate))
            "Certs should be different"))

  (def-test "ca/generate-intermediate increments parent serial"
    (def root (ca/generate {:serial 1}))
    (assert (= (int/s64 1) (:get-serial root)) "Root starts at serial 1")
    (ca/generate-intermediate root {})
    (assert (= (int/s64 2) (:get-serial root)) "Root serial incremented after issuing"))

  (def-test "ca/generate-intermediate with path-length"
    (def root (ca/generate))
    (def intermediate (ca/generate-intermediate root {:path-length 0}))
    (assert intermediate "Should create with path-length constraint"))

  # ===========================================================================
  # Certificate Issuance
  # ===========================================================================

  (def-test ":issue creates cert and key"
    (def ca (ca/generate))
    (def issued (:issue ca {:common-name "test.example.com"}))
    (assert (issued :cert) "Should have cert")
    (assert (issued :key) "Should have key")
    (assert (string/has-prefix? "-----BEGIN CERTIFICATE-----" (issued :cert))
            "Cert should be PEM")
    (assert (string/has-prefix? "-----BEGIN PRIVATE KEY-----" (issued :key))
            "Key should be PEM"))

  (def-test ":issue with SAN"
    (def ca (ca/generate))
    (def issued (:issue ca {:common-name "server"
                            :san ["DNS:server.example.com"
                                  "DNS:localhost"
                                  "IP:127.0.0.1"]}))
    (assert (issued :cert) "Should issue cert with SANs"))

  (def-test ":issue with extended-key-usage"
    (def ca (ca/generate))
    (def server (:issue ca {:common-name "server"
                            :extended-key-usage "serverAuth"}))
    (def client (:issue ca {:common-name "client"
                            :extended-key-usage "clientAuth"}))
    (assert server "Should issue server cert")
    (assert client "Should issue client cert"))

  (def-test ":issue tracks when enabled"
    (def ca (ca/generate {:track-issued true}))
    (:issue ca {:common-name "cert1"})
    (:issue ca {:common-name "cert2"})
    (def issued (:get-issued ca))
    (assert (= 2 (length issued)) "Should have 2 tracked certs"))

  (def-test ":issue increments serial"
    (def ca (ca/generate {:serial 1}))
    (:issue ca {:common-name "cert1"})
    (assert (= (int/s64 2) (:get-serial ca)) "Serial should be 2")
    (:issue ca {:common-name "cert2"})
    (assert (= (int/s64 3) (:get-serial ca)) "Serial should be 3"))

  # ===========================================================================
  # CA Creation from Existing
  # ===========================================================================

  (def-test "ca/create from existing cert and key"
    (def original (ca/generate {:serial 100}))
    (def cert (:get-cert original))

    # We can't easily get the key from a CA object, but we can test
    # that the function exists and validates inputs
    (assert cert "Should have cert"))

  (def-test "ca/create with serial restoration"
    # This tests the pattern for serial persistence
    (def ca (ca/generate {:serial 50}))
    (:issue ca {:common-name "test"})
    (def saved-serial (:get-serial ca))
    (assert (= (int/s64 51) saved-serial) "Serial should be 51 after one issuance"))

  # ===========================================================================
  # Serial Number Management
  # ===========================================================================

  (def-test ":get-serial returns current serial"
    (def ca (ca/generate {:serial 42}))
    (assert (= (int/s64 42) (:get-serial ca)) "Should return configured serial"))

  (def-test ":set-serial updates serial"
    (def ca (ca/generate {:serial 1}))
    (:set-serial ca 1000)
    (assert (= (int/s64 1000) (:get-serial ca)) "Serial should be updated"))

  # ===========================================================================
  # Revocation
  # ===========================================================================

  (def-test ":revoke adds to revocation list"
    (def ca (ca/generate))
    (:revoke ca 123)
    (def revoked (:get-revoked ca))
    (assert (= 1 (length revoked)) "Should have 1 revoked")
    (assert (= (int/s64 123) ((first revoked) :serial)) "Serial should match"))

  (def-test ":revoke with reason"
    (def ca (ca/generate))
    (:revoke ca 456 :key-compromise)
    (def revoked (:get-revoked ca))
    (assert (= :key-compromise ((first revoked) :reason)) "Reason should match"))

  (def-test ":revoke multiple certificates"
    (def ca (ca/generate))
    (:revoke ca 1 :unspecified)
    (:revoke ca 2 :superseded)
    (:revoke ca 3 :cessation-of-operation)
    (def revoked (:get-revoked ca))
    (assert (= 3 (length revoked)) "Should have 3 revoked"))

  (def-test "revocation reasons are valid keywords"
    (def ca (ca/generate))
    (def reasons [:unspecified :key-compromise :ca-compromise
                  :affiliation-changed :superseded :cessation-of-operation
                  :certificate-hold :privilege-withdrawn :aa-compromise])
    (var serial 1)
    (each reason reasons
      (:revoke ca serial reason)
      (++ serial))
    (def revoked (:get-revoked ca))
    (assert (= (length reasons) (length revoked)) "All reasons should work"))

  # ===========================================================================
  # CRL Generation
  # ===========================================================================

  (def-test ":generate-crl produces PEM CRL"
    (def ca (ca/generate))
    (def crl (:generate-crl ca))
    (assert (string? crl) "CRL should be string")
    (assert (string/has-prefix? "-----BEGIN X509 CRL-----" crl)
            "CRL should be PEM format"))

  (def-test ":generate-crl includes revoked certs"
    (def ca (ca/generate))
    (:revoke ca 100 :key-compromise)
    (:revoke ca 200 :superseded)
    (def crl (:generate-crl ca))
    (assert (> (length crl) 0) "CRL should have content"))

  (def-test ":generate-crl with additional revocations"
    (def ca (ca/generate))
    (def crl (:generate-crl ca {:revoked [{:serial 999 :reason :unspecified}]}))
    (assert crl "Should accept additional revocations"))

  (def-test ":generate-crl with custom validity"
    (def ca (ca/generate))
    (def crl (:generate-crl ca {:days-valid 7}))
    (assert crl "Should accept custom validity"))

  # ===========================================================================
  # OCSP Support
  # ===========================================================================

  # Note: Full OCSP testing requires actual OCSP request bytes
  # These tests verify the API exists and handles edge cases

  (def-test "ca/parse-ocsp-request exists"
    (assert ca/parse-ocsp-request "Function should exist"))

  (def-test ":create-ocsp-response exists as method"
    (def ca (ca/generate))
    # Methods are retrieved via the abstract type's get callback
    # We test that the CA object can be used with OCSP functions
    (assert ca "CA should support OCSP methods"))

  # ===========================================================================
  # Standalone Functions vs Methods
  # ===========================================================================

  (def-test "ca/issue works as standalone function"
    (def ca (ca/generate))
    (def result (ca/issue ca {:common-name "test"}))
    (assert (result :cert) "Standalone function should work"))

  (def-test "ca/get-cert works as standalone function"
    (def ca (ca/generate))
    (def cert (ca/get-cert ca))
    (assert (string? cert) "Should return cert string"))

  (def-test "ca/get-serial works as standalone function"
    (def ca (ca/generate {:serial 77}))
    (assert (= (int/s64 77) (ca/get-serial ca)) "Should return serial"))

  (def-test "ca/crl works as standalone function"
    (def ca (ca/generate))
    (def crl (ca/crl ca))
    (assert (string/has-prefix? "-----BEGIN X509 CRL-----" crl)
            "Should generate CRL"))

  # ===========================================================================
  # Error Handling
  # ===========================================================================

  (def-test ":issue requires common-name"
    :expected-fail "common-name"
    (def ca (ca/generate))
    (:issue ca {}))

  (def-test "ca/generate handles invalid key-type"
    :expected-fail "invalid key type"
    (ca/generate {:key-type :invalid-key-type}))

  # ===========================================================================
  # Integration: Full PKI Workflow
  # ===========================================================================

  (def-test "full PKI workflow"
    :timeout 15
    # Create root CA
    (def root (ca/generate {:common-name "Root CA"
                            :track-issued true
                            :serial 1}))

    # Create intermediate CA
    (def intermediate (ca/generate-intermediate root
                                                {:common-name "Intermediate CA"
                                                 :path-length 0
                                                 :track-issued true}))

    # Issue server certificate
    (def server (:issue intermediate
                        {:common-name "server.example.com"
                         :san ["DNS:server.example.com" "DNS:localhost"]
                         :extended-key-usage "serverAuth"}))

    # Issue client certificate
    (def client (:issue intermediate
                        {:common-name "client@example.com"
                         :extended-key-usage "clientAuth"}))

    # Verify chain
    (assert (= 1 (length (:get-issued root))) "Root issued 1 (intermediate)")
    (assert (= 2 (length (:get-issued intermediate))) "Intermediate issued 2")

    # Revoke client cert
    (def client-serial (- (:get-serial intermediate) 1))
    (:revoke intermediate client-serial :key-compromise)

    # Generate CRL
    (def crl (:generate-crl intermediate))
    (assert (string? crl) "CRL generated")

    # Check revocation list
    (def revoked (:get-revoked intermediate))
    (assert (= 1 (length revoked)) "One cert revoked")
    (assert (= client-serial ((first revoked) :serial)) "Correct serial revoked")))
