# jcrypto OpenSSL return-value and option-validation regression test
# Ticket b346579869486ff8f52f79b67ef42159b72ba79c
#
# "Check OpenSSL return values and preserve error reasons across jcrypto
#  keys, sign/verify, EC/ECDH, convert, CMS, and PKCS#12"
#
# Mechanism (this tree, branch ticket-b346579869... off 0.2.0 at
# 2eef29afaf): several jcrypto primitives discard OpenSSL error
# returns and silently drop invalid options. The observable
# representatives this suite pins:
#   - cfun_key_info (src/jcrypto/keys.c:299-...) returns
#     {:type :unknown} for an unparseable key PEM
#     (src/jcrypto/keys.c:340-346: both PEM_read_bio_PrivateKey and
#     PEM_read_bio_PUBKEY fail, ERR_clear_error at :343 swallows the
#     reason) instead of raising [CRYPTO:PARSE] - the caller cannot
#     tell "not a key" from "encrypted key" and the parse failure is
#     invisible;
#   - cfun_cms_encrypt (src/jcrypto/cms.c:165-...) maps only the
#     known :cipher keywords at src/jcrypto/cms.c:217-230 and treats
#     every other keyword as the AES-256-CBC default at :210 - an
#     unknown :cipher silently encrypts with AES-256-CBC instead of
#     raising [CRYPTO:PARAM];
#   - cfun_create_pkcs12 (src/jcrypto/pkcs12.c) sets the friendly name
#     with X509_alias_set1(..., (int)strlen(friendly_name)) at
#     src/jcrypto/pkcs12.c:244-245: the explicit Janet byte length is
#     available and ignored, so a friendly name carrying a NUL byte is
#     silently truncated at the NUL.
# The ruled fix (2026-10-11, INDEX.org Ruling 3.2 Option 2 plus Ruling
# 2.7 for E-25) checks these OpenSSL return values and option values,
# raises [CRYPTO:PARSE] on unparseable keys in crypto/key-info, raises
# [CRYPTO:PARAM] on an unknown :cipher in cms-encrypt, and passes the
# explicit byte length to X509_alias_set1 in pkcs12.c.
#
# This test demonstrates:
#   (a) crypto/key-info raises [CRYPTO:PARSE] on unparseable key input
#       instead of returning {:type :unknown},
#   (b) crypto/cms-encrypt raises [CRYPTO:PARAM] on an unknown :cipher
#       keyword instead of silently falling back to AES-256-CBC,
#   (c) a PKCS#12 friendly name containing a NUL byte round-trips its
#       full byte length through create-pkcs12 and parse-pkcs12.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - (a) "silently
# swallowed the parse failure into {:type :unknown}", (b) "silently
# fell back to AES-256-CBC", (c) "truncated at strlen" - and nothing
# else: no crash, no unrelated error. Under fixed code every test
# passes.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import jsec/ca :as ca)
(import ../helpers :prefix "")

(def authority (cert/generate-self-signed-cert
                 {:common-name "jcrypto-return-checks-regression.local"
                  :key-type :rsa :bits 2048 :days-valid 5}))

(defn- capture-error
  "Run thunk; return [:raised message] or [:returned value]."
  [thunk]
  (try
    [:returned (thunk)]
    ([e] [:raised (string e)])))

(defn- short-q
  "Describe x with %q, truncated to 200 chars for failure messages."
  [x]
  (def s (string/format "%q" x))
  (string/slice s 0 (min 200 (length s))))

# AES-256-CBC content-encryption OID (2.16.840.1.101.3.4.1.42) as DER.
(def- aes-256-cbc-oid
  (string/from-bytes 6 9 0x60 0x86 0x48 1 0x65 3 4 1 0x2a))

(def-suite :name "Jcrypto OpenSSL Return Checks Regression"
  :description "Ticket b346579869: key-info, cms-encrypt, and create-pkcs12 stop discarding OpenSSL failures and invalid option values"

  (def-test "key-info-raises-on-unparseable-key-input"
    :timeout 60

    (def outcome (capture-error
                   (fn [] (crypto/key-info "this is not a PEM key at all"))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARSE" (get outcome 1)))
            (string/format
              (string "crypto/key-info silently swallowed the parse "
                      "failure into {:type :unknown} instead of raising "
                      "[CRYPTO:PARSE]: got %q. src/jcrypto/keys.c "
                      ":320-346 try PEM_read_bio_PrivateKey then "
                      "PEM_read_bio_PUBKEY, and when both fail the "
                      "ERR_clear_error call drains the reason and the "
                      "function returns {:type :unknown} - an "
                      "unparseable key is indistinguishable from an "
                      "encrypted one and the failure is never signalled")
              (short-q outcome))))

  (def-test "cms-encrypt-raises-on-unknown-cipher"
    :timeout 60

    (def outcome (capture-error
                   (fn [] (crypto/cms-encrypt "secret payload"
                                        (authority :cert)
                                        {:cipher :bogus-xyz}))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARAM" (get outcome 1)))
            (string/format
              (string "crypto/cms-encrypt silently fell back to "
                      "AES-256-CBC for the unknown :cipher :bogus-xyz "
                      "instead of raising [CRYPTO:PARAM]: got %q. "
                      "src/jcrypto/cms.c :210-230 defaults to "
                      "EVP_aes_256_cbc and only replaces it for the "
                      "known keywords, so an unknown keyword is "
                      "dropped on the floor and the envelope is "
                      "encrypted with the default cipher")
              (short-q outcome))))

  (def-test "pkcs12-friendly-name-round-trips-embedded-nul-bytes"
    :timeout 60

    # The friendly name is 5 bytes with a NUL at index 2. The explicit
    # byte length is passed to create-pkcs12; X509_alias_set1 must
    # receive that length, not strlen(name).
    (def name-bytes (string/from-bytes 97 98 0 99 100))
    (def bundle (crypto/create-pkcs12 (authority :cert) (authority :key)
                                      {:password "pass"
                                       :friendly-name name-bytes}))
    (def parsed (crypto/parse-pkcs12 bundle "pass"))
    (def got (string (get parsed :friendly-name)))
    (assert (= got name-bytes)
            (string/format
              (string "the PKCS#12 friendly name %q (5 bytes, NUL at "
                      "index 2) round-tripped as %q (%d bytes): "
                      "create-pkcs12 truncated the name at the NUL. "
                      "src/jcrypto/pkcs12.c:244-245 calls "
                      "X509_alias_set1 with (int)strlen(friendly_name) "
                      "instead of the explicit Janet byte length, so "
                      "everything from the NUL on is silently dropped")
              (string/format "%q" name-bytes)
              (string/format "%q" got) (length got))))

  (def-test "cms-encrypt-unknown-cipher-must-raise"
    (def ca (ca/generate {:common-name "Discard Root"}))
    (def cert (ca/get-cert ca))
    (def outcome
      (try
        {:returned (crypto/cms-encrypt "payload" cert {:cipher :aes-256-gcm})}
        ([err] {:raised err})))
    (def observed
      (if-let [der-bytes (outcome :returned)]
        (string "returned " (length der-bytes) " bytes of CMS data "
                "encrypted with AES-256-CBC"
                (if (string/find aes-256-cbc-oid (string der-bytes))
                  " (the AES-256-CBC content-encryption OID is in the output)"
                  "")
                " - the unknown :cipher silently fell back to the default")
        (string "raised " (describe (outcome :raised)))))
    (assert (not (nil? (outcome :raised)))
            (string "crypto/cms-encrypt with an unsupported :cipher "
                    "must raise an unsupported-cipher error (as "
                    "crypto/export-key already does at "
                    "src/jcrypto/keys.c:221-224) instead of silently "
                    "encrypting with the AES-256-CBC default at "
                    "src/jcrypto/cms.c:210 because the cipher chain at "
                    "src/jcrypto/cms.c:213-228 matches nothing for "
                    ":aes-256-gcm, but it " observed)))

  (def-test "generate-key-invalid-rsa-bits-must-raise"
    (def outcome
      (try
        {:returned (crypto/generate-key :rsa 7)}
        ([err] {:raised err})))
    (def err-text (if (outcome :raised) (string (outcome :raised)) ""))
    (def at-keygen (string/find "failed to generate key" err-text))
    (def observed
      (if (nil? (outcome :raised))
        (string "silently returned a key of "
                (get (crypto/key-info (outcome :returned)) :bits) " bits")
        (string "raised " (describe (outcome :raised))
                (if at-keygen
                  " - the failure surfaced later inside key generation, not at the :bits argument"
                  ""))))
    (assert (and (not (nil? (outcome :raised))) (nil? at-keygen))
            (string "crypto/generate-key with an RSA size OpenSSL "
                    "rejects (7 is not a positive multiple of 8) must "
                    "raise at the :bits argument - bits must be a "
                    "positive multiple of 8 - or raise the key-size "
                    "setter error at src/jcrypto/keys.c:73, whose "
                    "return is discarded today; instead the failure "
                    "falls through into key generation and surfaces "
                    "there with a different, confusing error, so it "
                    observed)))

)
