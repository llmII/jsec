# Discarded OpenSSL failures and silent option fallbacks - regression guards
#
# Four surfaces where an OpenSSL failure or an unsupported option value
# is discarded and the caller gets a plausible but wrong answer instead
# of an error. The project rule is that real failures raise and a silent
# fallback is never an acceptable failure signal.
#
# 1. crypto/cms-encrypt cipher selection (src/jcrypto/cms.c:210-228):
#    the keyword chain matches only aes-128-cbc, aes-192-cbc,
#    aes-256-cbc, des3 and 3des; any other :cipher keyword (or a
#    non-keyword :cipher value) matches nothing and the AES-256-CBC
#    default at src/jcrypto/cms.c:210 silently stands. crypto/export-key
#    already raises "unsupported cipher: %s" for the same mistake
#    (src/jcrypto/keys.c:221-224).
# 2. crypto/generate-key RSA size (src/jcrypto/keys.c:22-24, :73):
#    the :bits argument is taken unvalidated and the return of the
#    key-size setter is discarded, so a size OpenSSL rejects fails later
#    inside key generation with a confusing error attributed to key
#    generation.
# 3. Revoked-serial extraction (src/jca/crl.c:391, src/jca/ocsp.c:111):
#    the return of the 64-bit ASN.1 integer read is discarded and the
#    serial slot stays 0, so a serial too large for 64 bits is reported
#    as serial 0 - indistinguishable from a real serial 0.
# 4. X.509 subject construction (src/jca/types.c:451-458,
#    src/jca/sign.c:474-481, src/jcrypto/csr.c:40-82,
#    src/jcert/jcert.c:159-163): X509_NAME_add_entry_by_txt and its
#    sibling setters are used as bare statements, so a subject entry
#    OpenSSL rejects (a country code that is not exactly two characters,
#    a common name over the length limit) is silently dropped and the
#    certificate or CSR is returned with a partial or empty subject.
#
# Each guard asserts the correct behaviour - the failure raises at the
# failing call - and fails on purpose with its predicted symptom; they
# become the regression guard after the fix lands.
#
# Not guarded here: the revocation-entry construction in
# src/jca/crl.c:135-158 also discards every ASN.1 setter return it
# makes. Those calls fail only when an allocation fails, and that path
# crashes the process instead of raising, so its symptom cannot be shown
# as a failing assertion without fault injection; no guard is staged for
# it.

(use assay)
(import jsec/ca)
(import jsec/cert)
(import jsec/crypto)
(import ../helpers :prefix "")

# AES-256-CBC content-encryption OID (2.16.840.1.101.3.4.1.42) as DER.
(def- aes-256-cbc-oid
  (string/from-bytes 6 9 0x60 0x86 0x48 1 0x65 3 4 1 0x2a))

(defn- der [tag content]
  (def len (length content))
  (assert (< len 128) "DER length must be under 128 bytes for this builder")
  (string (string/from-bytes tag len) content))

# A minimal OCSP request carrying one certificate id whose serial
# number is the DER INTEGER with the given value bytes. Structure: OCSPRequest, TBSRequest,
# requestList, Request, CertID with a sha256 AlgorithmIdentifier and
# 32-byte issuer name and key hashes.
(defn- ocsp-request-with-serial [serial-der-bytes]
  (def algid
    (der 0x30 (string (string/from-bytes 6 9 0x60 0x86 0x48 1 0x65 3 4 2 1)
                      (string/from-bytes 5 0))))
  (def name-hash (der 4 (string/repeat "a" 32)))
  (def key-hash (der 4 (string/repeat "b" 32)))
  (def certid
    (der 0x30 (string algid name-hash key-hash (der 2 serial-der-bytes))))
  (der 0x30 (der 0x30 (der 0x30 (der 0x30 certid)))))

(def-suite :name "Discarded OpenSSL Errors Regression"
  :description "Discarded OpenSSL failures and silent option fallbacks must raise, never answer wrongly"

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

  (def-test "parse-ocsp-request-oversized-serial-must-not-report-zero"
    (def req-big
      (ocsp-request-with-serial (string/from-bytes 4 0 0 0 0 0 0 0 0)))
    (def req-zero (ocsp-request-with-serial (string/from-bytes 0)))
    (def big
      (try {:returned (ca/parse-ocsp-request req-big)}
           ([err] {:raised err})))
    (def zero
      (try {:returned (ca/parse-ocsp-request req-zero)}
           ([err] {:raised err})))
    (def big-serial (if (big :returned) (get (big :returned) :serial)))
    (def zero-serial (if (zero :returned) (get (zero :returned) :serial)))
    (def reported-zero
      (or (= (int/s64 0) big-serial) (= 0 big-serial)))
    (def observed
      (if (big :raised)
        (string "raised " (describe (big :raised)))
        (string "reported serial " (describe big-serial)
                " for the large serial - the same answer a request for "
                "serial 0 gives (" (describe zero-serial)
                "), so the two are indistinguishable")))
    (assert (or (big :raised) (and big-serial (not reported-zero)))
            (string "ca/parse-ocsp-request must raise, or report the "
                    "true serial as a value that cannot overflow, when "
                    "the certificate id serial does not fit in 64 bits "
                    "- the 64-bit ASN.1 integer read at "
                    "src/jca/ocsp.c:111 has its return discarded and "
                    "the serial slot stays 0 - but it " observed)))

  (def-test "subject-entry-add-failure-must-raise"
    (def root (ca/generate {:common-name "Discard Root"}))
    (def key (crypto/generate-key :ec-p256))
    (def gen
      (try {:returned (ca/generate {:common-name (string/repeat "A" 200)})}
           ([err] {:raised err})))
    (def iss
      (try {:returned (ca/issue root {:common-name "leaf.example"
                                      :country "USA"})}
           ([err] {:raised err})))
    (def csr
      (try {:returned (crypto/generate-csr key {:common-name "s.example"
                                                :country "USA"})}
           ([err] {:raised err})))
    (def gen-subject
      (if-let [c (gen :returned)]
        (get (cert/parse (ca/get-cert c)) :subject)))
    (def iss-subject
      (if-let [issued (iss :returned)]
        (get (cert/parse (issued :cert)) :subject)))
    (def observed
      (string
        "ca/generate with a 200-character common name "
        (if (gen :raised) (string "raised " (describe (gen :raised)))
          (string "returned a CA whose subject dn is "
                  (describe (get gen-subject :dn))
                  " (the oversized common name was silently dropped)"))
        "; ca/issue with a three-letter country code "
        (if (iss :raised) (string "raised " (describe (iss :raised)))
          (string "returned a certificate whose subject dn is "
                  (describe (get iss-subject :dn))
                  " (the country entry was silently dropped)"))
        "; crypto/generate-csr with a three-letter country code "
        (if (csr :raised) (string "raised " (describe (csr :raised)))
          "returned a CSR with the country entry silently dropped")))
    (assert (and (not (nil? (gen :raised)))
                 (not (nil? (iss :raised)))
                 (not (nil? (csr :raised))))
            (string "a subject entry OpenSSL rejects - a common name "
                    "over the length limit, a country code that is not "
                    "two characters - must raise at the failing call "
                    "(X509_NAME_add_entry_by_txt and its sibling "
                    "setters are used as bare statements at "
                    "src/jca/types.c:451-458, src/jca/sign.c:474-481, "
                    "src/jcrypto/csr.c:40-82, "
                    "src/jcert/jcert.c:159-163) instead of silently "
                    "returning a certificate or CSR with a partial or "
                    "empty subject, but " observed))))
