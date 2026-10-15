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


(defn- pem-der [pem]
  (def body @"")
  (each line (string/split "\n" pem)
    (unless (or (string/has-prefix? "-----" line) (empty? line))
      (buffer/push-string body (string/trim line))))
  (crypto/base64-decode (string body)))

(defn- trycall [f]
  (try {:returned (f)} ([err] {:raised err})))

(defn- der-len
  "Definite-form DER length at idx: returns [len next-idx]."
  [buf idx]
  (def b (in buf idx))
  (if (< b 0x80)
    [b (+ idx 1)]
    (do
      (def n (band b 0x7f))
      (var len 0)
      (var i (+ idx 1))
      (for k 0 n
        (set len (+ (* len 256) (in buf i)))
        (++ i))
      [len i])))

(defn- der-elem
  "One DER TLV at idx: returns {:tag t :start s :len n :end e}."
  [buf idx]
  (def tag (in buf idx))
  (def [len start] (der-len buf (+ idx 1)))
  {:tag tag :start start :len len :end (+ start len)})

(defn- der-children
  "All TLVs covering buf start..end."
  [buf start end]
  (var idx start)
  (def out @[])
  (while (< idx end)
    (def e (der-elem buf idx))
    (array/push out e)
    (set idx (e :end)))
  out)

(defn- serial-bytes
  "DER INTEGER content bytes for a non-negative serial."
  [n]
  (def b @"")
  (var x n)
  (if (zero? x) (buffer/push-byte b 0))
  (while (> x 0)
    (buffer/push-byte b (band x 0xff))
    (set x (brshift x 8)))
  (def rev (reverse b))
  (if (and (> (length rev) 0) (>= (get rev 0) 0x80))
    (string (string/from-bytes 0x00) (string rev))
    (string rev)))

(defn- crl-revoked-serials
  "The serial numbers of a PEM CRL's revoked entries, as DER content
   byte strings."
  [pem]
  (def der (pem-der pem))
  (def outer (der-elem der 0))
  (def tbs (first (der-children der (outer :start) (outer :end))))
  (def out @[])
  (each kid (der-children der (tbs :start) (tbs :end))
    (when (= (kid :tag) 0x30)
      (def entry-kids (der-children der (kid :start) (kid :end)))
      (when (and (seq [e :in entry-kids] (= (e :tag) 0x30)) (> (length entry-kids) 0)
                 (all |(= ($ :tag) 0x30) entry-kids))
        (each entry entry-kids
          (def fields (der-children der (entry :start) (entry :end)))
          (when (and (> (length fields) 0) (= ((first fields) :tag) 0x02))
            (def s (first fields))
            (def bytes @"")
            (for i (s :start) (s :end)
              (buffer/push-byte bytes (in der i)))
            (array/push out (string bytes)))))))
  out)

(defn- missing-serials
  "Requested serial numbers that never reached the signed CRL."
  [res serials]
  (if (res :raised)
    @[]
    (do
      (def present (crl-revoked-serials (res :returned)))
      (filter |(not (index-of (serial-bytes $) present)) serials))))


(def-suite :name "Discarded OpenSSL Errors Regression"
  :description "Discarded OpenSSL failures and silent option fallbacks must raise, never answer wrongly"

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
    (def gen
      (try {:returned (ca/generate {:common-name (string/repeat "A" 200)})}
           ([err] {:raised err})))
    (def iss
      (try {:returned (ca/issue root {:common-name "leaf.example"
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
                  " (the country entry was silently dropped)"))))
    (assert (and (not (nil? (gen :raised)))
                 (not (nil? (iss :raised))))
            (string "a subject entry OpenSSL rejects - a common name "
                    "over the length limit, a country code that is not "
                    "two characters - must raise at the failing call "
                    "(X509_NAME_add_entry_by_txt and its sibling "
                    "setters are used as bare statements at "
                    "src/jca/types.c:451-458, src/jca/sign.c:474-481, "
                    "src/jcert/jcert.c:159-163) instead of silently "
                    "returning a certificate with a partial or "
                    "empty subject, but " observed)))

  (def-test "generate-crl-must-not-omit-revocations"
    (def root (ca/generate {:common-name "CRL Root"}))
    (def array-res
      (trycall |(ca/crl root {:revoked @[{:serial 4660}
                                         {:serial 22136 :reason
                                          :key-compromise}]})))
    (def literal-res
      (trycall |(ca/crl root {:revoked [{:serial 17185}
                                        {:serial 25770 :reason
                                         :ca-compromise}]})))
    (def miss-array (missing-serials array-res [4660 22136]))
    (def miss-literal (missing-serials literal-res [17185 25770]))
    (def observed
      (string
        "revocations given in a mutable array "
        (if (array-res :raised)
          (string "raised " (describe (array-res :raised)))
          (if (empty? miss-array)
            "all reached the signed CRL"
            (string "were dropped from the signed CRL: serials "
                    (string/format "%q" miss-array))))
        "; revocations given in the bracketed literal form "
        (if (literal-res :raised)
          (string "raised " (describe (literal-res :raised)))
          (if (empty? miss-literal)
            "all reached the signed CRL"
            (string "were dropped from the signed CRL with no error: "
                    "serials " (string/format "%q" miss-literal)
                    " are missing, so a relying party treats a "
                    "revoked certificate as valid")))))
    (assert (and (or (not (nil? (array-res :raised)))
                     (empty? miss-array))
                 (or (not (nil? (literal-res :raised)))
                     (empty? miss-literal)))
            (string "ca/crl must place every revocation it was given "
                    "into the signed CRL, or raise at the first entry "
                    "it cannot place - the option is consumed only "
                    "when it is a mutable array at "
                    "src/jca/crl.c:195-198, the entry construction "
                    "and the appends at :272-291 are unchecked, and "
                    "the sort at :332 is unchecked - never a signed "
                    "CRL with revocations silently missing; but "
                    observed))))
