# CSR SAN entry and :digest validation regression test
# Ticket 2d5d4382d7b4b4413e6dfb4128cbcc7588099fac
#
# "Validate SAN entries, extension creation, and :digest option in crypto/generate-csr"
#
# Mechanism (this tree, branch ticket-2d5d4382d7... off 0.2.0 at 2eef29afaf):
# cfun_generate_csr (src/jcrypto/csr.c) builds SubjectAltName and picks
# the signature digest with silent-failure paths:
#   - src/jcrypto/csr.c:88-90  a non-nil :san that is neither tuple nor
#     array is silently ignored - the CSR is signed with no SAN at all;
#   - src/jcrypto/csr.c:99-104 the :san entries are comma-joined into one
#     value string; non-string entries are silently skipped (:100) while
#     the separator keys on the array index (:102), so a skipped index-0
#     entry yields a leading comma;
#   - src/jcrypto/csr.c:109-116 the whole joined string is handed to one
#     X509V3_EXT_conf_nid call: a bare hostname/IP literal, an entry
#     containing a comma, or the malformed comma list makes it return
#     NULL, and :114-116 silently clear the error and emit the signed
#     CSR with NO SubjectAltName extension at all;
#   - src/jcrypto/csr.c:112-113 sk_X509_EXTENSION_push and
#     X509_REQ_add_extensions return values are ignored;
#   - src/jcrypto/csr.c:122-128 :digest accepts only a keyword and only
#     when EVP_get_digestbyname resolves it (:124-127): a string digest,
#     a non-keyword/string, and an unknown digest all silently fall back
#     to SHA-256.
# The ruled fix (2026-10-11, INDEX.org Ruling 3.1a) validates :san
# entry-by-entry - non-empty tuple/array of strings, prefixed and bare
# DNS/IP literals canonicalised like the jca builders - raises
# [CRYPTO:PARAM] on any non-string element or invalid container, checks
# the extension push/add returns, and raises [CRYPTO:PARAM] on an
# invalid or unknown :digest instead of falling back.
#
# This test demonstrates:
#   (a) bare and prefixed SAN entries round-trip through generate-csr
#       and ca/sign :copy-extensions into cert/parse exactly
#       (canonicalised: bare DNS/IP literals gain DNS:/IP: prefixes),
#       including an entry that contains a comma,
#   (b) non-string SAN entries and invalid :san containers are rejected
#       with a [CRYPTO:PARAM] error naming the offending entry,
#   (c) an unknown or non-keyword/string :digest raises [CRYPTO:PARAM]
#       instead of silently signing with SHA-256, and a string digest is
#       honoured exactly like its keyword spelling.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - (a) "the CSR was
# signed with no SubjectAltName extension at all", (b) "silently
# skipped/ignored ... emitted a signed CSR instead of raising
# [CRYPTO:PARAM]", (c) "silently fell back to SHA-256" - and nothing
# else: no crash, no unrelated error. Under fixed code every test
# passes.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import jsec/ca)
(import ../helpers :prefix "")

(def key (crypto/generate-key :rsa 2048))
(def authority (ca/generate {:common-name "csr-san-digest-regression-ca"
                             :days-valid 30}))

(defn- csr-san-roundtrip
  "Generate a CSR with :san, sign it with :copy-extensions, and return
   the SAN list cert/parse reads back (nil when no SAN extension)."
  [san]
  (def csr (crypto/generate-csr key {:common-name "csr-san-digest-regression.local"
                                     :san san}))
  (def signed (ca/sign authority csr {:copy-extensions true :days-valid 10}))
  (get (cert/parse signed) :san))

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

(def-suite :name "CSR SAN And Digest Validation Regression"
  :description "Ticket 2d5d4382d7: generate-csr validates :san entries and :digest instead of silently dropping the SAN extension or falling back to SHA-256"

  (def-test "bare-and-prefixed-san-entries-round-trip-into-the-csr"
    :timeout 60

    # Bare DNS/IP literals (accepted by the jca builders), prefixed
    # entries, an entry containing a comma, and an email entry must all
    # survive as exactly the canonical entries.
    (def san ["example.com"
              "127.0.0.1"
              "DNS:b.example.com"
              "URI:https://x.example.com/a,b"
              "email:user@example.com"])
    (def expected ["DNS:example.com"
                   "IP:127.0.0.1"
                   "DNS:b.example.com"
                   "URI:https://x.example.com/a,b"
                   "EMAIL:user@example.com"])
    (def got (csr-san-roundtrip san))
    (assert (and got (deep= (tuple ;got) (tuple ;expected)))
            (string/format
              (string "generate-csr silently dropped the SubjectAltName "
                      "extension for SAN entries %q: the CSR was signed "
                      "with no SubjectAltName extension at all (parsed "
                      ":san %q). src/jcrypto/csr.c:99-110 comma-joins "
                      "every entry into one value string and hands it to "
                      "a single X509V3_EXT_conf_nid call, which returns "
                      "NULL for a bare hostname/IP literal or an entry "
                      "containing a comma; src/jcrypto/csr.c:114-116 "
                      "clears the error and drops the extension "
                      "silently. Expected the canonical SAN list %q")
              (string/format "%q" san) (short-q got)
              (string/format "%q" expected))))

  (def-test "non-string-and-invalid-container-san-entries-raise-parameter-error"
    :timeout 60

    # A non-string element must be rejected with [CRYPTO:PARAM] naming
    # the entry - not silently skipped.
    (var outcome (capture-error
                   (fn [] (crypto/generate-csr key
                                         {:common-name "csr-san-digest-regression.local"
                                          :san ["DNS:ok.example.com" :bad]}))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARAM" (get outcome 1)))
            (string/format
              (string "generate-csr silently skipped the non-string SAN "
                      "entry :bad and emitted a signed CSR instead of "
                      "raising [CRYPTO:PARAM]: got %q. "
                      "src/jcrypto/csr.c:100 continues past non-string "
                      "entries without a signal")
              (short-q outcome)))

    # A leading non-string entry must likewise be rejected - today its
    # skip plus the index-keyed separator at :102 builds a leading
    # comma that fails the extension outright.
    (set outcome (capture-error
                   (fn [] (crypto/generate-csr key
                                         {:common-name "csr-san-digest-regression.local"
                                          :san [:bad "DNS:b.example.com"]}))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARAM" (get outcome 1)))
            (string/format
              (string "generate-csr did not raise [CRYPTO:PARAM] for a "
                      "leading non-string SAN entry: got %q. Under the "
                      "defect the entry is silently skipped and the "
                      "index-keyed comma at src/jcrypto/csr.c:102 "
                      "prepends a leading ',' that fails "
                      "X509V3_EXT_conf_nid, and the CSR is emitted with "
                      "no SubjectAltName extension at all")
              (short-q outcome)))

    # A :san that is not a tuple/array at all must be rejected - today
    # src/jcrypto/csr.c:88-90 ignores it and signs a CSR without SAN.
    (set outcome (capture-error
                   (fn [] (crypto/generate-csr key
                                         {:common-name "csr-san-digest-regression.local"
                                          :san "DNS:a.example.com"}))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARAM" (get outcome 1)))
            (string/format
              (string "generate-csr did not raise [CRYPTO:PARAM] for a "
                      "string :san container: got %q. Under the defect "
                      "src/jcrypto/csr.c:88-90 silently ignores a "
                      "non-nil :san that is neither tuple nor array and "
                      "the CSR is signed with no SubjectAltName "
                      "extension at all")
              (short-q outcome)))

    # An empty container must be rejected - today the san_len guard at
    # :95 silently emits the CSR with no extension.
    (set outcome (capture-error
                   (fn [] (crypto/generate-csr key
                                         {:common-name "csr-san-digest-regression.local"
                                          :san []}))))
    (assert (and (tuple? outcome)
                 (= :raised (get outcome 0))
                 (string/find "CRYPTO:PARAM" (get outcome 1)))
            (string/format
              (string "generate-csr did not raise [CRYPTO:PARAM] for an "
                      "empty :san container: got %q. Under the defect "
                      "src/jcrypto/csr.c:95 silently skips the "
                      "extension and the CSR is signed with no "
                      "SubjectAltName at all")
              (short-q outcome))))

  (def-test "unknown-or-invalid-digest-raises-parameter-error"
    :timeout 60

    (each d [:not-a-real-digest "not-a-real-digest" 42]
      (var outcome (capture-error
                     (fn [] (crypto/generate-csr key
                                           {:common-name "csr-san-digest-regression.local"
                                            :digest d}))))
      (assert (and (tuple? outcome)
                   (= :raised (get outcome 0))
                   (string/find "CRYPTO:PARAM" (get outcome 1)))
              (string/format
                (string "generate-csr silently fell back to SHA-256 for "
                        ":digest %q instead of raising [CRYPTO:PARAM]: "
                        "got %q. src/jcrypto/csr.c:122-128 reads only a "
                        "keyword and only when EVP_get_digestbyname "
                        "resolves it; every other non-nil value is "
                        "dropped on the floor and the CSR is signed "
                        "with the default SHA-256 digest")
                (string/format "%q" d) (short-q outcome)))))

  (def-test "string-digest-is-honoured-like-its-keyword-spelling"
    :timeout 60

    # A string digest must select the same digest as its keyword
    # spelling: RSA PKCS#1 v1.5 signatures are deterministic, so the two
    # CSRs must be byte-identical and must differ from the SHA-256
    # default.
    (def opts {:common-name "csr-san-digest-regression.local"})
    (def by-string (crypto/generate-csr key (merge opts {:digest "sha512"})))
    (def by-keyword (crypto/generate-csr key (merge opts {:digest :sha512})))
    (def by-default (crypto/generate-csr key opts))
    (assert (= by-string by-keyword)
            (string/format
              (string "generate-csr ignored the string digest \"sha512\": "
                      "the string form signed a different CSR than the "
                      "keyword form (they must be byte-identical). "
                      "src/jcrypto/csr.c:124 checks only JANET_KEYWORD, "
                      "so a string :digest silently falls back to the "
                      "SHA-256 default at :122 - the silent fallback "
                      "symptom; string CSR %q vs keyword CSR %q")
              (short-q by-string)
              (short-q by-keyword)))
    (assert (not= by-string by-default)
            (string/format
              (string "the \"sha512\" digest CSR is byte-identical to the "
                      "SHA-256 default CSR: the digest option was "
                      "silently ignored and the fallback signed with "
                      "SHA-256; CSR %q")
              (string/format "%q" by-string)))))
