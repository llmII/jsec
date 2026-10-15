# OCSP responder interoperability regression test
# Ticket 7ef15be7647934241ea593b645c5a75242b5b1e4
#
# "OCSP responder interoperability bugs (nonce double-wrap, SHA-1 CertID,
# unimplemented options)"
#
# Mechanism (this tree): ca/parse-ocsp-request returns the request's raw
# nonce extension value - the bytes of X509_EXTENSION_get_data, already an
# OCTET STRING wrapping the nonce (src/jca/ocsp.c:122-130) - and
# ca/create-ocsp-response hands those already-wrapped bytes to
# OCSP_basic_add1_nonce (src/jca/ocsp.c:334-335), which wraps them a second
# time. The same parse call discards the request CertID digest OID: the
# digest out-param of OCSP_id_get0_info is NULL (src/jca/ocsp.c:77), and
# ca/create-ocsp-response hardcodes EVP_sha1() in OCSP_cert_id_new
# (src/jca/ocsp.c:245), so a SHA-256 CertID request gets a SHA-1 CertID
# back. The documented :this-update and :next-update options
# (src/jca/ocsp.c:161-162) are never read - the option loop reads only
# :revocation-reason and :include-nonce (src/jca/ocsp.c:204-213) - and the
# response times are hardcoded to now and now plus one day
# (src/jca/ocsp.c:305-306).
#
# Fixture (following the tree's existing OCSP suite construction): a
# CA-issued leaf under a generated CA (ca/generate + ca/sign) - the
# established shape, because the OCSP machinery must key on a CA-issued
# serial and issuer hashes - and a real OCSP request built by the openssl
# CLI with a nonce and a SHA-256 CertID, then fed through
# ca/parse-ocsp-request exactly as a responder would. The leaf is issued
# through ca/sign with an explicit :serial so the fixture serial is
# fixed and fits the int64 :serial request-info path: ca/issue draws a
# fresh random 64-bit serial (src/jca/sign.c:458-463) which does not
# round-trip that path when it exceeds int64, and the full-CertID
# comparison needs an exact serial match rather than a flake on a
# serial-precision path outside this ticket's defects.
#
# One named guard per defect, each asserting the correct behaviour and
# each failing with its own predicted symptom under the defect:
#   (a) response-nonce-must-be-byte-identical-to-request-nonce: the echoed
#       nonce extension value must be the request value byte for byte -
#       the pair OCSP_check_nonce compares. Predicted symptom: the
#       response nonce is the request nonce wrapped in another OCTET
#       STRING, so the two are not byte-identical and the standard client
#       verdict is Nonce Verify error.
#   (b) response-cert-id-digest-must-match-request-cert-id-digest: the
#       response CertID must match the request CertID in full - digest
#       algorithm identifier plus issuer name hash, issuer key hash and
#       serial - not just the "Hash Algorithm:" line, because a
#       digest-name-only match passes while the response still fails
#       OCSP_id_cmp matching in clients. Predicted symptom: the response
#       CertID is a SHA-1 CertID - digest name and SHA-1 issuer name and
#       key hashes - where the request named SHA-256.
#   (c) this-update-and-next-update-options-must-be-honoured: the response
#       thisUpdate and nextUpdate must be the supplied :this-update and
#       :next-update values. Predicted symptom: they are now and now plus
#       one day instead of the supplied values.
#
# The OCSP_cert_to_id result that src/jca/ocsp.c:230 creates and
# src/jca/ocsp.c:238 frees is dead code (the cert ID actually used is
# built at src/jca/ocsp.c:245). It is recorded in the analysis and
# carries no guard here: it has no observable effect on the response.
#
# Proof contract: under the defect each guard fails with exactly its
# predicted symptom and nothing else (no crash, no hang, no unrelated
# error); under fixed code each guard passes.

(use assay)
(import jsec/ca :as ca)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(defn- abspath
  "Absolute path for a possibly-relative scratch path."
  [p]
  (if (string/has-prefix? "/" p) p (string (os/cwd) "/" p)))

(defn- write-pem
  "Write PEM text to a file under the given scratch dir; returns its path."
  [dir name pem]
  (def path (abspath (string dir "/" name)))
  (spit path pem)
  path)

(defn- openssl
  ``Run the openssl CLI and return its combined stdout and stderr text.``
  [& args]
  (def proc (os/spawn ["openssl" ;args] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))
  (os/proc-wait proc)
  (:close (proc :out))
  (:close (proc :err))
  (string out-buf "\n" err-buf))

(defn- build-request
  ``CA-issued fixture plus a real openssl-built OCSP request carrying a
   nonce and a SHA-256 CertID, parsed the way a responder parses it.
   Returns the root CA, the scratch dir, the paths and the request-info.``
  [dir]
  (def root (ca/generate {:common-name "jsec ocsp interop root"
                          :days-valid 2 :serial 1}))
  (def key-pem (crypto/generate-key :rsa 2048))
  (def csr-pem (crypto/generate-csr key-pem {:common-name "localhost"}))
  (def leaf-pem (ca/sign root csr-pem {:days-valid 2 :serial 4660}))
  (def root-path (write-pem dir "root.pem" (ca/get-cert root)))
  (def leaf-path (write-pem dir "leaf.pem" leaf-pem))
  (def req-path (abspath (string dir "/req.der")))
  (def gen-out (openssl "ocsp" "-sha256" "-issuer" root-path "-cert" leaf-path
                        "-nonce" "-reqout" req-path))
  (unless (os/stat req-path)
    (error (string "openssl failed to build the OCSP request: " gen-out)))
  {:root root
   :dir dir
   :root-path root-path
   :req-path req-path
   :req-der (slurp req-path)
   :info (ca/parse-ocsp-request (slurp req-path))})

(defn- request-text
  "openssl ocsp text dump of a DER request file."
  [req-path]
  (openssl "ocsp" "-reqin" req-path "-req_text"))

(defn- response-text
  "openssl ocsp text dump of a DER response file."
  [resp-path]
  (openssl "ocsp" "-respin" resp-path "-resp_text" "-noverify"))

(defn- nonce-hex
  ``The hex-encoded nonce extension value from an openssl ocsp text dump,
   or nil when the dump names no nonce.``
  [text]
  (var seen false)
  (var hex nil)
  (each line (string/split "\n" text)
    (cond
      (string/find "OCSP Nonce" line) (set seen true)
      (and seen (nil? hex))
      (do
        (def t (string/trim line))
        (when (and (> (length t) 0) (string/check-set "0123456789ABCDEFabcdef" t))
          (set hex t)))))
  hex)

(defn- certid-fields
  ``The full Certificate ID - digest algorithm name, issuer name hash,
   issuer key hash and serial - from the Certificate ID block of an
   openssl ocsp text dump, or nil when the block is absent or incomplete.
   Scraping stops at the block's end so a later embedded certificate's
   own Serial Number line cannot be picked up.``
  [text]
  (var in-id false)
  (var alg nil)
  (var name-hash nil)
  (var key-hash nil)
  (var serial nil)
  (each line (string/split "\n" text)
    (cond
      (string/find "Certificate ID" line) (set in-id true)
      (or (string/find "Cert Status:" line)
          (string/find "Request Extensions:" line)) (set in-id false)
      (and in-id (nil? alg) (string/find "Hash Algorithm:" line))
      (set alg (string/trim (last (string/split "Hash Algorithm:" line))))
      (and in-id (nil? name-hash) (string/find "Issuer Name Hash:" line))
      (set name-hash
           (string/trim (last (string/split "Issuer Name Hash:" line))))
      (and in-id (nil? key-hash) (string/find "Issuer Key Hash:" line))
      (set key-hash
           (string/trim (last (string/split "Issuer Key Hash:" line))))
      (and in-id (nil? serial) (string/find "Serial Number:" line))
      (set serial
           (string/trim (last (string/split "Serial Number:" line))))))
  (when (and alg name-hash key-hash serial)
    {:alg alg :name-hash name-hash :key-hash key-hash :serial serial}))

(defn- certid-line
  "One-line rendering of scraped CertID fields for error text."
  [id]
  (if id
    (string (id :alg) "/" (id :name-hash) "/" (id :key-hash) "/" (id :serial))
    "(none)"))

(defn- update-field
  ``The decoded time after the given label (like "This Update:") from an
   openssl ocsp text dump, or nil when the label is absent.``
  [text label]
  (var v nil)
  (each line (string/split "\n" text)
    (when (and (nil? v) (string/find label line))
      (set v (string/trim (last (string/split label line))))))
  v)

(defn- nonce-verdict
  ``The verdict an openssl client reaches on the echoed nonce - the
   OCSP_check_nonce comparison of the request and response values.``
  [req-path resp-path root-path]
  (def out (openssl "ocsp" "-reqin" req-path "-respin" resp-path
                    "-CAfile" root-path "-no_cert_checks"))
  (cond
    (string/find "Nonce Verify OK" out) "Nonce Verify OK"
    (string/find "Nonce Verify error" out) "Nonce Verify error"
    (string "no nonce verdict (probe output: " (string/trim out) ")")))

(defn- generalized-time
  ``UTC GeneralizedTime encoding (YYYYMMDDHHMMSSZ) for a unix timestamp;
   os/date reports month and month-day zero-based.``
  [ts]
  (def d (os/date ts))
  (string/format "%04d%02d%02d%02d%02d%02dZ"
                 (d :year) (inc (d :month)) (inc (d :month-day))
                 (d :hours) (d :minutes) (d :seconds)))

(def-suite :name "OCSP Responder Interop Regression"
  :description "Ticket 7ef15be7647934241ea593b645c5a75242b5b1e4: the echoed nonce, the CertID digest and the update times must follow the request and the supplied options"

  (def-test "response-nonce-must-be-byte-identical-to-request-nonce"
    :timeout 60

    (def fx (build-request (scratch-dir)))
    (def resp (ca/create-ocsp-response (fx :root) (fx :info) :good))
    (def resp-path (write-pem (fx :dir) "resp.der" resp))
    (def req-hex (nonce-hex (request-text (fx :req-path))))
    (def resp-hex (nonce-hex (response-text resp-path)))
    (def verdict (nonce-verdict (fx :req-path) resp-path (fx :root-path)))
    (assert (and req-hex resp-hex (= req-hex resp-hex))
            (string/format
              (string "the echoed nonce extension value must be "
                      "byte-identical to the request nonce value (the "
                      "pair OCSP_check_nonce compares): "
                      "ca/parse-ocsp-request returns the raw nonce "
                      "extension value, already an OCTET STRING wrapping "
                      "the nonce (src/jca/ocsp.c:122-130), and "
                      "ca/create-ocsp-response passes those "
                      "already-wrapped bytes to OCSP_basic_add1_nonce "
                      "(src/jca/ocsp.c:334-335) which wraps them a second "
                      "time; the request nonce extension value is %s but "
                      "the response carries %s (the request value wrapped "
                      "in another OCTET STRING), and the standard client "
                      "verdict is %s")
              (or req-hex "(no nonce)") (or resp-hex "(no nonce)") verdict)))

  (def-test "response-cert-id-digest-must-match-request-cert-id-digest"
    :timeout 60

    (def fx (build-request (scratch-dir)))
    (def resp (ca/create-ocsp-response (fx :root) (fx :info) :good))
    (def resp-path (write-pem (fx :dir) "resp.der" resp))
    (def req-id (certid-fields (request-text (fx :req-path))))
    (def resp-id (certid-fields (response-text resp-path)))
    (assert (and req-id (= (req-id :alg) "sha256") (= resp-id req-id))
            (string/format
              (string "the response CertID must match the request CertID "
                      "in full - digest algorithm identifier plus issuer "
                      "name hash, issuer key hash and serial - not just "
                      "the digest name, because a digest-name-only match "
                      "passes while the response still fails OCSP_id_cmp "
                      "matching in clients: ca/parse-ocsp-request "
                      "discards the request CertID digest OID (the digest "
                      "out-param of OCSP_id_get0_info is NULL at "
                      "src/jca/ocsp.c:77) and ca/create-ocsp-response "
                      "hardcodes EVP_sha1() in OCSP_cert_id_new "
                      "(src/jca/ocsp.c:245), so a SHA-256 CertID request "
                      "gets a SHA-1 CertID back; the request CertID is "
                      "%s but the response CertID is %s")
              (certid-line req-id) (certid-line resp-id))))

  (def-test "this-update-and-next-update-options-must-be-honoured"
    :timeout 60

    # 2001-09-09 01:46:40 UTC and the same instant one day later.
    (def this-ts 1000000000)
    (def next-ts (+ this-ts 86400))
    (def expect-this (generalized-time this-ts))
    (def expect-next (generalized-time next-ts))
    (def fx (build-request (scratch-dir)))
    (def resp (ca/create-ocsp-response (fx :root) (fx :info) :good
                                       {:this-update this-ts
                                        :next-update next-ts}))
    (def resp-path (write-pem (fx :dir) "resp.der" resp))
    (def text (response-text resp-path))
    (def actual-this (or (update-field text "This Update:") "(none)"))
    (def actual-next (or (update-field text "Next Update:") "(none)"))
    (def resp-str (string resp))
    (assert (and (string/find expect-this resp-str)
                 (string/find expect-next resp-str))
            (string/format
              (string "the response thisUpdate and nextUpdate must be "
                      "the supplied :this-update and :next-update "
                      "values: the options are documented "
                      "(src/jca/ocsp.c:161-162) but never read - the "
                      "option loop reads only :revocation-reason and "
                      ":include-nonce (src/jca/ocsp.c:204-213) - and the "
                      "response times are hardcoded to now and now plus "
                      "one day (src/jca/ocsp.c:305-306); the response "
                      "carries thisUpdate %s and nextUpdate %s (now and "
                      "now plus one day) instead of the supplied %s and "
                      "%s")
              actual-this actual-next expect-this expect-next))))
