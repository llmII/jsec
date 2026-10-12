# Cert generation hygiene regression test
# Ticket a608a674bb8f5f24cd65bc5ae03cb56af0d87a1f
#
# "Certificate generation hygiene (serial=1, CN injection, Ed25519, SAN, CRL)"
#
# Mechanism (this tree, ticket branch off 0.2.0 at 599e82e288):
#   Part 1 - Serial hardcoded 1 / sequential. cfun_generate_self_signed_cert
#     stamps ASN1_INTEGER_set(X509_get_serialNumber(x509), 1)
#     (src/jcert/jcert.c:152), cfun_generate_self_signed_from_key repeats it
#     (src/jcert/jcert.c:341), and cfun_ca_generate hardcodes 1 for the CA's
#     own certificate (src/jca/types.c:420). Issued certificates take their
#     serial from ca_next_serial (src/jca/types.c:269-271), a plain
#     ca->serial++ counter consumed at src/jca/sign.c:178 and
#     src/jca/sign.c:365-366. Browsers reject a second certificate with
#     serial 1, and CABF BR 7.1 requires non-sequential serials carrying at
#     least 64 bits of entropy (fix shape: BN_rand).
#   Part 2 - CN injection into the SAN config string.
#     cfun_generate_self_signed_cert splices the caller's :common-name into
#     the X509V3 config value with snprintf(san_value, "IP:%s" / "DNS:%s",
#     cn) (src/jcert/jcert.c:193-212) and hands it to X509V3_EXT_conf_nid
#     (src/jcert/jcert.c:214-215); the same shape sits in
#     cfun_generate_self_signed_from_key (src/jcert/jcert.c:380-399). The CN
#     is attacker-controlled text inside OpenSSL config syntax: the strchr
#     (cn, ':') IP heuristic (src/jcert/jcert.c:198-206) sends a crafted CN
#     down the "IP:%s" splice so "9.9.9.9,DNS:injected.example" becomes two
#     SAN entries [IP:9.9.9.9, DNS:injected.example], and a crafted CN whose
#     second fragment is not valid config makes X509V3_EXT_conf_nid fail and
#     the SAN extension vanish behind the silent if (ext)
#     (src/jcert/jcert.c:216-219). Fix shape: GENERAL_NAMES /
#     X509V3_add1_i2d with the CN as one literal name.
#   Part 3 - Ed25519 signing fails. cfun_generate_self_signed_from_key
#     signs with a fixed digest, X509_sign(x509, pkey, EVP_sha256())
#     (src/jcert/jcert.c:414), and cfun_generate_csr does the same to
#     X509_REQ_sign (src/jcrypto/csr.c:117-125). Ed25519 is a pure
#     signature scheme that needs a NULL digest; OpenSSL rejects the digest
#     with "invalid digest" and the call fails. The correct pattern is
#     already in-tree in cfun_generate_self_signed_cert: md = NULL for
#     EVP_PKEY_ED25519 (src/jcert/jcert.c:230-232).
#   Part 4 - ca/issue no-SAN default and keyEncipherment for EC.
#     cfun_ca_issue only adds SAN entries when :san is supplied
#     (src/jca/sign.c:413-414) and cfun_ca_sign_csr only when :san or
#     :copy-extensions is supplied (src/jca/sign.c:197-233), so a
#     certificate issued for a CN carries no SAN at all and cannot serve
#     modern TLS hostname verification. Both paths stamp the same default
#     key usage "digitalSignature,keyEncipherment"
#     (src/jca/sign.c:402-403 and src/jca/sign.c:220-221) even for EC keys,
#     where keyEncipherment is meaningless (RFC 5480). Fix shape: default
#     the SAN to the CN; use EC-appropriate keyUsage.
#   Part 5 - CRL missing crlNumber and AKI. cfun_ca_generate_crl builds the
#     CRL (src/jca/crl.c:152-268) and signs it (src/jca/crl.c:272-275)
#     without ever adding a crlNumber extension (RFC 5280 5.2.3, required
#     of conformant CRL issuers) or an Authority Key Identifier
#     (RFC 5280 5.2.1). Fix shape: add both.
#
# This test demonstrates:
#   (a) independently generated certificates carry unique serial numbers
#       and issued serials are non-sequential: under the defect every
#       self-signed, from-key and CA certificate carries serial 1 and
#       ca/issue hands out 01, 02, 03 from its counter,
#   (b) the CN becomes exactly one SAN name: under the defect the crafted
#       CN "9.9.9.9,DNS:injected.example" injects a second SAN entry and
#       the crafted CN "evil.example, DNS:injected.example" silently loses
#       the SAN extension entirely,
#   (c) Ed25519 keys sign certificates and CSRs with a NULL digest: under
#       the defect both calls fail with OpenSSL "invalid digest" while the
#       in-tree NULL-digest path (generate-self-signed-cert :key-type
#       :ed25519) keeps working,
#   (d) ca/issue defaults the SAN to the CN and EC-keyed certificates get
#       EC-appropriate key usage: under the defect the issued certificate
#       has no SAN at all and both the issue and sign-csr paths stamp
#       keyEncipherment onto EC keys,
#   (e) a generated CRL carries crlNumber and Authority Key Identifier
#       extensions: under the defect openssl crl -text shows neither.
#
# Proof contract: under the defect each def-test fails with exactly the
# predicted symptom named in its assertion - duplicate serial 1 and the
# sequential 01, 02, 03 counter; the injected DNS:injected.example SAN and
# the silently dropped SAN; the two "invalid digest" raises; the SAN-less
# EC certificate carrying keyEncipherment; the CRL without crlNumber and
# AKI - and nothing else: no crash, no hang, no unrelated error. Under
# fixed code all five def-tests pass.

(use assay)
(import jsec/cert :as cert)
(import jsec/ca)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(defn- serial-of
  "Serial number of a certificate PEM as the hex string cert/parse reports."
  [pem]
  ((cert/parse pem) :serial))

(defn- hex->num
  "Parse a hex serial string (bare or colon-separated octets) into a number."
  [s]
  (scan-number (string "0x" (string/replace-all ":" "" s))))

(defn- san-entries
  "cert/parse :san as an array of strings (empty when the SAN is absent)."
  [pem]
  (def info (cert/parse pem))
  (if-let [san (info :san)] (map string san) @[]))

(defn- duplicate-note
  "One violation string when the labeled serials are not pairwise unique."
  [label serials]
  (if (< (length (distinct serials)) (length serials))
    [(string/format
       (string "%s all carry serial %q - serials must be unique per issuer "
               "(RFC 5280 4.1.2.2; browsers reject a second certificate "
               "with serial 1)")
       label (string/join serials ", "))]
    []))

(defn- adjacency-notes
  "Violation strings for serial pairs that are consecutive integers."
  [label serials]
  (seq [i :range [0 (length serials)]
        j :range [(+ i 1) (length serials)]
        :let [a (hex->num (serials i))
              b (hex->num (serials j))]
        :when (= b (+ a 1))]
    (string/format
      (string "%s assigned sequential serials %q then %q - serials must be "
              "non-sequential (CABF BR 7.1: at least 64 bits of entropy "
              "from a CSPRNG; fix shape BN_rand)")
      label (serials i) (serials j))))

(defn- run-child
  "Run a child program under this same janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  [program]
  (def proc (os/spawn [(dyn :executable) "-e" program] :p
                      {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

# Child programs for the Ed25519 part. Each runs in its own process so the
# OpenSSL error queue is clean at entry: jsec reports the OLDEST queued
# error (get_ssl_error_string uses ERR_get_error, src/jutils/error.c:24),
# so in-process the raise text would name whatever leftover an earlier
# test left behind instead of the signing failure itself.
(def- child-from-key-program
  ```
(import jsec/cert :as cert)
(import jsec/crypto :as crypto)
(def edkey (crypto/generate-key :ed25519))
(try
  (do
    (def c (cert/generate-self-signed-from-key edkey {:common-name "ed-cert.example"}))
    (if (cert/verify-signature c c)
      (print "RESULT:ok")
      (print "RESULT:unsigned")))
  ([err] (print "RESULT:error:" err)))
```)

(def- child-csr-program
  ```
(import jsec/crypto :as crypto)
(def edkey (crypto/generate-key :ed25519))
(try
  (do
    (def csr (crypto/generate-csr edkey {:common-name "ed-csr.example"}))
    (if (get (crypto/parse-csr csr) :signature-valid)
      (print "RESULT:ok")
      (print "RESULT:bad-signature")))
  ([err] (print "RESULT:error:" err)))
```)

(def-suite :name "Cert Generation Hygiene Regression"
  :description "Ticket a608a674bb: serial=1 duplicates and sequential counters, CN spliced into the SAN config string, Ed25519 invalid digest, ca/issue missing SAN and EC keyEncipherment, CRL missing crlNumber and AKI"

  (def-test "certificate serials are unique and non-sequential"
    :timeout 30

    # Three independent self-signed generations (src/jcert/jcert.c:152).
    (def ss1 (cert/generate-self-signed-cert
               {:common-name "serial-a.example" :key-type :ec-p256}))
    (def ss2 (cert/generate-self-signed-cert
               {:common-name "serial-b.example" :key-type :ec-p256}))
    (def ss3 (cert/generate-self-signed-cert
               {:common-name "serial-c.example" :key-type :ec-p256}))

    # Two self-signed certs from the SAME existing key
    # (src/jcert/jcert.c:341).
    (def one-key (crypto/generate-key :ec-p256))
    (def fk1 (cert/generate-self-signed-from-key
               one-key {:common-name "serial-d.example"}))
    (def fk2 (cert/generate-self-signed-from-key
               one-key {:common-name "serial-e.example"}))

    # Two root CA certificates (src/jca/types.c:420).
    (def ca1 (ca/generate {:common-name "Serial CA One" :key-type :ec-p256}))
    (def ca2 (ca/generate {:common-name "Serial CA Two" :key-type :ec-p256}))

    # Three issued leaves from one CA (src/jca/types.c:269-271 via
    # src/jca/sign.c:365-366).
    (def leaf1 (ca/issue ca1 {:common-name "s-leaf1.example"
                              :key-type :ec-p256}))
    (def leaf2 (ca/issue ca1 {:common-name "s-leaf2.example"
                              :key-type :ec-p256}))
    (def leaf3 (ca/issue ca1 {:common-name "s-leaf3.example"
                              :key-type :ec-p256}))

    (def violations @[])
    (array/concat violations
                  (duplicate-note
                    "cert/generate-self-signed-cert (src/jcert/jcert.c:152)"
                    (map |(serial-of ($ :cert)) [ss1 ss2 ss3])))
    (array/concat violations
                  (duplicate-note
                    "cert/generate-self-signed-from-key (src/jcert/jcert.c:341)"
                    [(serial-of fk1) (serial-of fk2)]))
    (array/concat violations
                  (duplicate-note
                    "ca/generate root certificates (src/jca/types.c:420)"
                    [(serial-of (ca/get-cert ca1))
                     (serial-of (ca/get-cert ca2))]))
    (array/concat violations
                  (adjacency-notes
                    "ca/issue (src/jca/types.c:269-271)"
                    [(serial-of (leaf1 :cert))
                     (serial-of (leaf2 :cert))
                     (serial-of (leaf3 :cert))]))

    (assert (empty? violations)
            (string (string "certificate serial numbers must be unique and "
                            "non-sequential: each certificate gets a fresh "
                            "random serial of at least 64 bits of entropy "
                            "(fix shape BN_rand), never the constant 1 "
                            "(src/jcert/jcert.c:152, src/jcert/jcert.c:341, "
                            "src/jca/types.c:420) and never the sequential "
                            "ca->serial++ counter (src/jca/types.c:269-271). "
                            "Observed: ")
                    (string/join violations "; "))))

  (def-test "the common name becomes exactly one SAN entry and is never spliced into the config string"
    :timeout 15

    # Control: a plain CN yields exactly one SAN entry.
    (def plain-cn "plain.example")
    (def plain (cert/generate-self-signed-cert
                 {:common-name plain-cn :key-type :ec-p256}))
    (def plain-san (san-entries (plain :cert)))
    (assert (deep= @[(string "DNS:" plain-cn)] plain-san)
            (string/format
              "control: a plain common name must yield exactly one SAN entry %q, got %q"
              [(string "DNS:" plain-cn)] plain-san))

    (def violations @[])

    # (a) Injection exhibit: the strchr(cn, ':') heuristic routes this CN
    # into the "IP:%s" splice (src/jcert/jcert.c:198-212) and the comma
    # becomes X509V3 config syntax, so the CN injects a second SAN name.
    (def inject-cn "9.9.9.9,DNS:injected.example")
    (def c-inj (cert/generate-self-signed-cert
                 {:common-name inject-cn :key-type :ec-p256}))
    (def inj-san (san-entries (c-inj :cert)))
    (def inj-expected @[(string "DNS:" inject-cn) (string "IP:" inject-cn)])
    (cond
      (not= 1 (length inj-san))
      (array/push violations
                  (string/format
                    (string "the :common-name was spliced into the X509V3 "
                            "SAN config value (src/jcert/jcert.c:209-215): "
                            "CN %q produced %d SAN entries %q where exactly "
                            "one entry naming the whole CN is required - "
                            "the CN must not be able to inject %q")
                    inject-cn (length inj-san) inj-san "DNS:injected.example"))
      (nil? (index-of (inj-san 0) inj-expected))
      (array/push violations
                  (string/format
                    (string "the SAN entry %q must be the whole common name "
                            "%q as one literal name (fix shape GENERAL_NAMES "
                            "/ X509V3_add1_i2d)")
                    (inj-san 0) inject-cn)))

    # (b) Silent-loss exhibit: a CN whose config-syntax fragment does not
    # parse makes X509V3_EXT_conf_nid fail and the whole SAN extension is
    # dropped behind the silent if (ext) (src/jcert/jcert.c:216-219).
    (def loss-cn "evil.example, DNS:injected.example")
    (def c-loss (cert/generate-self-signed-cert
                  {:common-name loss-cn :key-type :ec-p256}))
    (def loss-san (san-entries (c-loss :cert)))
    (def loss-expected @[(string "DNS:" loss-cn) (string "IP:" loss-cn)])
    (cond
      (not= 1 (length loss-san))
      (array/push violations
                  (string/format
                    (string "the SAN extension was dropped entirely for CN "
                            "%q: got %d SAN entries %q - a crafted common "
                            "name must not be able to silence the SAN "
                            "extension (X509V3_EXT_conf_nid failure is "
                            "swallowed by the silent if (ext) at "
                            "src/jcert/jcert.c:216-219)")
                    loss-cn (length loss-san) loss-san))
      (nil? (index-of (loss-san 0) loss-expected))
      (array/push violations
                  (string/format
                    (string "the SAN entry %q must be the whole common name "
                            "%q as one literal name (fix shape GENERAL_NAMES "
                            "/ X509V3_add1_i2d)")
                    (loss-san 0) loss-cn)))

    (assert (empty? violations)
            (string (string "the common name must become exactly one SAN "
                            "entry naming the whole CN literally; it must "
                            "never be spliced into the X509V3 config value "
                            "(src/jcert/jcert.c:209-215, "
                            "src/jcert/jcert.c:393-399) where config syntax "
                            "lets it inject names or kill the extension. "
                            "Observed: ")
                    (string/join violations "; "))))

  (def-test "ed25519 keys sign certificates and CSRs with a null digest"
    :timeout 30

    # Control (in-process): the in-tree NULL-digest pattern
    # (src/jcert/jcert.c:230-232) signs Ed25519 fine, so the failures below
    # are the digest argument, not the key type.
    (def control (cert/generate-self-signed-cert
                   {:common-name "ed-control.example" :key-type :ed25519}))
    (assert (cert/verify-signature (control :cert) (control :cert))
            "control: generate-self-signed-cert :key-type :ed25519 must sign and verify")

    # (a) cfun_generate_self_signed_from_key signs with EVP_sha256 at
    # src/jcert/jcert.c:414; (b) cfun_generate_csr signs with EVP_sha256 at
    # src/jcrypto/csr.c:117-125. Both run in child processes so each raise
    # message is the failure's own diagnostic.
    (def from-key-run (run-child child-from-key-program))
    (def csr-run (run-child child-csr-program))

    (def violations @[])
    (unless (string/find "RESULT:ok" (from-key-run :out))
      (array/push violations
                  (string/format
                    (string "cert/generate-self-signed-from-key must sign an "
                            "Ed25519 certificate using the NULL digest - "
                            "X509_sign at src/jcert/jcert.c:414 hands "
                            "EVP_sha256 to the Ed25519 key and the call "
                            "fails; the working NULL-digest pattern is at "
                            "src/jcert/jcert.c:230-232. Child reported: %s")
                    (string/trim (from-key-run :out)))))
    (unless (string/find "RESULT:ok" (csr-run :out))
      (array/push violations
                  (string/format
                    (string "crypto/generate-csr must sign an Ed25519 CSR "
                            "using the NULL digest - X509_REQ_sign at "
                            "src/jcrypto/csr.c:117-125 hands EVP_sha256 to "
                            "the Ed25519 key and the call fails. Child "
                            "reported: %s")
                    (string/trim (csr-run :out)))))

    (assert (empty? violations)
            (string (string "ed25519 signing must use the NULL digest and "
                            "succeed end to end: generate-self-signed-from-"
                            "key (src/jcert/jcert.c:414) and generate-csr "
                            "(src/jcrypto/csr.c:117-125) must pass NULL to "
                            "X509_sign / X509_REQ_sign for Ed25519 keys, "
                            "exactly like the working pattern at "
                            "src/jcert/jcert.c:230-232. Observed: ")
                    (string/join violations "; "))))

  (def-test "ca/issue defaults the SAN to the CN and EC certificates get EC-appropriate key usage"
    :timeout 15

    (def ca (ca/generate {:common-name "Hygiene CA" :key-type :ec-p256}))

    # (a) No :san given: the SAN must default to the CN.
    (def issued (ca/issue ca {:common-name "leaf.example"
                              :key-type :ec-p256}))
    (def info (cert/parse (issued :cert)))
    (def san (san-entries (issued :cert)))

    (def violations @[])
    (unless (index-of "DNS:leaf.example" san)
      (array/push violations
                  (string/format
                    (string "ca/issue without :san produced no SAN for its "
                            "common name: got %q where %q is required - an "
                            "issued certificate must default its SAN to the "
                            "CN (src/jca/sign.c:413-414 only add SAN entries "
                            "when :san is supplied) so it can serve TLS "
                            "hostname verification")
                    san "DNS:leaf.example")))

    # (b) EC key on the issue path: keyEncipherment is meaningless for EC
    # (RFC 5480) yet the default at src/jca/sign.c:402-403 stamps it.
    (def ku (info :key-usage))
    (when (and ku (index-of :key-encipherment ku))
      (array/push violations
                  (string/format
                    (string "ca/issue on an EC key stamped keyEncipherment "
                            "into the default key usage (src/jca/sign.c:"
                            "402-403): got %q - EC certificates must get "
                            "EC-appropriate key usage (keyEncipherment is "
                            "meaningless for EC keys, RFC 5480)")
                    ku)))
    (unless (and ku (index-of :digital-signature ku))
      (array/push violations
                  (string/format
                    "the issued EC certificate must keep :digital-signature in its key usage, got %q"
                    ku)))

    # The same default sits in the sign-csr path (src/jca/sign.c:220-221).
    (def eckey (crypto/generate-key :ec-p256))
    (def csr (crypto/generate-csr eckey {:common-name "csr-leaf.example"}))
    (def sinfo (cert/parse (ca/sign ca csr)))
    (def sku (sinfo :key-usage))
    (when (and sku (index-of :key-encipherment sku))
      (array/push violations
                  (string/format
                    (string "ca/sign-csr on an EC-key CSR stamped "
                            "keyEncipherment into the default key usage "
                            "(src/jca/sign.c:220-221): got %q - EC "
                            "certificates must get EC-appropriate key usage")
                    sku)))

    (assert (empty? violations)
            (string (string "ca/issue must default the SAN to the CN and "
                            "EC-keyed certificates must get EC-appropriate "
                            "key usage: no :san must not mean no SAN "
                            "(src/jca/sign.c:413-414) and the default key "
                            "usage must not include keyEncipherment for EC "
                            "keys (src/jca/sign.c:402-403, "
                            "src/jca/sign.c:220-221). Observed: ")
                    (string/join violations "; "))))

  (def-test "generated CRLs carry crlNumber and authority key identifier extensions"
    :timeout 15

    (def ca (ca/generate {:common-name "CRL Hygiene CA" :key-type :ec-p256}))
    (ca/revoke ca (int/s64 42) :key-compromise)
    (def crl-pem (ca/crl ca {:days-valid 7}))

    # jsec cannot parse CRL extensions, so inspect the generated CRL with
    # the OpenSSL CLI (as sanctioned by the ticket for this part).
    (def tag (string/join (map |(string/format "%02x" $) (os/cryptorand 8)) ""))
    (def crl-path (string "/tmp/jsec-crl-" tag ".pem"))
    (def out-path (string "/tmp/jsec-crl-" tag ".txt"))
    (defer (do (try (os/rm crl-path) ([_]))
               (try (os/rm out-path) ([_])))
      (spit crl-path crl-pem)
      (def exit (os/execute ["openssl" "crl" "-in" crl-path "-text"
                             "-noout" "-out" out-path] :p))
      (assert (= 0 exit)
              (string/format
                "openssl crl -text must be able to dump the generated CRL, exit status %d"
                exit))
      (def text (slurp out-path))

      (def violations @[])
      (unless (string/find "X509v3 CRL Number" text)
        (array/push violations
                    (string "the CRL carries no crlNumber extension "
                            "(RFC 5280 5.2.3 requires crlNumber in every "
                            "CRL; openssl crl -text shows no X509v3 CRL "
                            "Number; cfun_ca_generate_crl at "
                            "src/jca/crl.c:152-275 never adds one)")))
      (unless (string/find "X509v3 Authority Key Identifier" text)
        (array/push violations
                    (string "the CRL carries no Authority Key Identifier "
                            "extension (RFC 5280 5.2.1; openssl crl -text "
                            "shows no X509v3 Authority Key Identifier; "
                            "cfun_ca_generate_crl at src/jca/crl.c:152-275 "
                            "never adds one)")))
      (assert (empty? violations)
              (string "a generated CRL must carry crlNumber and Authority Key Identifier extensions. Observed: "
                      (string/join violations "; "))))))
