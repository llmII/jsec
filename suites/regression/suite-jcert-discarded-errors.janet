# Discarded OpenSSL failures in jcert - regression guards
#
# Six surfaces where a real OpenSSL failure is discarded and the caller
# gets a plausible but wrong answer instead of an error. The project
# rule is that real failures raise and nil/false is documented absence,
# never a failure signal.
#
# 1. cert/verify-signature (src/jcert/jcert.c:1050-1052): X509_verify
#    answers 1 for a valid signature, 0 for a well-formed invalid one,
#    and a negative value for a verification error (unsupported
#    signature algorithm, malformed signature encoding, allocation
#    failure). The return folds every non-1 outcome into false and
#    leaves the verification error on the thread's OpenSSL error queue.
# 2. cert/verify-chain trust inputs (src/jcert/verify.c:279-290 for the
#    :trusted entries, :305-319 for the CRL, :336-346 for the :chain
#    entries): an entry that does not parse is skipped, and the store
#    add returns at :285 and :313 are unchecked, so a corrupt entry is
#    silently omitted from the verification.
# 3. cert/verify-chain :trusted-dir (src/jcert/verify.c:292-303): the
#    return of the trust-directory load is discarded, so a wrong or
#    unreadable directory silently loads zero anchors.
# 4. cert/build-chain (src/jcert/verify.c:448-580): the issuer walk
#    returns nil when no issuer is found (:553-558) with no diagnosis,
#    and when the depth bound at :512 is exhausted it returns the
#    partial chain at :578 as if it reached a trusted root.
# 5. ca/crl (src/jca/crl.c:179-332): the :revoked option is consumed
#    only when it is a mutable array (:195-198), so revocations given
#    in the bracketed literal form are dropped without a word; the
#    entry construction and the appends are unchecked (:272-291) and
#    the sort at :332 is unchecked, so a failing step drops revocation
#    entries from the signed list silently.
# 6. cert/parse helpers (src/jcert/jcert.c:412-448 serial, :544-550
#    times, :581-628 subject alternative names, :631-707 usages,
#    :794-803 fingerprints): a failed conversion is mapped to nil or
#    zero, and an extension that fails to decode (:582-583) reports
#    exactly like one the certificate does not carry. Inside the name
#    walk an IP address entry of unexpected length is skipped (:613-
#    624) rather than reported.
#
# Each guard asserts the correct behaviour - the failure raises at the
# failing call, or is reported honestly - and fails on purpose with its
# predicted symptom; they become the regression guard after the fix
# lands.
#
# Not guarded here: the self-signed certificate builders swallow a
# failing fixed extension build (basicConstraints, keyUsage and subject
# key identifier at src/jcert/jcert.c:175-205 and :342-372 drop the
# extension when the build fails and ignore the add return). Those
# three configuration strings are constants, so the drop can only
# manifest when an allocation fails - not as a failing assertion
# without fault injection - and the user-controlled extension route
# this defect was originally seen through (a common name spliced into a
# subject alternative name configuration string) is gone: the names are
# attached as raw directory entries by jutils_add_common_name_san
# (src/jutils/cert_loading.c:314-348), whose failure raises.

(use assay)
(import jsec/cert)
(import jsec/ca)
(import jsec/crypto)
(import ../helpers :prefix "")

# ---------------------------------------------------------------------------
# DER and PEM helpers - certificates below are built directly so the
# pathological shapes (an unsupported signature algorithm, mutually
# issued certificates, an undecodable extension) can be expressed.
# ---------------------------------------------------------------------------

(defn- der-len-buf
  "Definite-form DER length bytes."
  [n]
  (if (< n 0x80)
    (string/from-bytes n)
    (do
      (var b @"")
      (var x n)
      (while (> x 0)
        (buffer/push-byte b (band x 0xff))
        (set x (brshift x 8)))
      (string (string/from-bytes (bor 0x80 (length b))) (string (reverse b))))))

(defn- tlv [tag content]
  (string (string/from-bytes tag) (der-len-buf (length content)) content))

(defn- pem-der [pem]
  (def body @"")
  (each line (string/split "\n" pem)
    (unless (or (string/has-prefix? "-----" line) (empty? line))
      (buffer/push-string body (string/trim line))))
  (crypto/base64-decode (string body)))

(defn- wrap64 [s]
  (var out @"")
  (var i 0)
  (while (< i (length s))
    (buffer/push-string out (string/slice s i (min (+ i 64) (length s))))
    (buffer/push-string out "\n")
    (+= i 64))
  (string out))

(defn- der-pem [der]
  (string "-----BEGIN CERTIFICATE-----\n"
          (wrap64 (crypto/base64-encode (string der)))
          "-----END CERTIFICATE-----\n"))

(defn- trycall [f]
  (try {:returned (f)} ([err] {:raised err})))

(defn- replace-all [s old new]
  (var out "")
  (var i 0)
  (while (def p (string/find old s i))
    (set out (string out (string/slice s i p) new))
    (set i (+ p (length old))))
  (string out (string/slice s i)))

(defn- outcome-text
  "Render an unparseable-input outcome for a guard message."
  [o what]
  (if (o :raised)
    (string "raised " (describe (o :raised)))
    (if (get (o :returned) :valid)
      (string "answered valid true with the unparseable " what
              " silently omitted from the verification")
      (string "answered valid false with "
              (describe (get (o :returned) :error))
              " - blaming a missing input for an unparseable " what))))

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

# Ed25519 algorithm identifier and a fixed public key - enough for
# X.509 parsing; the signature bytes below are never verified.
(def- ed-algid (tlv 0x30 (string/from-bytes 0x06 0x03 0x2b 0x65 0x70)))
(def- ed-spki
  (tlv 0x30 (string ed-algid
                    (tlv 0x03 (string (string/from-bytes 0x00)
                                     (string/repeat "\x01" 32))))))
(def- oid-cn (string/from-bytes 0x06 0x03 0x55 0x04 0x03))
(def- validity
  (tlv 0x30 (string (tlv 0x17 "200101000000Z") (tlv 0x17 "490101000000Z"))))

(defn- name-der [cn]
  (tlv 0x30 (tlv 0x31 (tlv 0x30 (string oid-cn (tlv 0x0c cn))))))

(defn- cert-der
  "A parseable certificate with the given subject and issuer names and
   an optional raw extensions block."
  [subject-cn issuer-cn &opt exts-content]
  (def tbs-core
    (string (tlv 0xa0 (tlv 0x02 (string/from-bytes 2)))
            (tlv 0x02 (string/from-bytes 1))
            ed-algid
            (name-der issuer-cn)
            validity
            (name-der subject-cn)
            ed-spki))
  (def tbs
    (if exts-content
      (string tbs-core (tlv 0xa3 (tlv 0x30 exts-content)))
      tbs-core))
  (tlv 0x30 (string (tlv 0x30 tbs) ed-algid
                    (tlv 0x03 (string (string/from-bytes 0x00)
                                     (string/repeat "\x00" 8))))))

(defn- san-ext [general-names-der]
  (tlv 0x30 (string (string/from-bytes 0x06 0x03 0x55 0x1d 0x11)
                    (tlv 0x04 general-names-der))))

(defn- missing-serials
  "Requested serial numbers that never reached the signed CRL."
  [res serials]
  (if (res :raised)
    @[]
    (do
      (def present (crl-revoked-serials (res :returned)))
      (filter |(not (index-of (serial-bytes $) present)) serials))))

(defn- queue-probe
  "Force a raise whose message quotes one OpenSSL error-queue entry."
  []
  (def out (trycall |(cert/fingerprint "not-a-cert")))
  (if (out :raised) (string (out :raised)) "no raise"))

(defn- queue-drain
  "Clear the thread's OpenSSL error queue: an empty :trusted list
   reaches the clear-after-loop at src/jcert/verify.c:289."
  []
  (try
    (cert/verify-chain (der-pem (cert-der "drain.example" "drain.example"))
                       {:trusted []})
    ([_] nil)))

(def-suite :name "jcert Discarded OpenSSL Errors Regression"
  :description "Discarded OpenSSL failures in jcert must raise or report honestly, never answer wrongly"

  (def-test "verify-signature-internal-error-must-raise"
    (def gen (cert/generate-self-signed-cert {:common-name "sig.example"
                                              :key-type :rsa :bits 1024}))
    (def cert-pem (gen :cert))
    # Swap the certificate's signature algorithm for an unassigned
    # OID of the same encoded length, in both the inner and outer
    # algorithm fields, so the certificate parses but the signature
    # cannot be evaluated at all.
    (def der (pem-der cert-pem))
    (def known-alg
      (string/from-bytes 0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x0b))
    (def unassigned-alg
      (string/from-bytes 0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x63))
    (def patched (der-pem (replace-all der known-alg unassigned-alg)))
    (queue-drain)
    (def outcome (trycall |(cert/verify-signature patched cert-pem)))
    (def residue (queue-probe))
    (queue-drain)
    (def observed
      (if (outcome :raised)
        (string "raised " (describe (outcome :raised)))
        (string "returned " (describe (outcome :returned))
                " - the same answer a genuinely wrong signature gets"
                (if (string/find "unknown signature algorithm" residue)
                  (string ", and left the verification error on the "
                          "thread's OpenSSL error queue, where a later "
                          "OpenSSL-using call reports "
                          (describe residue))
                  ""))))
    (assert (not (nil? (outcome :raised)))
            (string "cert/verify-signature on a certificate whose "
                    "signature algorithm is not supported must raise "
                    "with the OpenSSL error - the signature cannot be "
                    "evaluated at all - and return false only for a "
                    "well-formed invalid signature, because the "
                    "X509_verify result is folded to a boolean at "
                    "src/jcert/jcert.c:1050-1052 and a verification "
                    "error is indistinguishable from a wrong "
                    "signature; but it " observed)))

  (def-test "verify-chain-unparseable-input-must-raise"
    (def root (ca/generate {:common-name "Chain Root"}))
    (def root-pem (ca/get-cert root))
    (def leaf (ca/issue root {:common-name "chain-leaf.example"}))
    (def leaf-pem (leaf :cert))
    (def bad "garbage-not-a-certificate")
    (def trusted-res
      (trycall |(cert/verify-chain leaf-pem {:trusted [root-pem bad]})))
    (def chain-res
      (trycall |(cert/verify-chain leaf-pem {:trusted [root-pem]
                                             :chain [bad]})))
    (def crl-res
      (trycall |(cert/verify-chain leaf-pem {:trusted [root-pem]
                                             :crl bad})))
    (queue-drain)
    (def observed
      (string "an unparseable :trusted entry "
              (outcome-text trusted-res ":trusted entry")
              "; an unparseable :chain entry "
              (outcome-text chain-res ":chain entry")
              "; an unparseable :crl "
              (outcome-text crl-res ":crl")))
    (assert (and (not (nil? (trusted-res :raised)))
                 (not (nil? (chain-res :raised)))
                 (not (nil? (crl-res :raised))))
            (string "cert/verify-chain with an entry that does not "
                    "parse in :trusted, :chain or :crl must raise "
                    "naming the entry that failed to parse (the load "
                    "failures are skipped at src/jcert/verify.c:283-"
                    "289, :310-317 and :340-345 and the store add "
                    "returns at :285 and :313 are unchecked), instead "
                    "of silently verifying without it; but " observed)))

  (def-test "verify-chain-trusted-dir-load-failure-must-raise"
    (def root (ca/generate {:common-name "Dir Root"}))
    (def leaf (ca/issue root {:common-name "dir-leaf.example"}))
    (def outcome
      (trycall |(cert/verify-chain (leaf :cert)
                                   {:trusted-dir "/nonexistent-jsec-trust-dir"})))
    (queue-drain)
    (def observed
      (if (outcome :raised)
        (string "raised " (describe (outcome :raised)))
        (string "answered valid "
                (describe (get (outcome :returned) :valid))
                " with "
                (describe (get (outcome :returned) :error))
                " - the trust-directory load failed and the failure "
                "was discarded, so verification ran with zero "
                "anchors and never mentioned the directory")))
    (assert (not (nil? (outcome :raised)))
            (string "cert/verify-chain with a wrong or unreadable "
                    ":trusted-dir must raise naming the directory "
                    "(the load return at src/jcert/verify.c:297-303 "
                    "is discarded today), instead of quietly loading "
                    "zero anchors and letting verification blame its "
                    "own chain building; but it " observed)))

  (def-test "build-chain-failure-must-raise-not-nil-or-rootless"
    # Half one: no issuer anywhere - the walk returns nil.
    (def root (ca/generate {:common-name "Walk Root"}))
    (def leaf (ca/issue root {:common-name "walk-leaf.example"}))
    (def nil-res (trycall |(cert/build-chain (leaf :cert) [] [])))
    # Half two: two certificates that name each other as issuer - the
    # walk cycles until the depth bound runs out and returns the
    # partial chain as success.
    (def cert-a (der-pem (cert-der "A" "B")))
    (def cert-b (der-pem (cert-der "B" "A")))
    (def cycle-res (trycall |(cert/build-chain cert-a [cert-a cert-b] [])))
    (def observed
      (string "a leaf with no issuer anywhere "
              (if (nil-res :raised)
                (string "raised " (describe (nil-res :raised)))
                (string "returned " (describe (nil-res :returned))
                        " with no diagnosis"))
              "; and with two certificates that name each other as "
              "issuer and an empty trust set "
              (if (cycle-res :raised)
                (string "raised " (describe (cycle-res :raised)))
                (string "returned "
                        (describe (length (cycle-res :returned)))
                        " certificates as if a chain that never "
                        "reaches a trusted root were a valid chain"))))
    (assert (and (not (nil? (nil-res :raised)))
                 (not (nil? (cycle-res :raised))))
            (string "cert/build-chain must raise when it cannot "
                    "build a chain to a trusted root - naming the "
                    "subject and the depth the walk stopped at - and "
                    "must never return a chain that ends outside a "
                    "trusted root as success, but the walk returns "
                    "nil without a diagnosis at "
                    "src/jcert/verify.c:553-558 and returns the "
                    "partial chain at :578 when the depth bound at "
                    ":512 runs out; " observed)))

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
                    observed)))

  (def-test "parse-conversion-failure-must-not-read-as-absence"
    # An IP address entry of unexpected length inside an otherwise
    # sound subject alternative name extension.
    (def names-bad-ip
      (tlv 0x30 (string (tlv 0x82 "ok.example")
                        (tlv 0x87 "\x01\x02\x03\x04\x05"))))
    (def cert-bad-ip
      (der-pem (cert-der "ip.example" "ip.example" (san-ext names-bad-ip))))
    # A subject alternative name extension whose content does not
    # decode at all.
    (def names-truncated
      (string/from-bytes 0x30 0x05 0x82 0x01 0x41))
    (def cert-undecodable
      (der-pem (cert-der "g.example" "g.example" (san-ext names-truncated))))
    # The same shape with no extension at all - the lookalike outcome.
    (def cert-absent (der-pem (cert-der "n.example" "n.example")))
    (def ip-res (trycall |(cert/parse cert-bad-ip)))
    (def undec-res (trycall |(cert/parse cert-undecodable)))
    (def absent-res (trycall |(cert/parse cert-absent)))
    (def ip-san (if (ip-res :returned) (get (ip-res :returned) :san)))
    (def undec-san (if (undec-res :returned) (get (undec-res :returned) :san)))
    (def absent-san (if (absent-res :returned) (get (absent-res :returned) :san)))
    (def ip-reported
      (and ip-san (some |(string/find "IP:" $) ip-san)))
    (def undec-distinct
      (and (nil? (undec-res :raised))
           (not= undec-san absent-san)))
    (def observed
      (string
        "a certificate with a five-byte IP address entry "
        (if (ip-res :raised)
          (string "raised " (describe (ip-res :raised)))
          (string "returned :san "
                  (string/format "%q" ip-san)
                  " - the entry is dropped with no error"))
        "; a certificate whose subject alternative name extension "
        "does not decode "
        (if (undec-res :raised)
          (string "raised " (describe (undec-res :raised)))
          (string "returned no :san field at all, exactly like the "
                  "same certificate with no such extension (:san "
                  (string/format "%q" absent-san)
                  "), so a failed conversion is indistinguishable "
                  "from a field the certificate does not carry"))))
    (assert (and (or (not (nil? (ip-res :raised))) ip-reported)
                 (or (not (nil? (undec-res :raised))) undec-distinct))
            (string "cert/parse must raise when a field fails to "
                    "convert, and omit only fields a certificate "
                    "truly does not carry - the helpers at "
                    "src/jcert/jcert.c:412-448, :544-550, :581-628, "
                    ":631-707 and :794-803 map a failed conversion to "
                    "nil or zero, the extension read at :582-583 "
                    "cannot tell a decode failure from an absent "
                    "extension, and the IP address case at :613-624 "
                    "silently skips an entry of unexpected length; "
                    "but " observed))))
