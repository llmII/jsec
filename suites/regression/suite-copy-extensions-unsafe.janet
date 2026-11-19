# Copy extensions unsafe regression test
# Ticket c0077b4d15adb289ac16eec11f72744543d7a999
#
# ":copy-extensions produces invalid and attacker-influenced certificates"
#
# Mechanism (this tree, 0.2.0 basis):
#   ca_sign_csr's :copy-extensions path (src/jca/sign.c:196-206) copies
#   EVERY extension of the CSR into the certificate at
#   src/jca/sign.c:202 BEFORE jsec appends its own extensions at
#   src/jca/sign.c:209-233. There is no whitelist and no strip of an
#   already-present NID, so:
#     - every CSR extension is duplicated: jsec's own basicConstraints
#       ("CA:FALSE", src/jca/sign.c:209-210) lands next to the CSR's
#       copy, and jsec's own keyUsage (src/jca/sign.c:217 or the
#       default at src/jca/sign.c:220-221) lands next to the CSR's
#       copy - RFC 5280 allows at most one extension of each NID,
#     - an attacker submitting a CSR can smuggle critical constraints
#       into the issued certificate: basicConstraints CA:TRUE and
#       keyUsage keyCertSign from the CSR survive verbatim (and first,
#       so any first-wins reader sees the attacker's values).
#   The ca_add_extension return values are unchecked at
#   src/jca/sign.c:209-233 (and src/jca/types.c:447-452, :597-602), so
#   even a failed append is silent. Separately, :not-before and
#   :not-after are documented at src/jca/sign.c:76-77 but never read:
#   validity is hardcoded at src/jca/sign.c:183-185 (that doc gap is
#   recorded in the ticket ledger, not asserted here).
#
# This test demonstrates:
#   (a) a CSR carrying basicConstraints CA:TRUE and keyUsage
#       keyCertSign, signed with :copy-extensions true, yields a
#       certificate with DUPLICATE extensions (two basicConstraints,
#       two keyUsage) and with the attacker-copied critical constraints
#       present - basicConstraints is not CA:FALSE-only and keyUsage
#       still carries keyCertSign,
#   (b) under the fixed shape (whitelist SAN/EKU as copyable, strip
#       existing NIDs before appending jsec's own, check every
#       ca_add_extension return) the same call yields exactly one
#       basicConstraints, CA:FALSE, exactly one keyUsage, no
#       keyCertSign, and no extension OID duplicated - and every guard
#       here passes.
#
# Proof contract: under the defect each guard fails with the counts and
# the attacker constraint names shown in its message; under the fix the
# resulting certificate has one CA:FALSE basicConstraints, no
# attacker-copied constraints, and the whole suite is green.
#
# Observation channel: cert/parse cannot exhibit the defect - OpenSSL's
# X509_get_ext_d2i refuses duplicate-NID extensions (returns none), so
# :is-ca reads false and :key-usage reads nil even under the defect.
# The guards therefore count extensions at the DER level: the PEM body
# is base64-decoded (crypto/base64-decode) and the certificate's [3]
# extensions field is walked with a minimal DER TLV reader below, which
# yields every extension OID, its critical flag, and its extnValue
# body.

(use assay)
(import jsec/ca :as ca)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

# Attacker CSR fixture (generated once with the openssl CLI):
#   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
#     -keyout attacker-key.pem -out attacker-csr.pem \
#     -subj "/CN=attacker.example/O=Attacker Org" \
#     -addext "basicConstraints=critical,CA:TRUE" \
#     -addext "keyUsage=critical,keyCertSign,cRLSign" -nodes
# The CSR is self-signed with its own key; only its public key and its
# REQUESTED EXTENSIONS matter to ca/sign.
(def- attacker-csr
  ```
-----BEGIN CERTIFICATE REQUEST-----
MIIBHjCBxgIBADAyMRkwFwYDVQQDDBBhdHRhY2tlci5leGFtcGxlMRUwEwYDVQQK
DAxBdHRhY2tlciBPcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASyJBwHZv1P
EmvlwqCjDl3eMifVAQvNQEE/IzeUhu1tjt0dkX4s4YELwXNXGTojhwFt2bwzrWFq
fbIVx+O00Zb0oDIwMAYJKoZIhvcNAQkOMSMwITAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiBlMOblM0dExvPHMVydO+zG
Wd5MA94nlc3S5kW2mCV7ZQIgJF2oDC5p2HA+BP2IAslkmV2ZGi+u+7nSBLokrWSn
JgI=
-----END CERTIFICATE REQUEST-----
```)

# 2.5.29.19 basicConstraints, 2.5.29.15 keyUsage, as DER OID content bytes.
(def- oid-basic-constraints "551d13")
(def- oid-key-usage "551d0f")

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

(defn- oid-key
  "OID content bytes as a lowercase hex string, for comparison."
  [buf e]
  (def s @"")
  (for i (e :start) (+ (e :start) (e :len))
    (buffer/push-string s (string/format "%02x" (in buf i))))
  (string s))

(defn- cert-extensions
  "Walk a certificate PEM and return every X.509v3 extension as a table
   {:oid <hex> :crit <bool> :val <body bytes>}."
  [pem]
  (def body @"")
  (each line (string/split "\n" pem)
    (unless (or (string/has-prefix? "-----" line) (empty? line))
      (buffer/push-string body (string/trim line))))
  (def der (crypto/base64-decode (string body)))
  (def cert (der-elem der 0))
  (def tbs (first (der-children der (cert :start) (cert :end))))
  (def tbs-kids (der-children der (tbs :start) (tbs :end)))
  (def exts-tag (find |(= ($ :tag) 0xa3) tbs-kids))
  (assert exts-tag "no [3] extensions field in TBS")
  (def exts-seq (first (der-children der (exts-tag :start) (exts-tag :end))))
  (def out @[])
  (each x (der-children der (exts-seq :start) (exts-seq :end))
    (def kids (der-children der (x :start) (x :end)))
    (def oid (first kids))
    (var crit false)
    (var val nil)
    (each k (drop 1 kids)
      (case (k :tag)
        0x01 (set crit (not= 0 (in der (k :start))))
        0x04 (set val (string/slice der (k :start) (k :end)))))
    (array/push out {:oid (oid-key der oid) :crit crit :val val}))
  out)

(defn- count-oid
  [exts oid]
  (count |(= (in $ :oid) oid) exts))

(defn- bc-says-ca-true
  "True when a basicConstraints extnValue body encodes CA:TRUE. body is
   the extnValue OCTET STRING content: a SEQUENCE of optional BOOLEAN ca
   and optional INTEGER pathlen."
  [body]
  (def seq-e (der-elem body 0))
  (def kids (der-children body (seq-e :start) (seq-e :end)))
  (var truthy false)
  (each k kids
    (when (and (= (k :tag) 0x01) (not= 0 (in body (k :start))))
      (set truthy true)))
  truthy)

(defn- ku-says-key-cert-sign
  "True when a keyUsage extnValue body has the keyCertSign bit (bit 5).
   body is the extnValue OCTET STRING content: a BIT STRING TLV whose
   content is the unused-bits count byte followed by the data bytes."
  [body]
  (def e (der-elem body 0))
  (def data-start (+ (e :start) 1))
  (and (> (e :len) 1)
       (not= 0 (band (in body data-start) 0x04))))

(defn- sign-attacker-csr
  "Issue from the attacker CSR fixture with :copy-extensions true."
  []
  (def ca-obj (ca/generate {:common-name "Test CA"}))
  (ca/sign ca-obj attacker-csr {:copy-extensions true}))

(def-suite :name "Copy Extensions Unsafe Regression"
  :description "Ticket c0077b4d15: :copy-extensions must not duplicate extensions or copy attacker constraints from the CSR"

  (def-test "copy-extensions-produces-no-duplicate-certificate-extensions"
    :timeout 30

    (def exts (cert-extensions (sign-attacker-csr)))
    (def bc-count (count-oid exts oid-basic-constraints))
    (def ku-count (count-oid exts oid-key-usage))

    # The CSR's basicConstraints and keyUsage must not be duplicated by
    # jsec appending its own. Under the defect this fails with the
    # predicted counts: the CSR copies are added at src/jca/sign.c:202
    # and jsec appends its own at src/jca/sign.c:209 and
    # src/jca/sign.c:220 without stripping.
    (assert (and (= 1 bc-count) (= 1 ku-count))
            (string/format
              (string ":copy-extensions signed a certificate with "
                      "duplicate extensions: %d basicConstraints "
                      "(expected exactly one) and %d keyUsage (expected "
                      "exactly one); CSR extensions are copied before "
                      "jsec appends its own")
              bc-count ku-count))

    # And nothing else may be duplicated either - RFC 5280 allows at
    # most one extension of each NID.
    (def oids (distinct (map |(in $ :oid) exts)))
    (def dupes (filter |(> (count-oid exts $) 1) oids))
    (assert (empty? dupes)
            (string/format
              (string ":copy-extensions signed a certificate with "
                      "duplicated extension OIDs %s; expected no "
                      "extension OID more than once")
              (describe dupes))))

  (def-test "copy-extensions-does-not-copy-attacker-critical-constraints"
    :timeout 30

    (def exts (cert-extensions (sign-attacker-csr)))
    (def bc-exts (filter |(= (in $ :oid) oid-basic-constraints) exts))
    (def ku-exts (filter |(= (in $ :oid) oid-key-usage) exts))
    (def bc-true (filter |(bc-says-ca-true (in $ :val)) bc-exts))
    (def ku-sign (filter |(ku-says-key-cert-sign (in $ :val)) ku-exts))

    # The CSR's basicConstraints CA:TRUE and keyUsage keyCertSign are
    # smuggled critical constraints and must not survive
    # :copy-extensions; the resulting certificate's basicConstraints
    # must be CA:FALSE and its keyUsage must not grant keyCertSign.
    # Under the defect this fails: both attacker copies are present and
    # sit first in the extension list.
    (assert (and (empty? bc-true) (empty? ku-sign))
            (string/format
              (string ":copy-extensions copied the CSR critical "
                      "constraints into the signed certificate: %d of "
                      "%d basicConstraints copies encode CA:TRUE (the "
                      "resulting basicConstraints must be CA:FALSE) "
                      "and %d of %d keyUsage copies carry keyCertSign; "
                      "attacker-copied critical constraints must not "
                      "survive")
              (length bc-true) (length bc-exts)
              (length ku-sign) (length ku-exts)))))
