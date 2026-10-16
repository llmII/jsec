# Key export 3DES policy regression test
# Ticket 8df504b6e1e071536952fa97cb2cb8c09347f001
#
# "DES-EDE3-CBC offered for private key export encryption"
#
# Mechanism (this tree, branch ticket-8df504b6e1e071536952fa97cb2cb8c09347f001
# off 0.2.0 at 599e82e288): get_export_cipher
# (src/jcrypto/keys.c:182-187) still offers 3DES for protecting
# exported private keys:
#   src/jcrypto/keys.c:185  if (strcmp(name, "des-ede3-cbc") == 0) return EVP_des_ede3_cbc();
# cfun_export_key feeds that cipher to PEM_write_bio_PrivateKey
# (src/jcrypto/keys.c:265-268) whenever :password is set, so
# (crypto/export-key key {:password "pw" :cipher :des-ede3-cbc}) encrypts
# the exported key with DES-EDE3-CBC. 3DES is advertised as a supported
# export cipher in the "unsupported cipher" error strings at
# src/jcrypto/keys.c:219-221 and src/jcrypto/keys.c:240-242 and in the
# export-key docstring at src/jcrypto/module.c:204-205.
#
# This test demonstrates:
#   (a) exporting a private key with :cipher :des-ede3-cbc must be
#       refused (raise) - or at minimum be reachable only through an
#       explicitly named unsafe/legacy option not passed here - instead
#       of silently encrypting the key with a broken legacy cipher,
#   (b) under the defect the export succeeds and the produced PKCS#8
#       blob names DES-EDE3-CBC (OID 1.2.840.113549.3.7) as the key
#       encryption algorithm, i.e. the legacy cipher is still offered.
#
# Predicted symptom (verbatim): exporting a private key with :cipher
# :des-ede3-cbc succeeds and the exported key is DES-EDE3-CBC-encrypted
# - the legacy cipher is still offered.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes.

(use assay)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(def des-ede3-cbc-oid
  "DER object identifier 1.2.840.113549.3.7 (des-ede3-cbc)"
  "\x2A\x86\x48\x86\xF7\x0D\x03\x07")

(defn- pem-body
  ``Base64 body of a PEM document (header/footer and empties dropped).``
  [pem]
  (string/join
    (seq [l :in (string/split "\n" (string pem))
          :when (and (not (string/has-prefix? "-----" l)) (not (empty? l)))]
      l)))

(def-suite :name "Key Export 3DES Policy Regression"
  :description "Ticket 8df504b6e1: exporting a private key with :des-ede3-cbc must be refused, not silently offered"

  (def-test "exporting a private key with des-ede3-cbc is refused"
    (def keys (generate-temp-certs {:common-name "key-export-3des-policy"}))

    (var outcome nil)
    (try
      (do
        # Under fixed code this raises (des-ede3-cbc is dropped or gated
        # behind an explicitly named legacy option not passed here) and
        # the test passes.
        (def pem (crypto/export-key (keys :key)
                                    {:password "regression"
                                     :cipher :des-ede3-cbc}))
        # Defect path: the export succeeded. Prove the produced key is
        # 3DES-encrypted by checking the PBES2 key-encryption algorithm
        # identifier in the decoded PKCS#8 blob.
        (def der (string (crypto/base64-decode (pem-body pem))))
        (def names-3des (if (string/find des-ede3-cbc-oid der) true false))
        (set outcome {:proceeded true :pem-names-des-ede3-cbc names-3des}))
      ([err] (set outcome {:raised err})))
    (assert (outcome :raised)
            (string/format
              (string "crypto/export-key with :cipher :des-ede3-cbc must "
                      "refuse the legacy cipher (get_export_cipher offers "
                      "it at src/jcrypto/keys.c:185 and the error strings "
                      "at src/jcrypto/keys.c:219-221 and :240-242 advertise "
                      "it); the export instead succeeded and the key is "
                      "DES-EDE3-CBC-encrypted - the legacy cipher is still "
                      "offered; observed: %q")
              outcome))))
