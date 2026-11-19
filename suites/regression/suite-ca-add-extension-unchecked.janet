# ca_add_extension return ignored at 21 call sites regression test
# Ticket 482fcffaaaee31b953e9774240a00082f51139a3
#
# "ca_add_extension return ignored at 21 call sites"
#
# Mechanism (this tree):
#   ca_add_extension (src/jca/types.c:253-266) returns 0 when
#   X509V3_EXT_conf_nid fails (src/jca/types.c:258-260) and otherwise the
#   X509_add_ext result (src/jca/types.c:263-265). All 21 call sites
#   discard that return: src/jca/sign.c:60 (add_san_entries), the
#   ca/sign-csr standard extensions at src/jca/sign.c:209-227
#   (basicConstraints :209, subjectKeyIdentifier :211,
#   authorityKeyIdentifier :212, keyUsage :217 or the default :220,
#   extendedKeyUsage :226), the ca/issue extensions at
#   src/jca/sign.c:393-409 (basicConstraints :393, subjectKeyIdentifier
#   :394, authorityKeyIdentifier :395, keyUsage :400 or the default :402,
#   extendedKeyUsage :408), the ca/generate self-signed CA extensions at
#   src/jca/types.c:447-452 (:447, :448, :450, :451) and the
#   ca/generate-intermediate extensions at src/jca/types.c:597-603
#   (:597, :599, :601, :602). An invalid :extended-key-usage string makes
#   X509V3_EXT_conf_nid fail at src/jca/types.c:258, ca_add_extension
#   returns 0, and the issued certificate simply lacks the extension with
#   no error raised. The house rule is that real failures raise
#   (docs/maintainer/jsec-conventions.org:137-139).
#
# This test demonstrates:
#   (a) under the defect ca/issue with an invalid :extended-key-usage
#       value RETURNS NORMALLY and the issued certificate carries no
#       extendedKeyUsage extension at all (cert/parse reports no
#       :ext-key-usage key): the failed add at src/jca/sign.c:408 was
#       silently discarded,
#   (b) the same silent drop on the ca/sign-csr entry point: the invalid
#       :extended-key-usage value reaches src/jca/sign.c:226 and the
#       signed certificate is returned without the extension,
#   (c) under fixed code both calls raise a CA error naming the failing
#       extension value instead of issuing a certificate without it.
#
# Proof contract: plain tests asserting the correct behaviour - a failing
# extension value must raise, never silently issue a certificate without
# the extension. Under the defect the tests fail on purpose with the
# predicted silent-drop symptom (the call returned and the extension is
# absent), and they become the regression guard once the fix lands.

(use assay)
(import jsec/ca)
(import jsec/cert)
(import jsec/crypto)
(import ../helpers :prefix "")

(def-suite :name "CA Add Extension Unchecked Regression"
  :description "Ticket 482fcffaaa: ca_add_extension failures must raise, not silently drop the extension"

  (def-test "ca-issue-invalid-extended-key-usage-must-raise"
    (def ca (ca/generate {:common-name "Add-Ext Root"}))
    (def outcome
      (try
        {:returned (:issue ca {:common-name "add-ext-issue.example"
                               :extended-key-usage
                               "notAValidExtendedKeyUsage"})}
        ([err] {:raised err})))
    (def observed
      (if-let [issued (outcome :returned)]
        (string "returned a certificate whose cert/parse :ext-key-usage is "
                (describe (get (cert/parse (issued :cert)) :ext-key-usage))
                " - the extension is silently absent")
        (string "raised " (describe (outcome :raised)))))
    (assert (not (nil? (outcome :raised)))
            (string "ca/issue with an invalid :extended-key-usage value "
                    "must raise instead of issuing a certificate without "
                    "the extension (the failed ca_add_extension at "
                    "src/jca/types.c:253-266 is discarded at "
                    "src/jca/sign.c:408; house rule: real failures raise), "
                    "but it " observed)))

  (def-test "ca-sign-csr-invalid-extended-key-usage-must-raise"
    (def ca (ca/generate {:common-name "Add-Ext Root"}))
    (def key-pem (crypto/generate-key :ec-p256))
    (def csr-pem (crypto/generate-csr key-pem
                                      {:common-name "add-ext-csr.example"}))
    (def outcome
      (try
        {:returned (:sign-csr ca csr-pem {:extended-key-usage
                                          "notAValidExtendedKeyUsage"})}
        ([err] {:raised err})))
    (def observed
      (if-let [issued-pem (outcome :returned)]
        (string "returned a certificate whose cert/parse :ext-key-usage is "
                (describe (get (cert/parse issued-pem) :ext-key-usage))
                " - the extension is silently absent")
        (string "raised " (describe (outcome :raised)))))
    (assert (not (nil? (outcome :raised)))
            (string "ca/sign-csr with an invalid :extended-key-usage "
                    "value must raise instead of signing a certificate "
                    "without the extension (the failed ca_add_extension "
                    "at src/jca/types.c:253-266 is discarded at "
                    "src/jca/sign.c:226; house rule: real failures "
                    "raise), but it " observed))))
