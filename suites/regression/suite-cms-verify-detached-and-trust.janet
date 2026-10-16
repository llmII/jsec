# CMS detached verification and trust regression test
# Ticket e4a5882f4ba5023fa15c5ed1f2dcf0b73247a07f
#
# "crypto/cms-verify: detached verification non-functional, NO_SIGNER_CERT_VERIFY silent"
#
# Mechanism (this tree, ticket branch off 0.2.0 at 599e82e288):
#   - Detached verification is non-functional. cfun_cms_verify reads its
#     optional third argument as the detached content
#     (src/jcrypto/cms.c:102) and raises the CMS_DETACHED flag at
#     src/jcrypto/cms.c:103, then discards the supplied bytes with
#     (void)detached_data at src/jcrypto/cms.c:106. The verification call
#     CMS_verify(cms, certs, store, NULL, content, flags) at
#     src/jcrypto/cms.c:121 passes NULL as the 4th argument (dcont, the
#     detached content BIO) while content sits in the 5th (output). The
#     detached content is never fed to the verification, so a detached
#     signature can never verify: CMS_verify finds no content to check
#     the signature against and every detached call reports :valid false.
#   - The no-trusted-cert path silently succeeds. The flags default at
#     src/jcrypto/cms.c:84 is CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY;
#     supplying trusted certs resets flags to plain CMS_BINARY at
#     src/jcrypto/cms.c:98, so the skip is armed for exactly the
#     documented one- and two-argument calls (the ticket's "always on"
#     wording is imprecise - the flag is dropped when trusted certs are
#     supplied - but the silent path is real). With no trust anchor at
#     all, any self-signed signer yields {:valid true}: signer
#     certificate verification is skipped outright and neither the
#     result nor the documentation says so. The cms-verify docstring at
#     src/jcrypto/module.c:119-126 is silent about both defects: it
#     names trusted-certs-pem and detached-data (module.c:120-121)
#     without saying detached-data is ignored, and its result contract
#     (module.c:122-126) claims ":valid - boolean indicating signature
#     validity" with no caveat for the unverified no-trust path.
#
# This test demonstrates:
#   (a) cms-verify of a detached message with content supplied actually
#       verifies the signature: the correct content, under the signer's
#       own cert as trust anchor, must report :valid true, and tampered
#       content must report :valid false (an attached signature under the
#       same trust anchor first proves the verifier itself works, so the
#       failure is isolated to the detached path),
#   (b) the no-trusted-cert path does not silently succeed: a one-arg
#       cms-verify of a self-signed signature must not return bare
#       {:valid true} - it must raise, report :valid false, or carry an
#       explicit caveat in the result that signer certificate
#       verification was skipped.
#
# Proof contract: under the defect each def-test fails with exactly the
# predicted symptom named in its final assertion - (a) the detached
# verify of the correct content reporting (:valid false) ("the detached
# content is never fed to the verification"), (b) the bare no-trust
# result (:valid true) ("any self-signed signer yields {:valid true}")
# - and nothing else: no crash, no hang, no unrelated error. Under fixed
# code both def-tests pass.

(use assay)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "CMS Verify Detached And Trust Regression"
  :description "Ticket e4a5882f4b: detached cms-verify never feeds its content and the no-trust path silently reports valid"

  (def-test "detached cms-verify with content supplied verifies the signature"

    (def msg "Important signed message")
    (def tampered "Important TAMPERED message")
    (def attached (crypto/cms-sign (certs :cert) (certs :key) msg))
    (def detached (crypto/cms-sign (certs :cert) (certs :key) msg {:detached true}))

    # Control: the same signer and trust anchor verify an ATTACHED
    # signature, proving the verifier works whenever the content is
    # reachable and isolating the failure below to the detached path.
    (def ra (crypto/cms-verify attached (certs :cert)))
    (assert (get ra :valid)
            (string/format
              (string "control: attached cms-verify under the signer's own "
                      "cert as trust anchor must report :valid true, "
                      "got (:valid %q)")
              (get ra :valid)))

    # (a) The detached signature over the correct content, with the
    # signer's own cert as trust anchor. cms-verify must feed the
    # supplied content to the signature check. Under the defect the
    # content argument is discarded (src/jcrypto/cms.c:106) and CMS_verify
    # is handed NULL as its detached-content BIO (src/jcrypto/cms.c:121),
    # so this reports :valid false even though every input is correct.
    (def r (crypto/cms-verify detached (certs :cert) msg))
    (assert (get r :valid)
            (string/format
              (string "cms-verify of a detached signature with the correct "
                      "content supplied must verify the signature and report "
                      ":valid true (the detached content must be fed to "
                      "CMS_verify as its indata), got (:valid %q)")
              (get r :valid)))

    # Same detached signature under tampered content: verification must
    # actually compare the supplied content, so this reports :valid false.
    (def rt (crypto/cms-verify detached (certs :cert) tampered))
    (assert (not (get rt :valid))
            (string/format
              (string "cms-verify of a detached signature under tampered "
                      "content must report :valid false (the supplied content "
                      "must be checked against the signature), "
                      "got (:valid %q)")
              (get rt :valid))))

  (def-test "cms-verify without trusted certs reports :valid false"

    (def msg "Important signed message")
    (def signed (crypto/cms-sign (certs :cert) (certs :key) msg))

    # One-argument cms-verify - the exact call the docstring at
    # src/jcrypto/module.c:119-126 documents - supplies NO trust anchor,
    # so signer certificate verification cannot succeed. Under the defect
    # CMS_NO_SIGNER_CERT_VERIFY (src/jcrypto/cms.c:84) silently skips it
    # and the call reports {:valid true} for this self-signed signer.
    # As a verdict function (matching cert/verify-chain), cms-verify must
    # return a table with :valid false rather than raising or silently
    # reporting :valid true.
    (def result (crypto/cms-verify signed))
    (assert (false? (get result :valid))
            (string/format
              (string "cms-verify with no trusted certs must report :valid "
                      "false for an unanchored self-signed signer rather "
                      "than silently succeeding; got (:valid %q :content %q)")
              (get result :valid)
              (get result :content)))))

