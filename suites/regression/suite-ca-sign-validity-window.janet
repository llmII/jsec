# ca/sign and ca/issue ignore the :not-before and :not-after validity
# options
#
# Mechanism (this tree):
#   SIGN_CSR_DOC documents :not-before ("Custom start time") and
#   :not-after ("Custom end time") at src/jca/sign.c:87-88, and the
#   option list comment above cfun_ca_sign_csr repeats both
#   (src/jca/internal.h:138-139). The ca/sign option parser reads
#   :days-valid, :serial, :copy-extensions, :key-usage,
#   :extended-key-usage, :san and :basic-constraints and never
#   :not-before or :not-after (src/jca/sign.c:115-169), and the ca/issue
#   parser never reads them either (src/jca/sign.c:376-448). Both entry
#   points stamp validity unconditionally from the signing time to the
#   signing time plus days-valid seconds (src/jca/sign.c:212-214 and
#   src/jca/sign.c:467-469), so a requested backdated or future-dated
#   window is silently ignored, and a window whose end is not later
#   than its start is silently accepted.
#
# This test demonstrates:
#   (a) ca/sign with :not-before and :not-after signs a certificate
#       whose validity window is exactly the requested window - a
#       :days-valid value in the same options table must not shift it,
#   (b) ca/issue with :not-before and :not-after issues a certificate
#       carrying exactly the requested window,
#   (c) ca/sign with an :not-after earlier than its :not-before raises
#       instead of issuing,
#   (d) ca/issue with an :not-after equal to its :not-before raises
#       instead of issuing.
#
# Predicted symptom: both entry points accept the options and sign
# with the current time regardless - the issued certificates report
# the signing-time window (now to now + days-valid) instead of the
# requested one, and the inconsistent windows are accepted with no
# error at all.
#
# Proof contract: plain tests asserting the correct behaviour - the
# requested validity window is carried exactly, and a window whose end
# is at or before its start raises. Under the defect the tests fail on
# purpose with the predicted symptom (the options are ignored and the
# certificates are signed with the current time regardless) and become
# the regression guard once the fix lands.

(use assay)
(import jsec/ca)
(import jsec/cert)
(import jsec/crypto)
(import ../helpers :prefix "")

# Fixed epoch seconds, chosen away from any signing time so "signed
# with the current time regardless" is unmistakable: 2023-11-14 and
# 2027-01-15 against a 2026 signing time. They also exercise both
# backdating (start before now) and future-dating (end after now).
(def- request-not-before 1700000000)
(def- request-not-after 1800000000)

(defn- signed-window
  ``Validity window of a PEM certificate as epoch seconds.``
  [pem]
  (def parsed (cert/parse pem))
  {:not-before (parsed :not-before) :not-after (parsed :not-after)})

(defn- sign-outcome
  ``One ca/sign call, captured as the issued window or the raise.``
  [ca opts]
  (def key-pem (crypto/generate-key :ec-p256))
  (def csr-pem (crypto/generate-csr key-pem
                                    {:common-name "validity.example"}))
  (try
    {:issued (signed-window (ca/sign ca csr-pem opts))}
    ([err] {:raised err})))

(defn- issue-outcome
  ``One ca/issue call, captured as the issued window or the raise.``
  [ca opts]
  (try
    {:issued (signed-window ((ca/issue ca opts) :cert))}
    ([err] {:raised err})))

(def-suite :name "CA Sign Validity Window Regression"
  :description "ca/sign and ca/issue honour :not-before and :not-after and refuse a window whose end is not later than its start"

  (def-test "ca-sign-csr-carries-the-requested-validity-window"
    (def ca (ca/generate {:common-name "Validity Root"}))
    (def outcome
      (sign-outcome ca {:not-before request-not-before
                        :not-after request-not-after
                        :days-valid 1}))
    (assert (and (outcome :issued)
                 (= request-not-before ((outcome :issued) :not-before))
                 (= request-not-after ((outcome :issued) :not-after)))
            (string/format
              (string "ca/sign with :not-before and :not-after must sign a "
                      "certificate carrying exactly the requested validity "
                      "window (both options are documented at "
                      "src/jca/sign.c:87-88, the option parser at "
                      "src/jca/sign.c:115-169 never reads them, and "
                      "src/jca/sign.c:212-214 stamps the window from the "
                      "signing time to the signing time plus days-valid "
                      "seconds); instead the documented options were "
                      "silently ignored and the certificate was signed with "
                      "the current time regardless - the requested validity "
                      "window is not carried; observed: %q")
              {:requested {:not-before request-not-before
                           :not-after request-not-after
                           :days-valid 1}
               :outcome outcome})))

  (def-test "ca-issue-carries-the-requested-validity-window"
    (def ca (ca/generate {:common-name "Validity Root"}))
    (def outcome
      (issue-outcome ca {:common-name "validity.example"
                         :not-before request-not-before
                         :not-after request-not-after
                         :days-valid 1}))
    (assert (and (outcome :issued)
                 (= request-not-before ((outcome :issued) :not-before))
                 (= request-not-after ((outcome :issued) :not-after)))
            (string/format
              (string "ca/issue with :not-before and :not-after must issue "
                      "a certificate carrying exactly the requested "
                      "validity window (the same two options ca/sign "
                      "documents at src/jca/sign.c:87-88; the ca/issue "
                      "option parser at src/jca/sign.c:376-448 never reads "
                      "them, and src/jca/sign.c:467-469 stamps the window "
                      "from the signing time to the signing time plus "
                      "days-valid seconds); instead the options were "
                      "silently ignored and the certificate was signed "
                      "with the current time regardless - the requested "
                      "validity window is not carried; observed: %q")
              {:requested {:not-before request-not-before
                           :not-after request-not-after
                           :days-valid 1}
               :outcome outcome})))

  (def-test "ca-sign-csr-not-after-earlier-than-not-before-must-raise"
    (def ca (ca/generate {:common-name "Validity Root"}))
    (def outcome
      (sign-outcome ca {:not-before request-not-after
                        :not-after request-not-before}))
    (assert (outcome :raised)
            (string/format
              (string "ca/sign with an :not-after earlier than its "
                      ":not-before must raise instead of issuing (the "
                      "end must be later than the start; the parser at "
                      "src/jca/sign.c:115-169 reads neither option and "
                      "src/jca/sign.c:212-214 stamps the window from the "
                      "signing time regardless); instead the call issued "
                      "a certificate with no error at all - the validity "
                      "options are silently ignored and an inverted "
                      "window request is accepted; observed: %q")
              {:requested {:not-before request-not-after
                           :not-after request-not-before}
               :outcome outcome})))

  (def-test "ca-issue-not-after-equal-to-not-before-must-raise"
    (def ca (ca/generate {:common-name "Validity Root"}))
    (def outcome
      (issue-outcome ca {:common-name "validity.example"
                         :not-before request-not-before
                         :not-after request-not-before}))
    (assert (outcome :raised)
            (string/format
              (string "ca/issue with an :not-after equal to its "
                      ":not-before must raise instead of issuing (the "
                      "end must be later than the start; the parser at "
                      "src/jca/sign.c:376-448 reads neither option and "
                      "src/jca/sign.c:467-469 stamps the window from the "
                      "signing time regardless); instead the call issued "
                      "a certificate with no error at all - the validity "
                      "options are silently ignored and a zero-length "
                      "window request is accepted; observed: %q")
              {:requested {:not-before request-not-before
                           :not-after request-not-before}
               :outcome outcome}))))
