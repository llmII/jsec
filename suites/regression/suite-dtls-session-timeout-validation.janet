# DTLS session timeout validation regression test
# Ticket f8efc3144a5b573e6f662e5e8c1f0b6a76a5b527
#
# "DTLS session_timeout not validated (negative/NaN)"
#
# Mechanism (this tree, branch ticket-f8efc3144a5b573e6f662e5e8c1f0b6a76a5b527
# off 0.2.0 at 599e82e288): cfun_dtls_listen stores the :session-timeout
# option with no type, range or finiteness check:
#   src/jdtls/server.c:314  Janet t = janet_get(...janet_ckeywordv("session-timeout"))
#   src/jdtls/server.c:315  if (!janet_checktype(t, JANET_NIL)) {
#   src/jdtls/server.c:316      server->session_timeout = janet_unwrap_number(t);
# The only guard is JANET_NIL. Negative values and NaN are passed
# straight into the DTLS session configuration (the default is
# DTLS_SESSION_TIMEOUT at src/jdtls/server.c:309) instead of being
# rejected at the API boundary with an argument error. The fix is to
# reject negative and non-finite values with a Janet argument error.
#
# This test demonstrates:
#   (a) a negative :session-timeout is rejected with a Janet argument
#       error at dtls/listen,
#   (b) a NaN :session-timeout is rejected the same way,
# and that both rejections are real argument errors rather than
# environment failures: each test first proves a control call with a
# valid :session-timeout is accepted on the same host/port/certs.
#
# Under the defect the test fails with exactly the predicted symptom -
# dtls/listen accepts the bad value and returns a server with no error;
# under fixed code the whole test passes.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- try-listen
  "Attempt dtls/listen with the given :session-timeout. Returns :accepted
   when the call succeeds (the server is closed again), or [:error err]
   when it raises, so tests can tell a rejection from an acceptance."
  [session-timeout]
  (try
    (do
      (def server (dtls/listen "127.0.0.1" "0"
                               {:cert (certs :cert)
                                :key (certs :key)
                                :session-timeout session-timeout}))
      (:close server)
      :accepted)
    ([err] [:error err])))

(defn- rejected?
  "True when try-listen reported a Janet error (the fix's contract)."
  [result]
  (and (indexed? result) (= :error (get result 0))))

(def-suite :name "DTLS Session Timeout Validation Regression"
  :description "Ticket f8efc3144a: negative and NaN session-timeout must be rejected with an argument error"

  (def-test "negative session-timeout is rejected with an argument error"
    :timeout 15

    # Control: a valid positive timeout must be accepted on this host,
    # so a later rejection cannot be a bind or cert failure in disguise.
    (def control (try-listen 300))
    (assert (= :accepted control)
            (string/format
              "control dtls/listen with :session-timeout 300 must be accepted (environment check), got %q"
              control))

    # (a) The defect: -5 is accepted verbatim at src/jdtls/server.c:314-316
    # and reaches the session configuration. Under the fix this returns
    # [:error err] and the assertion passes.
    (def result (try-listen -5))
    (assert (rejected? result)
            (string/format
              (string "dtls/listen accepted a negative :session-timeout (-5) "
                      "without error (got %q); a negative session_timeout "
                      "must be rejected with an argument error at the API "
                      "boundary")
              result)))

  (def-test "nan session-timeout is rejected with an argument error"
    :timeout 15

    (def control (try-listen 300))
    (assert (= :accepted control)
            (string/format
              "control dtls/listen with :session-timeout 300 must be accepted (environment check), got %q"
              control))

    # (b) NaN flows through janet_unwrap_number at src/jdtls/server.c:316
    # with no finiteness check. math/sqrt of -1 yields NaN.
    (def nan-timeout (math/sqrt -1))
    (def result (try-listen nan-timeout))
    (assert (rejected? result)
            (string/format
              (string "dtls/listen accepted a NaN :session-timeout without "
                      "error (got %q); a non-finite session_timeout must be "
                      "rejected with an argument error at the API boundary")
              result))))
