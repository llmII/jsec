# DTLS cert loading and security option error detail regression test
# Ticket b73a621e85f1903958cb51461fcc6c4f0784699e
#
# "Pass recorded failure detail to jdtls callers at the raise sites"
#
# Mechanism (this tree, branch ticket-b73a621e85f1903958cb51461fcc6c4f0784699e
# off 0.2.0 at 713de246ef): the cert-loading helpers (load_cert_chain_mem,
# load_ca_mem, add_trusted_cert) in src/jutils/cert_loading.c and the
# security-option validation (apply_security_options) in src/jutils/security.c
# record a human-readable failure detail in cert_load_error_buf and return
# failure status 0; they never raise directly.
#
# The jtls and jutils callers raise with the recorded detail through
# jutils_cert_load_error() directly:
#   jsec_panic(MOD, "SSL", "...: %s", jutils_cert_load_error());
#
# But the jdtls callers in dtls/connect (src/jdtls/api/connect.c),
# dtls/upgrade (src/jdtls/api/upgrade.c), and the DTLS context build in
# dtls/listen (src/jdtls/server.c) raise through dtls_panic_ssl:
#   dtls_panic_ssl("failed to apply security options");
#   dtls_panic_ssl("failed to add trusted certificate");
#
# dtls_panic_ssl calls get_ssl_error_string() (src/jutils/error.c).
# get_ssl_error_string() only consults cert_load_error_buf when the thread's
# OpenSSL error queue is completely empty (err == 0). When the queue is
# non-empty at raise time (e.g. from a prior failed operation or residual
# error entries), get_ssl_error_string() drains ERR_get_error() and reports
# the OpenSSL queue text, completely dropping the recorded failure cause
# (such as ":min-version must be a string or keyword, got number" or
# "trusted certificate must be a string or buffer, got 42").
#
# This test demonstrates:
#   (a) dtls/connect with invalid security options on a dirty OpenSSL error
#       queue must raise with the recorded failure detail naming :min-version,
#       not the leftover OpenSSL queue error,
#   (b) dtls/connect with a wrong-type :trusted-cert on a dirty queue must
#       raise naming the type problem, not the leftover error,
#   (c) dtls/upgrade with invalid security options on a dirty queue must
#       raise naming the :min-version problem,
#   (d) dtls/upgrade with a wrong-type :trusted-cert on a dirty queue must
#       raise naming the type problem,
#   (e) dtls/listen with invalid security options on a dirty queue must
#       raise naming the :min-version problem.
#
# Predicted symptom: under the defect, each test fails because the raised
# message contains the leftover OpenSSL error (e.g. "DECODER routines::unsupported")
# and completely lacks the recorded failure detail (:min-version or trusted
# certificate type description).
#
# Proof contract: under the defect the suite fails with the predicted symptom
# (the raise reports the leftover OpenSSL error instead of the recorded cause);
# under fixed code the whole suite passes.

(use assay)
(import jsec/dtls-stream :as dtls)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

# A non-RSA key to dirty the OpenSSL error queue deterministically.
# crypto/rsa-encrypt calls PEM_read_bio_PUBKEY which fails on an EC key,
# pushing DECODER routines::unsupported to OpenSSL's error queue, and then
# panics with crypto_panic_param (which does not drain the OpenSSL queue).
(def ec-key (crypto/generate-key :ec-p256))

(defn- dirty-queue []
  (try (crypto/rsa-encrypt ec-key "probe") ([_] nil)))

(defn- capture [thunk]
  (try
    [:returned (thunk)]
    ([err] [:raised (string err)])))

(def-suite :name "DTLS Cert Load Error Detail Regression"
  :description "Ticket b73a621e85: jdtls callers must report recorded failure details directly at raise sites even on dirty queue"

  (def-test "dtls-connect-with-bad-security-options-retains-detail-on-dirty-queue"
    :timeout 15

    (dirty-queue)
    (def outcome
      (capture
        (fn []
          (dtls/connect "127.0.0.1" 1234 {:security {:min-version 5}}))))

    (assert (= :raised (get outcome 0))
            "dtls/connect with bad security option must raise")
    (def msg (get outcome 1))
    (assert (and (string/find ":min-version" msg)
                 (string/find "string or keyword" msg))
            (string/format
              (string "dtls/connect with invalid :min-version must raise naming "
                      ":min-version and the expected type, but got %q "
                      "- under the defect dtls_panic_ssl reports the leftover "
                      "error from the OpenSSL queue instead of the recorded detail")
              msg)))

  (def-test "dtls-connect-with-bad-trusted-cert-retains-detail-on-dirty-queue"
    :timeout 15

    (dirty-queue)
    (def outcome
      (capture
        (fn []
          (dtls/connect "127.0.0.1" 1234 {:trusted-cert 42}))))

    (assert (= :raised (get outcome 0))
            "dtls/connect with bad :trusted-cert must raise")
    (def msg (get outcome 1))
    (assert (and (string/find "trusted certificate" msg)
                 (string/find "string or buffer" msg))
            (string/format
              (string "dtls/connect with bad :trusted-cert must raise naming "
                      "the type problem (string or buffer), but got %q "
                      "- under the defect dtls_panic_ssl reports the leftover "
                      "error from the OpenSSL queue instead of the recorded detail")
              msg)))

  (def-test "dtls-upgrade-with-bad-security-options-retains-detail-on-dirty-queue"
    :timeout 15

    (def listener (net/listen "127.0.0.1" "0" :datagram))
    (def [_ port] (net/localname listener))
    (defer (:close listener)
      (def sock (net/connect "127.0.0.1" (string port) :datagram "127.0.0.1" "0"))
      (defer (:close sock)
        (dirty-queue)
        (def outcome
          (capture
            (fn []
              (dtls/upgrade sock {:security {:min-version 5}}))))

        (assert (= :raised (get outcome 0))
                "dtls/upgrade with bad security option must raise")
        (def msg (get outcome 1))
        (assert (and (string/find ":min-version" msg)
                     (string/find "string or keyword" msg))
                (string/format
                  (string "dtls/upgrade with invalid :min-version must raise naming "
                          ":min-version and the expected type, but got %q "
                          "- under the defect dtls_panic_ssl reports the leftover "
                          "error from the OpenSSL queue instead of the recorded detail")
                  msg)))))

  (def-test "dtls-upgrade-with-bad-trusted-cert-retains-detail-on-dirty-queue"
    :timeout 15

    (def listener (net/listen "127.0.0.1" "0" :datagram))
    (def [_ port] (net/localname listener))
    (defer (:close listener)
      (def sock (net/connect "127.0.0.1" (string port) :datagram "127.0.0.1" "0"))
      (defer (:close sock)
        (dirty-queue)
        (def outcome
          (capture
            (fn []
              (dtls/upgrade sock {:trusted-cert 42}))))

        (assert (= :raised (get outcome 0))
                "dtls/upgrade with bad :trusted-cert must raise")
        (def msg (get outcome 1))
        (assert (and (string/find "trusted certificate" msg)
                     (string/find "string or buffer" msg))
                (string/format
                  (string "dtls/upgrade with bad :trusted-cert must raise naming "
                          "the type problem (string or buffer), but got %q "
                          "- under the defect dtls_panic_ssl reports the leftover "
                          "error from the OpenSSL queue instead of the recorded detail")
                  msg)))))

  (def-test "dtls-listen-with-bad-security-options-retains-detail-on-dirty-queue"
    :timeout 15

    (dirty-queue)
    (def outcome
      (capture
        (fn []
          (dtls/listen "127.0.0.1" "0"
                       {:cert (certs :cert)
                        :key (certs :key)
                        :security {:min-version 5}}))))

    (assert (= :raised (get outcome 0))
            "dtls/listen with bad security option must raise")
    (def msg (get outcome 1))
    (assert (and (string/find ":min-version" msg)
                 (string/find "string or keyword" msg))
            (string/format
              (string "dtls/listen with invalid :min-version must raise naming "
                      ":min-version and the expected type, but got %q "
                      "- under the defect dtls_panic_ssl reports the leftover "
                      "error from the OpenSSL queue instead of the recorded detail")
              msg))))
