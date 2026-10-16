# Options dictionary enforcement regression test
# Ticket ee435eccb3a5c0b6d6d9514d307da8a58dd43538
#
# "Enforce table or struct on options dictionary parameters across
# jcrypto, jtls, jdtls, and jca"
#
# Mechanism (this tree, branch ticket-ee435eccb3a5c0b6d6d9514d307da8a58dd43538
# off 0.2.0 at 2eef29afaf): options dictionary parameters are checked
# with `if (janet_checktype(x, JANET_TABLE) || janet_checktype(x,
# JANET_STRUCT)) { read options }` and no else branch, so a non-nil
# non-dictionary argument falls through and the call proceeds with
# default settings. Sites: cfun_export_key (src/jcrypto/keys.c:207,
# :228), cfun_wrap and cfun_connect (src/jtls/api/connect.c:130-131,
# :808-809), cfun_listen (src/jtls/api/server.c:435-455), cfun_dtls_connect
# (src/jdtls/api/connect.c:81-82), cfun_dtls_upgrade
# (src/jdtls/api/upgrade.c:63-64), cfun_ec_point_to_bytes's opts argument
# (src/jcrypto/ec.c:394-406), and the ca_opts_valid gate of
# cfun_ca_create_ocsp_response (src/jca/ocsp.c:204, helper at
# src/jca/internal.h:280). cfun_create_pkcs12 (src/jcrypto/pkcs12.c:137-146)
# falls through to NULL dictionary lookups and only fails later on the
# missing :password. The jcert verification functions already enforce
# the contract and raise [CERT:PARAM] "options must be a table or
# struct" (src/jcert/verify.c:159-165) - the intended precedent.
# cfun_ca_create_ocsp_response additionally rejects struct request-info
# with [CA:PARAM] "request-info must be a table" (src/jca/ocsp.c:174-178),
# the ticket's reverse symptom (a dictionary rejected).
#
# This test demonstrates: every options dictionary parameter named in
# the ticket accepts nil, a table, or a struct and raises the
# subsystem's [*:PARAM] error when passed any other type. One probe per
# subsystem (jcrypto, jtls, jdtls, jca) passes a string in the options
# position and asserts the parameter raise. Under the defect the test
# fails with exactly the predicted symptom - the invalid arguments are
# accepted (or, at dtls/connect, ignored until an unrelated SSL failure
# later in the handshake) and no [*:PARAM] error is raised; under fixed
# code the whole test passes.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/ca :as ca)
(import jsec/cert :as cert)
(import jsec/tls-stream :as tls-stream)
(import jsec/dtls-stream :as dtls-stream)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- probe-opts-arg
  "Run one call with a non-dictionary options argument and classify the
   outcome: [:param] when the subsystem [*:PARAM] error was raised (the
   contract), [:wrong e] for any other error, [:accepted v] when the
   call returned normally."
  [thunk]
  (try
    (do (def r (thunk)) [:accepted (if (bytes? r) (string "<bytes>") r)])
    ([e]
      (let [es (string e)]
        (if (string/find ":PARAM]" es)
          [:param]
          [:wrong es])))))

(def-suite :name "Options Dictionary Enforcement Regression"
  :description "Ticket ee435eccb3: options dictionary parameters must raise [*:PARAM] on non-dictionary arguments across jcrypto, jtls, jdtls, and jca"

  (def-test "options-dictionary-parameters-must-reject-non-dictionary-values"
    :timeout 60

    # jdtls probe needs a live DTLS listener and a peer that answers the
    # handshake, so a non-dictionary opts at dtls/connect is observable
    # at the API boundary instead of hanging - the shape of
    # suites/regression/suite-dtls-connect-string-port.janet.
    (def dtls-server
      (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert)
                                         :key (certs :key)}))
    (def [_ dtls-port] (dtls-stream/localname dtls-server))
    (defer (:close dtls-server)
      (ev/go
        (fn []
          (try
            (repeat 3
              (def buf (buffer/new 1024))
              (def addr (dtls-stream/recv-from dtls-server 1024 buf))
              (when addr
                (dtls-stream/send-to dtls-server addr
                                     (string "echo:" (string buf)))))
            ([_] nil))))
      (ev/sleep 0.2)

      # Control: the same dtls/connect call with a valid options table
      # completes against the live listener, so a later non-raise below
      # cannot be an environment failure in disguise.
      (def control
        (probe-opts-arg
          |(do (def c (dtls-stream/connect "127.0.0.1" (string dtls-port)
                                           {:verify false}))
               (:close c true)
               :connected)))
      (assert (= :accepted (get control 0))
              (string/format
                (string "control: dtls/connect with a valid options table "
                        "must complete against the live listener, got %q - "
                        "the probe cannot distinguish acceptance from a "
                        "broken environment")
                control))

      # One non-dictionary probe per subsystem named in the ticket. Each
      # options position must raise the subsystem's [*:PARAM] error - the
      # [CERT:PARAM] "options must be a table or struct" shape of
      # src/jcert/verify.c:159-165 - before any work is done.
      (def key-pem (crypto/generate-key :ed25519))
      (def my-ca (ca/generate {:common-name "Enforcement Probe CA"}))
      (def cases
        [["(crypto/export-key key \"oops\") - jcrypto export-key opts"
          |(crypto/export-key key-pem "oops")]
         ["(tls-stream/listen \"127.0.0.1\" \"0\" \"oops\") - jtls listen opts"
          |(do (def s (tls-stream/listen "127.0.0.1" "0" "oops"))
               (:close s)
               :accepted)]
         ["(dtls-stream/connect host port \"oops\") - jdtls connect opts"
          |(do (def c (dtls-stream/connect "127.0.0.1" (string dtls-port)
                                           "oops"))
               (:close c true)
               :accepted)]
         ["(ca/create-ocsp-response ca req :good \"oops\") - jca opts"
          |(ca/create-ocsp-response my-ca @{:serial 1} :good "oops")]])

      (def violations @[])
      (each [label thunk] cases
        (def outcome (probe-opts-arg thunk))
        (unless (= :param (get outcome 0))
          (array/push violations
                      (string label " -> " (string/format "%q" outcome)))))

      # Every non-dictionary options argument above must raise the
      # parameter error. Under the defect each site skips its options
      # block silently: export-key returns an unencrypted key, listen
      # returns a listener with default backlog, connect ignores the
      # argument and only fails much later inside the handshake, and
      # create-ocsp-response builds a response with default options.
      (assert (empty? violations)
              (string/format
                (string "options dictionary parameters that must raise the "
                        "subsystem's [*:PARAM] error on a non-dictionary "
                        "argument were accepted or mis-handled instead (%d "
                        "violations): %s. The sites read their options only "
                        "under janet_checktype TABLE/STRUCT (e.g. "
                        "src/jcrypto/keys.c:207, src/jtls/api/server.c:435, "
                        "src/jdtls/api/connect.c:81, src/jca/internal.h:280) "
                        "with no else branch, so anything else falls through "
                        "to the defaults instead of raising - the contract "
                        "enforced at src/jcert/verify.c:159-165")
                (length violations)
                (string/join violations "; "))))))
