# DTLS security options ignored regression test
# Ticket 703d13cddbe00afef61fc4ca01ff31bcdfa41f51
#
# "DTLS ignores apply_security_options return value"
#
# Mechanism (this tree, branch ticket-703d13cddbe00afef61fc4ca01ff31bcdfa41f51
# off 0.2.0 at 599e82e288): apply_security_options
# (src/jutils/security.c:53) returns 0 when a security option fails to
# apply. For a non-string :ciphers value janet_to_string_or_keyword
# returns NULL (src/jutils/janet_types.c:14-22) and
# src/jutils/security.c:124-125 returns 0 WITHOUT touching the SSL_CTX,
# so the context keeps its default cipher list. Three DTLS call sites
# ignore that return value and keep building the session:
#   src/jdtls/server.c:340        apply_security_options(server->ctx, security, 1);
#   src/jdtls/api/connect.c:183   apply_security_options(client->ctx, security, 1);
#   src/jdtls/api/upgrade.c:137   apply_security_options(client->ctx, security, 1);
# The TLS side checks the same return and raises (goto error at
# src/jtls/context/server.c:328-330; the shared-context path panics
# "failed to apply security options" at src/jutils/context.c:153-156).
#
# This test demonstrates:
#   (a) dtls/listen with :security {:ciphers 42} must fail the session
#       (raise) instead of returning a server - under the defect the
#       server is returned, and a normal client handshake through it
#       negotiates the DEFAULT cipher ECDHE-RSA-AES256-GCM-SHA384,
#   (b) dtls/connect with :security {:ciphers 42} must fail the session
#       instead of returning a connected client - under the defect the
#       handshake completes on defaults and :cipher reports
#       ECDHE-RSA-AES256-GCM-SHA384,
#   (c) dtls/upgrade with :security {:ciphers 42} must fail the session
#       instead of upgrading the datagram socket - under the defect the
#       upgrade completes on defaults and :cipher reports
#       ECDHE-RSA-AES256-GCM-SHA384.
#
# Predicted symptom (verbatim, forge ticket): a failed :ciphers/security
# option is silently swallowed and the session proceeds with defaults.
#
# Proof contract: under the defect the test fails with exactly that
# symptom - each session call returns a session that proceeded with the
# default cipher list and the failure message reports :proceeded and the
# negotiated default cipher; under fixed code the whole test passes.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- start-echo-server
  ``Start a DTLS echo server on a random port with the given :security
   options (or none). Returns {:server :port :done}. The echo fiber pumps
   dtls/recv-from so peer handshakes complete.``
  [&opt security]
  (def opts @{:cert (certs :cert) :key (certs :key)})
  (when security (put opts :security security))
  (def server (dtls/listen "127.0.0.1" "0" opts))
  (def [_ port] (dtls/localname server))
  (def done (ev/chan 1))
  (ev/go (fn []
           (try
             (do
               (while true
                 (def buf @"")
                 (def addr (dtls/recv-from server 1024 buf 3))
                 (if addr
                   (dtls/send-to server addr (string "Echo: " buf))
                   (break))))
             ([_] nil))
           (ev/give done true)))
  {:server server :port port :done done})

(defn- stop-echo-server [echo]
  (try (dtls/close-server (echo :server) true) ([_] nil))
  (try (ev/take (echo :done)) ([_] nil)))

(defn- negotiated-cipher
  ``Complete a normal (no :security) DTLS client handshake against the
   echo server on port and return the negotiated cipher name.``
  [port]
  (def c (dtls/connect "127.0.0.1" port {:verify false}))
  (def cipher (dtls/cipher c))
  (try (dtls/close c) ([_] nil))
  cipher)

(def-suite :name "DTLS Security Options Ignored Regression"
  :description "Ticket 703d13cddb: a failed :ciphers security option must fail the DTLS session, not proceed with defaults"

  (def-test "listen with a bad ciphers value fails the session instead of proceeding with defaults"
    :timeout 15

    (var outcome nil)
    (try
      (do
        # Under fixed code this dtls/listen raises (apply_security_options
        # returned 0 must fail the session) and the test passes.
        (def server (dtls/listen "127.0.0.1" "0"
                                 {:cert (certs :cert) :key (certs :key)
                                  :security {:ciphers 42}}))
        # Defect path: the failed :ciphers value was silently swallowed
        # (src/jdtls/server.c:340 ignores the return) and a server came
        # back. Prove it proceeded with defaults: pump its handshake with
        # a normal client and record the negotiated cipher.
        (def echo {:server server})
        (ev/go (fn []
                 (try
                   (do
                     (while true
                       (def buf @"")
                       (def addr (dtls/recv-from server 1024 buf 3))
                       (if addr
                         (dtls/send-to server addr (string "Echo: " buf))
                         (break))))
                   ([_] nil))))
        (def [_ port] (dtls/localname server))
        (def cipher (negotiated-cipher port))
        (try (dtls/close-server server true) ([_] nil))
        (set outcome {:proceeded true :negotiated cipher}))
      ([err] (set outcome {:raised err})))
    (assert (outcome :raised)
            (string/format
              (string "dtls/listen with :security {:ciphers 42} must fail "
                      "the session: apply_security_options returned 0 "
                      "(src/jutils/security.c:124-125) and the return is "
                      "ignored at src/jdtls/server.c:340, so the failed "
                      ":ciphers value is silently swallowed and the "
                      "session proceeds with defaults; observed: %q")
              outcome)))

  (def-test "connect with a bad ciphers value fails the session instead of proceeding with defaults"
    :timeout 15

    (def echo (start-echo-server))
    (var outcome nil)
    (try
      (do
        # Under fixed code this dtls/connect raises and the test passes.
        (def c (dtls/connect "127.0.0.1" (echo :port)
                             {:verify false :security {:ciphers 42}}))
        # Defect path: the failed :ciphers value was silently swallowed
        # (src/jdtls/api/connect.c:183 ignores the return), the handshake
        # completed on the default cipher list, and a client came back.
        (def cipher (try (dtls/cipher c) ([e] (string "cipher-err: " e))))
        (try (dtls/close c) ([_] nil))
        (set outcome {:proceeded true :negotiated cipher}))
      ([err] (set outcome {:raised err})))
    (stop-echo-server echo)
    (assert (outcome :raised)
            (string/format
              (string "dtls/connect with :security {:ciphers 42} must fail "
                      "the session: apply_security_options returned 0 "
                      "(src/jutils/security.c:124-125) and the return is "
                      "ignored at src/jdtls/api/connect.c:183, so the "
                      "failed :ciphers value is silently swallowed and "
                      "the session proceeds with defaults; observed: %q")
              outcome)))

  (def-test "upgrade with a bad ciphers value fails the session instead of proceeding with defaults"
    :timeout 15

    (def echo (start-echo-server))
    (var outcome nil)
    (try
      (do
        (def sock (net/connect "127.0.0.1" (echo :port) :datagram))
        # Under fixed code this dtls/upgrade raises and the test passes.
        (def c (dtls/upgrade sock {:verify false :security {:ciphers 42}}))
        # Defect path: the failed :ciphers value was silently swallowed
        # (src/jdtls/api/upgrade.c:137 ignores the return), the upgrade
        # completed on the default cipher list, and a client came back.
        (def cipher (try (dtls/cipher c) ([e] (string "cipher-err: " e))))
        (try (dtls/close c) ([_] nil))
        (set outcome {:proceeded true :negotiated cipher}))
      ([err] (set outcome {:raised err})))
    (stop-echo-server echo)
    (assert (outcome :raised)
            (string/format
              (string "dtls/upgrade with :security {:ciphers 42} must fail "
                      "the session: apply_security_options returned 0 "
                      "(src/jutils/security.c:124-125) and the return is "
                      "ignored at src/jdtls/api/upgrade.c:137, so the "
                      "failed :ciphers value is silently swallowed and "
                      "the session proceeds with defaults; observed: %q")
              outcome))))
