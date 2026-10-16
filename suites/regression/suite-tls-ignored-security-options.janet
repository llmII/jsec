# TLS ignored security options regression test
# Ticket 14044e944188b536d7339816d13e7f8bfceba359
#
# "Security-relevant options silently ignored on the TLS side"
#
# Mechanism (this tree, 0.2.0 basis at 599e82e288):
#   Part 1 - the client :ca option is only honored in the server mTLS
#   branch, so tls/connect and tls/wrap fall back to system roots:
#     src/jtls/api/connect.c:133-144  the :ca read (:134) sits inside
#       the server-mode :verify branch at :116 (server branch :95-146)
#     src/jtls/api/connect.c:208-249  the cfun_wrap client path creates
#       the client ctx at :208 and honors :trusted-cert (:213-221) and
#       client :cert/:key (:223-247) but never reads :ca
#     src/jtls/api/connect.c:501-552  tls_connect_callback, the
#       tls/connect TCP path, is the same: jtls_create_client_ctx at
#       :526, :trusted-cert at :535-541, no :ca anywhere
#     src/jtls/context/client.c:28  SSL_CTX_set_default_verify_paths is
#       the system-roots fallback that :ca never gets to override
#     src/jutils/security.c:155-156, :184  only :security {:ca-file ...}
#       loads a client CA today
#   Part 2 - the tls/new-context client path drops documented options:
#     src/jtls/api/context.c:132-143  reads only :verify (:134-136) and
#       :security (:138), then jtls_create_client_ctx at :140; :ca,
#       :trusted-cert and :ciphers are never read
#     jsec/tls.janet:36-44  the facade documents :ca, :trusted-cert and
#       :ciphers for new-context
#   Part 3 - the :context path skips :verify-hostname:
#     src/jtls/api/connect.c:162-180  the :context branch jumps to
#       common_setup at :180 before :verify-hostname is parsed at
#       :202-205 (the direct context signature at :66-91 does the same
#       at :91). common_setup would apply it at :302-318, but it is
#       never set on those paths. The TCP tls/connect path does parse
#       it (callback :609-615) - the defect is the wrap/upgrade
#       :context path.
#
# This test demonstrates:
#   (a) (tls/connect host port {:ca "my-ca.pem"}) actually uses the
#       supplied CA: a certificate issued by that CA verifies and the
#       connection carries data, and a certificate OUTSIDE that CA fails
#       verification instead of silently succeeding against system
#       roots,
#   (b) :verify-hostname is honored on the :context path: a mismatching
#       :verify-hostname must fail the handshake and a matching one must
#       pass,
#   (c) cheap part-2 guards: tls/new-context honors its documented :ca
#       and :trusted-cert options.
#
# Proof contract: under the defect (a-1) fails with a certificate verify
# failure although the exact issuing CA was supplied, (a-2) fails with
# the connection silently ACCEPTED against system roots, (b-mismatch)
# fails with the connection SUCCEEDED although the demanded
# :verify-hostname name is not on the certificate, (b-match) fails with
# a certificate verify / hostname mismatch because verification
# silently used :hostname instead, and the two part-2 guards fail with a
# certificate verify failure from a context that dropped its :ca resp.
# :trusted-cert. Exactly those symptoms and nothing else; under the fix
# all six tests pass and guard the fix. The (a-2) scenario runs its
# client in a SUBPROCESS so the SSL_CERT_FILE override that stands in
# for "system roots" cannot leak into any other test's process.

(use assay)
(import jsec/tls :as tls)
(import jsec/ca)
(import ../helpers :prefix "")

(def ca-a
  (ca/generate {:common-name "jsec tls-opts test CA A"
                :key-type :ec-p256
                :days-valid 1}))

(def ca-b
  (ca/generate {:common-name "jsec tls-opts test CA B"
                :key-type :ec-p256
                :days-valid 1}))

(def leaf
  (:issue ca-a {:common-name "server.example"
                :san ["DNS:server.example"]
                :key-type :ec-p256
                :days-valid 1}))

(defn- abspath
  "Absolute path for a possibly-relative scratch path."
  [p]
  (if (string/has-prefix? "/" p) p (string (os/cwd) "/" p)))

(defn- write-pem
  "Write PEM text to a file under the given scratch dir; returns its path."
  [dir name pem]
  (def path (abspath (string dir "/" name)))
  (spit path pem)
  path)

# Child program for (a-2). Regenerates no certs: the parent passes file
# paths. The child re-points the default verify paths (SSL_CERT_FILE) at
# CA A's PEM, so "system roots" for this process is exactly CA A. It
# then connects with :ca pointing at CA B: correct behaviour rejects the
# certificate (outside the supplied CA), the defect accepts it (verified
# against the SSL_CERT_FILE stand-in for system roots).
(def- child-template
  ``
(import jsec/tls :as tls)

(os/setenv "SSL_CERT_FILE" "%s")

(def leaf-cert (slurp "%s"))
(def leaf-key (slurp "%s"))

(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))

(ev/go (fn []
         (try
           (with [conn (:accept server)]
             (with [s (tls/wrap conn {:cert leaf-cert :key leaf-key})]
               (:write s "ok")
               (ev/sleep 2)))
           ([err] nil))))

(def out
  (try
    (with [c (tls/connect host (string port)
                          {:verify true
                           :ca "%s"
                           :hostname "server.example"})]
      (def data (:read c 2 nil 5.0))
      (string "RESULT:accepted:" (describe data)))
    ([err] (string "RESULT:rejected:" err))))
(print out)
(os/exit 0)
``)

(defn- run-ca-restrict-child
  "Spawn the (a-2) scenario in a child janet. Returns
   {:exit n :out stdout :err stderr}."
  [ca-a-path cert-path key-path ca-b-path]
  (def program
    (string/format child-template ca-a-path cert-path key-path ca-b-path))
  (def proc (os/spawn ["janet" "-e" program] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(def-suite :name "TLS Ignored Security Options Regression"
  :description "Ticket 14044e9441: client :ca, new-context :ca/:trusted-cert, and :context :verify-hostname are silently ignored"

  (def-test "client-ca-option-must-use-the-supplied-ca"
    :timeout 20

    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))

    (let [[server _] (make-server :tcp)
          [host port] (net/localname server)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 1.0)))
                   ([_] nil))))

        (var err nil)
        (var data nil)
        (try
          (with [c (tls/connect host (string port)
                                {:verify true
                                 :ca ca-a-path
                                 :hostname "server.example"})]
            (set data (:read c 2 nil 5.0)))
          ([e] (set err e)))

        (assert (nil? err)
                (string/format
                  (string "tls/connect with :ca pointing at the issuing CA "
                          "must verify the server certificate and connect - "
                          "the certificate is issued by exactly that CA; the "
                          "handshake failed: %v (the client path never reads "
                          ":ca - src/jtls/api/connect.c:208-249 and :501-552 "
                          "- so the supplied CA is dropped and verification "
                          "falls back to system roots, "
                          "src/jtls/context/client.c:28)")
                  err))
        (assert (= "ok" (string data))
                "the verified connection must carry application data"))))

  (def-test "client-ca-option-must-reject-certs-outside-the-supplied-ca"
    :timeout 30

    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))
    (def ca-b-path (write-pem (scratch-dir) "ca-b.pem" (ca/get-cert ca-b)))
    (def cert-path (write-pem (scratch-dir) "leaf-cert.pem" (leaf :cert)))
    (def key-path (write-pem (scratch-dir) "leaf-key.pem" (leaf :key)))

    (def child (run-ca-restrict-child ca-a-path cert-path key-path ca-b-path))
    (def out (child :out))
    (def err (child :err))

    (assert (string/find "RESULT:rejected" out)
            (string/format
              (string "tls/connect with :ca ca-B.pem must REJECT a "
                      "certificate that is outside ca-B.pem even though that "
                      "certificate verifies against the SSL_CERT_FILE "
                      "stand-in for system roots - the supplied CA must be "
                      "the trust source; the connection was ACCEPTED "
                      "(silent fallback: verification used system roots and "
                      "ignored :ca). child exit status %d; child stdout: %s; "
                      "child stderr: %s")
              (child :exit) (string/trim out) (string/trim err))))

  (def-test "context-path-verify-hostname-mismatch-must-fail"
    :timeout 20

    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))
    (def ctx (tls/new-context {:verify true
                               :security {:ca-file ca-a-path}}))

    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 1.0)))
                   ([_] nil))))

        (var err nil)
        (var data nil)
        (try
          (with [conn (make-client-conn :tcp addr)]
            (with [c (tls/wrap conn {:context ctx
                                     :hostname "server.example"
                                     :verify-hostname "attacker.example"})]
              (set data (:read c 2 nil 5.0))))
          ([e] (set err e)))

        (assert (not (nil? err))
                (string/format
                  (string "tls/wrap with {:context ctx :hostname "
                          "\"server.example\" :verify-hostname "
                          "\"attacker.example\"} must FAIL hostname "
                          "verification - the certificate is issued for "
                          "server.example and the caller demanded "
                          "attacker.example; the connection SUCCEEDED (%s "
                          "carried) because the :context path never reads "
                          ":verify-hostname (src/jtls/api/connect.c:162-180 "
                          "jumps to common_setup before :202-205) and "
                          "verification silently used :hostname")
                  (describe data))))))

  (def-test "context-path-verify-hostname-match-must-succeed"
    :timeout 20

    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))
    (def ctx (tls/new-context {:verify true
                               :security {:ca-file ca-a-path}}))

    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 1.0)))
                   ([_] nil))))

        (var err nil)
        (var data nil)
        (try
          (with [conn (make-client-conn :tcp addr)]
            (with [c (tls/wrap conn {:context ctx
                                     :hostname "attacker.example"
                                     :verify-hostname "server.example"})]
              (set data (:read c 2 nil 5.0))))
          ([e] (set err e)))

        (assert (nil? err)
                (string/format
                  (string "tls/wrap with {:context ctx :hostname "
                          "\"attacker.example\" :verify-hostname "
                          "\"server.example\"} must connect because "
                          ":verify-hostname selects the certificate name to "
                          "verify; the handshake failed: %v (:verify-hostname "
                          "is ignored on the :context path, so verification "
                          "used the :hostname value attacker.example and the "
                          "certificate for server.example cannot match)")
                  err))
        (assert (= "ok" (string data))
                "the verified connection must carry application data"))))

  (def-test "new-context-ca-option-must-be-honored"
    :timeout 20

    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))
    (def ctx (tls/new-context {:verify true :ca ca-a-path}))

    (let [[server _] (make-server :tcp)
          [host port] (net/localname server)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 1.0)))
                   ([_] nil))))

        (var err nil)
        (var data nil)
        (try
          (with [c (tls/connect host (string port)
                                {:context ctx
                                 :hostname "server.example"})]
            (set data (:read c 2 nil 5.0)))
          ([e] (set err e)))

        (assert (nil? err)
                (string/format
                  (string "tls/new-context with {:ca ca-A.pem} must build a "
                          "context that trusts the supplied CA - a "
                          "tls/connect through that context to its issuer's "
                          "certificate must verify; the handshake failed: %v "
                          "(the new-context client path reads only "
                          ":verify/:security - src/jtls/api/context.c:132-143 "
                          "- so :ca is dropped and the context trusts only "
                          "system roots)")
                  err))
        (assert (= "ok" (string data))
                "the verified connection must carry application data"))))

  (def-test "new-context-trusted-cert-option-must-be-honored"
    :timeout 20

    (def ctx (tls/new-context {:verify true
                               :trusted-cert (ca/get-cert ca-a)}))

    (let [[server _] (make-server :tcp)
          [host port] (net/localname server)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 1.0)))
                   ([_] nil))))

        (var err nil)
        (var data nil)
        (try
          (with [c (tls/connect host (string port)
                                {:context ctx
                                 :hostname "server.example"})]
            (set data (:read c 2 nil 5.0)))
          ([e] (set err e)))

        (assert (nil? err)
                (string/format
                  (string "tls/new-context with {:trusted-cert ca-A.pem} "
                          "must build a context that trusts that "
                          "certificate - a tls/connect through that context "
                          "to a certificate it issued must verify; the "
                          "handshake failed: %v (the new-context client "
                          "path reads only :verify/:security - "
                          "src/jtls/api/context.c:132-143 - so "
                          ":trusted-cert is dropped and the context trusts "
                          "only system roots)")
                  err))
        (assert (= "ok" (string data))
                "the verified connection must carry application data")))))
