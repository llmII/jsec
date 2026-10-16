# Wrap shared cached server SSL_CTX mutation regression test
# Ticket c60a17183aabe6d26a8c44d9ca6877448932f9201
#
# "cfun_wrap mutates the shared cached server SSL_CTX"
#
# Mechanism (this tree, 0.2.0 basis at 599e82e288):
#   src/jtls/api/connect.c:108-109  cfun_wrap's server mode calls
#     jtls_create_server_ctx(cert, key, security_opts, alpn_opt, 1) -
#     use_cache = 1 - so it may get back the process-global cached
#     server SSL_CTX
#   src/jtls/context/server.c:278-287  the cache-hit path returns that
#     shared ctx (SSL_CTX_up_ref at :283)
#   src/jtls/context/server.c:111-150  check_cache_hit keys the cache on
#     cert + key + ALPN only - verify/trusted/ca/:security are not part
#     of the key
#   and then cfun_wrap mutates the returned ctx in place:
#     src/jtls/api/connect.c:118-120  SSL_CTX_set_verify(ctx,
#       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) for a
#       {:verify true} wrap (gated at :115-116)
#     src/jtls/api/connect.c:127  jtls_add_trusted_cert for :trusted-cert
#       (block :123-131)
#     src/jtls/api/connect.c:138  SSL_CTX_load_verify_locations for :ca
#       (block :133-144)
#   src/jtls/context/server.c:328  :security is applied only when the
#     ctx is CREATED, so a cache-hit wrap's own :security is silently
#     dropped and the cached ctx keeps whatever the first wrap applied.
#
# This test demonstrates:
#   (a) a per-connection {:verify true} wrap does not turn on mandatory
#       client-cert auth for a later default-configured wrap of the same
#       cert+key - the second connection must accept a client that
#       presents no certificate,
#   (b) a per-connection :ca / :trusted-cert / :security {:ca-file}
#       config does not leak trust anchors into a later wrap of the same
#       cert+key - the second connection (verify on, no trust options)
#       must REJECT a client certificate issued by the first wrap's CA.
#
# Proof contract: under the defect (a) fails with the second,
# default-configured connection REJECTED because the shared cached
# SSL_CTX still carries SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT
# from the first wrap, and each (b) guard fails with the second
# connection SUCCEEDED - the client certificate from the first wrap's CA
# was ACCEPTED by the shared cached SSL_CTX. Exactly those symptoms and
# nothing else; under the fix all four tests pass and guard the fix.
# Each test uses its own server certificate so the one-slot cache
# (src/jtls/context/server.c:162-163, :189) cannot bleed state between
# tests.

(use assay)
(import jsec/tls :as tls)
(import jsec/ca)
(import ../helpers :prefix "")

(def ca-a
  (ca/generate {:common-name "jsec wrap-ctx test CA A"
                :key-type :ec-p256
                :days-valid 1}))

(def client-leaf
  (:issue ca-a {:common-name "client.example"
                :extended-key-usage "clientAuth"
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

(defn- make-test-leaf
  "Fresh server leaf for one test - unique key so the server ctx cache
   cannot match across tests."
  [cn]
  (:issue ca-a {:common-name cn
                :san [(string "DNS:" cn)]
                :key-type :ec-p256
                :days-valid 1}))

(defn- serve-one
  "Server fiber: accept one connection, wrap it with wrap-opts, read 4
   bytes, write \"pong\". Gives [:ok] or [:err e] on the returned
   channel."
  [server wrap-opts]
  (def ch (ev/chan 1))
  (ev/go (fn []
           (try
             (with [conn (:accept server)]
               (with [s (tls/wrap conn wrap-opts)]
                 (def msg (:read s 4 nil 5.0))
                 (:write s "pong")))
             ([e] (ev/give ch [:err e])))
           (ev/give ch [:ok])))
  ch)

(defn- client-ping
  "Client side of one scenario: connect, wrap with client-opts, write
   \"ping\", read the pong. Returns nil on success, the error otherwise."
  [addr client-opts &opt hostname]
  (try
    (do
      (with [conn (make-client-conn :tcp addr)]
        (with [c (if hostname
                   (tls/wrap conn hostname client-opts)
                   (tls/wrap conn client-opts))]
          (:write c "ping")
          (def pong (:read c 4 nil 5.0))
          (assert (= "pong" (string pong))
                  "echo round trip should deliver the pong")))
      nil)
    ([e] e)))

(def-suite :name "Wrap Shared Server Ctx Mutation Regression"
  :description "Ticket c60a17183a: cfun_wrap mutates the shared cached server SSL_CTX (verify/trust leak across wraps)"

  (def-test "per-connection-verify-config-must-not-leak-into-default-wrap"
    :timeout 20

    (def leaf (make-test-leaf "wrap-verify-leak.example"))
    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        # Scenario A (control): the {:verify true} wrap itself must demand
        # a client certificate on ITS connection - the option is real on
        # its own ctx (SSL_CTX_set_verify at src/jtls/api/connect.c:118-120).
        (def a-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true}))
        (def a-err (client-ping addr {:verify false}))
        (def a-srv (ev/take a-server))
        (assert (not (nil? a-err))
                (string/format
                  (string "control: a {:verify true} wrap must demand a "
                          "client certificate on its own connection "
                          "(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT "
                          "at src/jtls/api/connect.c:118-120); the "
                          "connection SUCCEEDED with no client certificate")
                  ))

        # Scenario B (the leak): a default-configured wrap of the SAME
        # cert+key must see unchanged verify state and accept a client
        # with no certificate.
        (def b-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)}))
        (def b-err (client-ping addr {:verify false}))
        (def b-srv (ev/take b-server))
        (assert (nil? b-err)
                (string/format
                  (string "the default-configured wrap of the same cert+key "
                          "must accept a client with no certificate - the "
                          "per-connection {:verify true} of the previous "
                          "wrap must not leak into the shared cached "
                          "SSL_CTX; the handshake failed: %v (the cached "
                          "ctx at src/jtls/context/server.c:278-287 is "
                          "keyed on cert+key+ALPN only, "
                          "src/jtls/context/server.c:111-150, and still "
                          "carries SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_"
                          "PEER_CERT from src/jtls/api/connect.c:118-120)")
                  b-err)))))

  (def-test "per-connection-ca-config-must-not-leak-into-later-verify-wrap"
    :timeout 20

    (def leaf (make-test-leaf "wrap-ca-leak.example"))
    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))

    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        # Scenario A (control): the :ca wrap trusts CA A on its own
        # connection - a client certificate issued by CA A verifies.
        (def a-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true
                                         :ca ca-a-path}))
        (def a-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-ca-leak.example"))
        (def a-srv (ev/take a-server))
        (assert (nil? a-err)
                (string/format
                  (string "control: a {:verify true :ca ca-A.pem} wrap must "
                          "accept a client certificate issued by CA A; the "
                          "handshake failed: %v")
                  a-err))

        # Scenario B (the leak): a later {:verify true} wrap with no
        # trust options of the SAME cert+key must reject a certificate
        # that is outside its trust state.
        (def b-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true}))
        (def b-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-ca-leak.example"))
        (def b-srv (ev/take b-server))
        (assert (not (nil? b-err))
                (string/format
                  (string "the later {:verify true} wrap of the same "
                          "cert+key, carrying no trust options, must "
                          "REJECT a client certificate from the previous "
                          "wrap's :ca - trust anchors must not leak into "
                          "the shared cached SSL_CTX; the connection "
                          "SUCCEEDED (the certificate from CA A was "
                          "ACCEPTED because SSL_CTX_load_verify_locations "
                          "at src/jtls/api/connect.c:138 mutated the "
                          "cached ctx keyed on cert+key+ALPN only, "
                          "src/jtls/context/server.c:111-150)"))))))

  (def-test "per-connection-trusted-cert-must-not-leak-into-later-verify-wrap"
    :timeout 20

    (def leaf (make-test-leaf "wrap-trusted-leak.example"))

    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        # Scenario A (control): the :trusted-cert wrap trusts CA A's
        # certificate on its own connection.
        (def a-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true
                                         :trusted-cert (ca/get-cert ca-a)}))
        (def a-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-trusted-leak.example"))
        (def a-srv (ev/take a-server))
        (assert (nil? a-err)
                (string/format
                  (string "control: a {:verify true :trusted-cert ca-A} "
                          "wrap must accept a client certificate issued by "
                          "CA A; the handshake failed: %v")
                  a-err))

        # Scenario B (the leak).
        (def b-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true}))
        (def b-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-trusted-leak.example"))
        (def b-srv (ev/take b-server))
        (assert (not (nil? b-err))
                (string/format
                  (string "the later {:verify true} wrap of the same "
                          "cert+key, carrying no trust options, must "
                          "REJECT a client certificate from the previous "
                          "wrap's :trusted-cert - trust anchors must not "
                          "leak into the shared cached SSL_CTX; the "
                          "connection SUCCEEDED (the certificate from CA A "
                          "was ACCEPTED because jtls_add_trusted_cert at "
                          "src/jtls/api/connect.c:127 mutated the cached "
                          "ctx keyed on cert+key+ALPN only, "
                          "src/jtls/context/server.c:111-150)"))))))

  (def-test "per-connection-security-ca-file-must-not-leak-into-later-verify-wrap"
    :timeout 20

    (def leaf (make-test-leaf "wrap-security-leak.example"))
    (def ca-a-path (write-pem (scratch-dir) "ca-a.pem" (ca/get-cert ca-a)))

    (let [[server _] (make-server :tcp)
          addr (get-server-addr server :tcp nil)]

      (defer (:close server)

        # Scenario A (control): the :security {:ca-file} wrap trusts CA A
        # on its own connection (applied at ctx creation,
        # src/jtls/context/server.c:328).
        (def a-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true
                                         :security {:ca-file ca-a-path}}))
        (def a-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-security-leak.example"))
        (def a-srv (ev/take a-server))
        (assert (nil? a-err)
                (string/format
                  (string "control: a {:verify true :security {:ca-file "
                          "ca-A.pem}} wrap must accept a client "
                          "certificate issued by CA A; the handshake "
                          "failed: %v")
                  a-err))

        # Scenario B (the leak): a later {:verify true} wrap with no
        # :security of the SAME cert+key must not inherit CA A - the
        # cache hit drops the later wrap's own :security and hands back
        # the first wrap's trust state.
        (def b-server (serve-one server {:cert (leaf :cert)
                                         :key (leaf :key)
                                         :verify true}))
        (def b-err (client-ping addr {:verify false
                                      :cert (client-leaf :cert)
                                      :key (client-leaf :key)}
                               "wrap-security-leak.example"))
        (def b-srv (ev/take b-server))
        (assert (not (nil? b-err))
                (string/format
                  (string "the later {:verify true} wrap of the same "
                          "cert+key, carrying no trust options, must "
                          "REJECT a client certificate from the previous "
                          "wrap's :security {:ca-file} - trust anchors "
                          "must not leak into the shared cached SSL_CTX; "
                          "the connection SUCCEEDED (the certificate from "
                          "CA A was ACCEPTED because the cache key is "
                          "cert+key+ALPN only, "
                          "src/jtls/context/server.c:111-150, and :security "
                          "is applied only at ctx creation, "
                          "src/jtls/context/server.c:328)")))))))
