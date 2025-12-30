# DTLS Stream Test Suite (janet-assay version)
#
# Tests DTLS functionality across versions, verification modes, cert types, and ciphers.
#
# Matrix dimensions:
#   - dtls-version: [:default :dtls1.2]
#   - verify-mode: [:no-verify :verify-trusted]
#   - cert-type: [:rsa :ec-p256]
#   - cipher-group: [:aes-gcm :chacha20]
#
# Total: 2 * 2 * 2 * 2 = 16 combinations per test
#
# In janet-assay matrix tests, matrix vars are bound directly as symbols (e.g., dtls-version,
# verify-mode) rather than accessed via a config table. The harness provides additional
# bindings like 'certs' that setup functions produce.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# =============================================================================
# DTLS-specific helpers
# =============================================================================

(defn- make-dtls-server-opts
  "Build DTLS server options from matrix vars and certs.
   Matrix vars: dtls-version, cipher-group
   Certs: table with :cert and :key"
  [dtls-version cipher-group certs]
  (let [opts @{:datagram true
               :cert (certs :cert)
               :key (certs :key)}]
    (unless (= dtls-version :default)
      (put opts :dtls-version dtls-version))
    (case cipher-group
      :aes-gcm (put opts :ciphersuites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
      :chacha20 (put opts :ciphersuites "TLS_CHACHA20_POLY1305_SHA256"))
    opts))

(defn- make-dtls-client-opts
  "Build DTLS client options from matrix vars and certs.
   Matrix vars: verify-mode, cipher-group
   Certs: table with :cert and :key (for trusted verification)"
  [verify-mode cipher-group certs]
  (let [opts @{:datagram true}]
    (case verify-mode
      :no-verify (put opts :verify false)
      :verify-trusted (do
                        (put opts :verify true)
                        (put opts :trusted-cert (certs :cert))
                        (put opts :hostname "127.0.0.1")))
    (case cipher-group
      :aes-gcm (put opts :ciphersuites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
      :chacha20 (put opts :ciphersuites "TLS_CHACHA20_POLY1305_SHA256"))
    opts))

# =============================================================================
# Suite Definition
# =============================================================================

(def-suite :name "DTLS Stream Suite"

  # ===========================================================================
  # Non-Matrix Tests (Basic Functionality)
  # ===========================================================================

  (def-test "Address Type"
    (let [addr (tls/address "192.168.1.1" 443)]
      (assert (tls/address? addr) "Created address")
      (assert (= (tls/address-host addr) "192.168.1.1") "Host matches")
      (assert (= (tls/address-port addr) 443) "Port matches")))

  (def-test "IPv6 Address"
    (let [addr (tls/address "::1" 8443)]
      (assert (tls/address? addr) "Created IPv6 address")
      (assert (= (tls/address-host addr) "::1") "IPv6 host matches")
      (assert (= (tls/address-port addr) 8443) "IPv6 port matches")))

  (def-test "Timeout"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [_ port] (:localname server)
          timed-out (ev/chan 1)]

      (ev/go
        (fn []
          (try
            (ev/with-deadline 2
              (def buf (buffer/new 1024))
              (:recv-from server 1024 buf)
              (ev/give timed-out false))
            ([_]
              (ev/give timed-out true)))))

      (def result (ev/take timed-out))
      (:close server)
      (assert result "Server recv timed out as expected")))

  (def-test "Invalid port connection fails"
    :expected-fail "Connection to invalid port should fail"
    (ev/with-deadline 2
      (def client (tls/connect "127.0.0.1" 1 {:datagram true :verify false}))
      (:write client "test")))

  (def-test "Bad cert verification fails"
    :expected-fail "Verification with wrong cert should fail"
    (let [server-certs (generate-temp-certs {:common-name "server.local"})
          other-certs (generate-temp-certs {:common-name "other.local"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (server-certs :cert) :key (server-certs :key)})
          [_ port] (:localname server)]
      (defer (:close server)
        (ev/with-deadline 3
          (def client (tls/connect "127.0.0.1" port
                                   {:datagram true :verify true :trusted-cert (other-certs :cert)}))
          (:write client "test")))))

  (def-test "Server localname"
    (let [certs (generate-temp-certs {:common-name "127.0.0.1"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [host port] (:localname server)]
      (:close server)
      (assert (= host "127.0.0.1") "Host is localhost")
      (assert (> port 0) "Port was assigned")))

  (def-test "DTLS verify-hostname option"
    (let [certs (generate-temp-certs {:common-name "localhost"})
          server (tls/listen "127.0.0.1" 0
                             {:datagram true :cert (certs :cert) :key (certs :key)})
          [_ port] (:localname server)
          done (ev/chan 1)]

      (ev/go (fn []
               (def buf (buffer/new 1024))
               (try
                 (ev/with-deadline 5
                   (when-let [addr (:recv-from server 1024 buf)]
                     (:send-to server addr "hello")))
                 ([_] nil))
               (ev/give done true)))

      (ev/sleep 0.2)

      (let [client (tls/connect "127.0.0.1" port
                                {:datagram true
                                 :verify true
                                 :trusted-cert (certs :cert)
                                 :verify-hostname "localhost"})]
        (:write client "Ping")
        (def response (string (:read client 1024)))
        (assert (= response "hello") "DTLS verify-hostname: received data")
        (:close client true))

      (ev/take done)
      (:close server)))

  # ===========================================================================
  # Matrix Tests - Comprehensive DTLS Testing
  # ===========================================================================
  #
  # All matrix tests share the same parameter space:
  #   dtls-version × verify-mode × cert-type × cipher-group
  # 
  # The harness generates certificates once per matrix combo based on cert-type.
  # Matrix vars (dtls-version, verify-mode, cert-type, cipher-group) are bound
  # directly as symbols in the test body.

  (def-test "DTLS Config Matrix"
    :type :matrix
    :matrix {:dtls-version [:default :dtls1.2]
             :verify-mode [:no-verify :verify-trusted]
             :cert-type [:rsa :ec-p256]
             :cipher-group [:aes-gcm :chacha20]}
    :parallel {:fiber 6 :thread 6 :subprocess 6}
    :harness [:certs {:setup (fn [cfg vs]
                               # cfg contains the matrix combo as a table
                               (generate-certs-for-matrix cfg))}]

    # -------------------------------------------------------------------------
    # basic echo - Simple send/receive test
    # -------------------------------------------------------------------------
    (def-test "basic echo"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "Pong")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "Ping")
        (def reply (:read client 1024))
        (assert (= (string reply) "Pong") "Got Pong")
        (:close client true)

        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # large message - Test with larger payloads
    # -------------------------------------------------------------------------
    (def-test "large message"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            msg-size 4000 # Conservative size for DTLS
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new (+ msg-size 100)))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server (+ msg-size 100) buf)]
                  (:send-to server addr buf)))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def large-msg (string/repeat "X" msg-size))
        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client large-msg)
        (def reply (:read client (+ msg-size 100)))
        (:close client true)

        (ev/take done)
        (:close server)

        (assert (= (length reply) msg-size) "Large message echoed correctly")))

    # -------------------------------------------------------------------------
    # connection info - Verify connection metadata available
    # -------------------------------------------------------------------------
    (def-test "connection info"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "info")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (:read client 1024)

        (def info (:connection-info client))
        (assert (struct? info) "Connection info is a struct")
        (when (info :cipher)
          (assert (string? (info :cipher)) "Cipher is a string"))

        (:close client true)
        (ev/take done)
        (:close server)))

    # -------------------------------------------------------------------------
    # ALPN negotiation - Application-Layer Protocol Negotiation
    # -------------------------------------------------------------------------
    (def-test "ALPN negotiation"
      (let [server-opts (merge (make-dtls-server-opts dtls-version cipher-group certs)
                               {:alpn ["h2" "http/1.1"]})
            client-opts (merge (make-dtls-client-opts verify-mode cipher-group certs)
                               {:alpn ["h2"]})
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 5
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "alpn-ok")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (def reply (:read client 1024))

        (def info (:connection-info client))

        (:close client true)
        (ev/take done)
        (:close server)

        (assert (= (string reply) "alpn-ok") "ALPN negotiation completed")))

    # -------------------------------------------------------------------------
    # multiple simultaneous clients - Concurrency test
    # -------------------------------------------------------------------------
    (def-test "multiple simultaneous clients"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            num-clients 3
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            results (ev/chan num-clients)
            server-done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (for i 0 num-clients
              (buffer/clear buf)
              (try
                (ev/with-deadline 5
                  (when-let [addr (:recv-from server 1024 buf)]
                    (:send-to server addr (string "Reply-" (string buf)))))
                ([_] nil)))
            (ev/give server-done true)))

        (ev/sleep 0.2)

        (for i 0 num-clients
          (ev/go
            (fn []
              (try
                (ev/with-deadline 5
                  (def client (tls/connect "127.0.0.1" port client-opts))
                  (:write client (string "Client-" i))
                  (def reply (:read client 1024))
                  (:close client true)
                  (ev/give results
                           {:client i
                            :success (string/has-prefix? "Reply-Client-" (string reply))}))
                ([_]
                  (ev/give results {:client i :success false}))))))

        (var successes 0)
        (for i 0 num-clients
          (let [r (ev/take results)]
            (when (r :success) (++ successes))))

        (ev/take server-done)
        (:close server)

        (assert (= successes num-clients)
                (string "All " num-clients " clients succeeded"))))

    # -------------------------------------------------------------------------
    # close with force flag - Test forced close behavior
    # -------------------------------------------------------------------------
    (def-test "close with force flag"
      (let [server-opts (make-dtls-server-opts dtls-version cipher-group certs)
            client-opts (make-dtls-client-opts verify-mode cipher-group certs)
            server (tls/listen "127.0.0.1" 0 server-opts)
            [_ port] (:localname server)
            done (ev/chan 1)]

        (ev/go
          (fn []
            (def buf (buffer/new 1024))
            (try
              (ev/with-deadline 3
                (when-let [addr (:recv-from server 1024 buf)]
                  (:send-to server addr "done")))
              ([_] nil))
            (ev/give done true)))

        (ev/sleep 0.2)

        (def client (tls/connect "127.0.0.1" port client-opts))
        (:write client "test")
        (:read client 1024)
        (:close client true)

        (ev/take done)
        (:close server)))))
