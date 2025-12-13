###
### Coverage tests for jsec/dtls-stream internal API
###
### These tests exercise the low-level dtls-stream module directly.
### Users should use jsec/tls with :datagram true instead.
###

(import assay)
(import jsec/dtls-stream)
(import jsec/cert)
(import ../helpers :prefix "")

(assay/def-suite :name "DTLS Stream Internal API Coverage"
                 :timeout 30

                 # =============================================================================
                 # Direct Function Tests (internal API)
                 # =============================================================================

                 (assay/def-test "new-context creates context directly"
                                 (let [ctx (dtls-stream/new-context {:verify false})]
                                   (assay/assert ctx "Created context")
                                   (assay/assert (abstract? ctx) "Context is abstract type")))

                 (assay/def-test "address functions work directly"
                                 (let [addr (dtls-stream/address "192.168.1.1" 443)]
                                   (assay/assert (dtls-stream/address? addr) "address? works")
                                   (assay/assert (= (dtls-stream/address-host addr) "192.168.1.1") "address-host works")
                                   (assay/assert (= (dtls-stream/address-port addr) 443) "address-port works")))

                 (assay/def-test "listen creates server directly"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})]
                                   (defer (:close server)
                                     (assay/assert server "Created server")
                                     (let [[_ port] (dtls-stream/localname server)]
                                       (assay/assert (> port 0) "Server has valid port")))))

                 (assay/def-test "connect and read/write work directly"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     # Server fiber
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "Pong"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     # Client using dtls-stream/connect directly
                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "Ping")
                                         (let [reply (dtls-stream/read client 1024)]
                                           (assay/assert (= (string reply) "Pong") "Direct connect/read/write works"))))

                                     (ev/take done))))

                 (assay/def-test "recv-from and send-to work directly"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     # Server using recv-from/send-to directly
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              # Use dtls-stream/recv-from directly
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                # Use dtls-stream/send-to directly
                                                (dtls-stream/send-to server addr (string "echo:" (string buf))))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test-data")
                                         (let [reply (dtls-stream/read client 1024)]
                                           (assay/assert (= (string reply) "echo:test-data") "recv-from/send-to work"))))

                                     (ev/take done))))

                 (assay/def-test "upgrade raw UDP socket to DTLS"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "upgraded"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     # Create raw UDP socket and upgrade
                                     (let [raw-sock (net/connect "127.0.0.1" port :datagram)
                                           client (dtls-stream/upgrade raw-sock {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         (let [reply (dtls-stream/read client 1024)]
                                           (assay/assert (= (string reply) "upgraded") "upgrade works"))))

                                     (ev/take done))))

                 (assay/def-test "chunk reads exact bytes"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "ChunkData1"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         # Use dtls-stream/chunk directly
                                         (let [reply (dtls-stream/chunk client 10)]
                                           (assay/assert (buffer? reply) "chunk returns buffer")
                                           (assay/assert (= (string reply) "ChunkData1") "chunk reads correct data"))))

                                     (ev/take done))))

                 (assay/def-test "shutdown connection"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "before-shutdown"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         (dtls-stream/read client 1024)
                                         # Use dtls-stream/shutdown directly
                                         (dtls-stream/shutdown client)))

                                     (ev/take done))))

                 (assay/def-test "session and session-reused? functions"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "session"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         (dtls-stream/read client 1024)

                                         # Test session directly
                                         (let [session (dtls-stream/session client)]
                                           (assay/assert (buffer? session) "session returns buffer"))

                                         # Test session-reused? directly
                                         (let [reused (dtls-stream/session-reused? client)]
                                           (assay/assert (boolean? reused) "session-reused? returns boolean"))))

                                     (ev/take done))))

                 (assay/def-test "connection info version/cipher/bits/info"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "info"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         (dtls-stream/read client 1024)

                                         # Test version directly
                                         (let [ver (dtls-stream/version client)]
                                           (assay/assert (string? ver) "version returns string")
                                           (assay/assert (string/has-prefix? "DTLS" ver) "version starts with DTLS"))

                                         # Test cipher directly
                                         (let [cipher (dtls-stream/cipher client)]
                                           (assay/assert (string? cipher) "cipher returns string"))

                                         # Test cipher-bits directly
                                         (let [bits (dtls-stream/cipher-bits client)]
                                           (assay/assert (number? bits) "cipher-bits returns number")
                                           (assay/assert (>= bits 128) "cipher bits >= 128"))

                                         # Test connection-info directly
                                         (let [info (dtls-stream/connection-info client)]
                                           (assay/assert (struct? info) "connection-info returns struct")
                                           (assay/assert (info :version) "info has :version")
                                           (assay/assert (info :cipher) "info has :cipher"))))

                                     (ev/take done))))

                 (assay/def-test "localname and peername"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "names"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/write client "test")
                                         (dtls-stream/read client 1024)

                                         # Test peername directly
                                         (let [peer (dtls-stream/peername client)]
                                           (assay/assert (dtls-stream/address? peer) "peername returns address")
                                           (assay/assert (= (dtls-stream/address-port peer) port) "peername port matches"))))

                                     (ev/take done))))

                 (assay/def-test "trust-cert on connection"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})
                                       [_ port] (dtls-stream/localname server)
                                       done (ev/chan 1)]
                                   (defer (:close server)
                                     (ev/go (fn []
                                              (def buf (buffer/new 1024))
                                              (def addr (dtls-stream/recv-from server 1024 buf))
                                              (when addr
                                                (dtls-stream/send-to server addr "trusted"))
                                              (ev/give done true)))

                                     (ev/sleep 0.2)

                                     # Client with trust-cert
                                     (let [client (dtls-stream/connect "127.0.0.1" port {:verify false})]
                                       (defer (:close client true)
                                         (dtls-stream/trust-cert client (certs :cert))
                                         (dtls-stream/write client "test")
                                         (let [reply (dtls-stream/read client 1024)]
                                           (assay/assert (= (string reply) "trusted") "trust-cert works"))))

                                     (ev/take done))))

                 (assay/def-test "close-server"
                                 :harness [:certs {:setup (fn [_ _] (cert/generate-self-signed-cert {:common-name "127.0.0.1"}))}]
                                 (let [server (dtls-stream/listen "127.0.0.1" 0 {:cert (certs :cert) :key (certs :key)})]
                                   # Use dtls-stream/close-server directly
                                   (dtls-stream/close-server server)
                                   (assay/assert true "close-server works"))))
