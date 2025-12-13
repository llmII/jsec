# Cert Test Suite (janet-assay version)
#
# Tests for jsec's certificate generation and loading.

(import assay)
(import jsec/cert :as cert)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import ../helpers :prefix "")

(assay/def-suite :name "Cert Suite"

                 (assay/def-test "Generate Self-Signed Cert"
                                 (let [certs (cert/generate-self-signed-cert {:common-name "test-cert"})]
                                   (assay/assert (string? (certs :cert)) "Cert is string")
                                   (assay/assert (string? (certs :key)) "Key is string")
                                   (assay/assert (> (length (certs :cert)) 0) "Cert not empty")
                                   (assay/assert (> (length (certs :key)) 0) "Key not empty")))

                 (assay/def-test "Buffer Cert Loading"
                                 (let [server-certs (cert/generate-self-signed-cert {:common-name "127.0.0.1"})
                                       cert-pem (server-certs :cert)
                                       key-pem (server-certs :key)
                                       server-done (ev/chan 1)]

                                   (ev/go (fn []
                                            (try
                                              (let [listener (tls-stream/listen "127.0.0.1" "0")
                                                    addr (net/localname listener)
                                                    port (string (addr 1))]
                                                (ev/give server-done port)
                                                (let [ctx (tls-stream/new-context {:cert cert-pem :key key-pem})]
                                                  (let [client (tls-stream/accept listener ctx)]
                                                    (defer (:close client)
                                                      (:read client 1024)
                                                      (:write client "OK")))))
                                              ([err] (ev/give server-done err)))))

                                   (let [raw-port (ev/take server-done)
                                         port (if (number? raw-port) (string raw-port) raw-port)]
                                     (if (string? port)
                                       (do
                                         (ev/sleep 0.1)
                                         (let [s1 (tls/connect "127.0.0.1" port {:hostname "127.0.0.1"
                                                                                 :security {:ca-file cert-pem}})]
                                           (defer (:close s1)
                                             (:write s1 "Hello")
                                             (let [response (:read s1 1024)]
                                               (assay/assert (= (string response) "OK") "Received OK")))))
                                       (error port)))))

                 (assay/def-test "Malformed cert data"
                                 (assert-error (tls-stream/new-context {:cert "NOT A VALID CERTIFICATE"
                                                                        :key "NOT A VALID KEY"})))

                 (assay/def-test "Invalid options type"
                                 (assert-error (cert/generate-self-signed-cert "not-a-table")))

                 (assay/def-test "Valid minimal options"
                                 (let [certs (cert/generate-self-signed-cert)]
                                   (assay/assert (certs :cert) "Has cert")
                                   (assay/assert (certs :key) "Has key"))))
