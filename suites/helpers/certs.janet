# Certificate generation helpers for jsec tests
#
# These helpers generate temporary certificates for testing TLS/DTLS functionality.
# All certificates are generated in-memory (no disk writes).

(import jsec/cert :as cert)

(defn generate-temp-certs
  ``Generate temporary self-signed certificates for testing.
   
   Options:
     :common-name  - Common name for the certificate (default: "localhost")
     :key-type     - Key type :rsa, :ec-p256, :ec-p384, :ec-p521, :ed25519
                     (default: :rsa)
     :bits         - RSA key bits (default: 2048)
     :days         - Validity period in days (default: 1)
   
   Returns table with :cert and :key PEM strings.``
  [&opt opts]
  (default opts @{})
  (def common-name (or (opts :common-name) "localhost"))
  (def key-type (or (opts :key-type) :rsa))

  (def cert-opts @{:common-name common-name
                   :days-valid (or (opts :days) 1)})

  (case key-type
    :rsa (do
           (put cert-opts :key-type :rsa)
           (put cert-opts :bits (or (opts :bits) 2048)))
    :ec (do
          (put cert-opts :key-type :ec-p256))
    :ec-p256 (do
               (put cert-opts :key-type :ec-p256))
    :ec-p384 (do
               (put cert-opts :key-type :ec-p384))
    :ec-p521 (do
               (put cert-opts :key-type :ec-p521))
    :ed25519 (do
               (put cert-opts :key-type :ed25519))
    # Default to RSA
    (do
      (put cert-opts :key-type :rsa)
      (put cert-opts :bits (or (opts :bits) 2048))))

  (cert/generate-self-signed-cert cert-opts))

(defn generate-certs-for-matrix
  ``Generate certificates based on matrix configuration.
   
   Reads :cert-type from config to determine key type:
     :rsa      -> RSA 2048-bit key
     :ec-p256  -> EC P-256 key
   
   Common name defaults to "127.0.0.1" for test compatibility.``
  [config]
  (def key-type (or (config :cert-type) :rsa))
  (def common-name (or (config :common-name) "127.0.0.1"))

  (generate-temp-certs {:common-name common-name
                        :key-type key-type}))
