# Matrix configuration helpers for jsec TLS/DTLS tests
#
# These helpers convert matrix configuration to TLS context options.

(defn matrix-config->ctx-opts
  ``Convert matrix configuration to TLS context options.
   
   Reads from config:
     :tls-version   - :default, :tls12, :tls13, :dtls1.2
     :tcp-nodelay   - true/false (TCP_NODELAY option)
     :cipher-group  - :aes-gcm, :chacha20
   
   Returns table suitable for passing to tls/wrap, tls/connect, etc.``
  [config]
  (def opts @{})

  # TLS version
  (when-let [tls-ver (config :tls-version)]
    (unless (= tls-ver :default)
      (case tls-ver
        :tls12 (put opts :tls-version :tls12)
        :tls13 (put opts :tls-version :tls13))))

  # DTLS version  
  (when-let [dtls-ver (config :dtls-version)]
    (unless (= dtls-ver :default)
      (put opts :dtls-version dtls-ver)))

  # TCP nodelay
  (when-let [nd (config :tcp-nodelay)]
    (put opts :tcp-nodelay nd))

  # Cipher selection
  (when-let [cg (config :cipher-group)]
    (def tls-ver (or (config :tls-version) :default))
    (case cg
      :aes-gcm
      (if (= tls-ver :tls13)
        (put opts :cipher-suites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
        (put opts :cipher "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"))

      :chacha20
      (if (= tls-ver :tls13)
        (put opts :cipher-suites "TLS_CHACHA20_POLY1305_SHA256")
        (put opts :cipher "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305"))))

  opts)

(defn matrix-config->capabilities
  ``Get TLS capabilities based on matrix configuration.
   
   Returns table indicating what operations are supported:
     {:tls {:renegotiation bool :key-update bool}}``
  [config]
  (def tls-ver (or (config :tls-version) :default))

  (def tls-caps
    (case tls-ver
      :tls12 {:renegotiation true :key-update false}
      :tls13 {:renegotiation false :key-update true}
      # Default - allow both (server/client negotiate)
      {:renegotiation true :key-update true}))

  {:tls tls-caps})
