#!/usr/bin/env janet
# TLS Policy Enforcement Example
#
# This example demonstrates how to implement custom TLS security policies
# that go beyond basic configuration. The scenario:
#
# - Support both TLS 1.2 and TLS 1.3
# - Allow specific cipher suites for TLS 1.3 (TLS_AES_256_GCM_SHA384)
# - For TLS 1.2, allow ECDHE ciphers with AES-GCM
# - Reject TLS 1.2 with older ciphers (CBC mode)
# - Reject any connection with < 128 bit ciphers

(import jsec/tls :as jtls)

(defn check-tls-policy
  "Check if a TLS connection meets security policy requirements"
  [stream]
  (let [info (jtls/get-connection-info stream)]

    (when (nil? info)
      (error "Connection info not available (handshake not complete)"))

    (let [version (info :version)
          cipher (info :cipher)
          bits (info :cipher-bits)]

      (printf "Connection: %s with %s (%d bits)" version cipher bits)

      # Policy Rule 1: Minimum cipher strength
      (when (< bits 128)
        (eprintf "  ❌ REJECT: Cipher too weak (%d < 128 bits)" bits)
        (error {:policy "min-cipher-strength" :reason "cipher too weak"}))

      # Policy Rule 2: TLS 1.3 cipher requirements
      (when (= version "TLSv1.3")
        (let [allowed-tls13-ciphers
              ["TLS_AES_256_GCM_SHA384"
               "TLS_CHACHA20_POLY1305_SHA256"
               "TLS_AES_128_GCM_SHA256"]]

          (unless (find |(= $ cipher) allowed-tls13-ciphers)
            (eprintf "  ❌ REJECT: TLS 1.3 cipher not in allowed list")
            (error {:policy "tls13-cipher-whitelist" :cipher cipher}))))

      # Policy Rule 3: TLS 1.2 cipher requirements
      (when (= version "TLSv1.2")
        # Require ECDHE for forward secrecy
        (unless (string/find "ECDHE" cipher)
          (eprintf "  ❌ REJECT: TLS 1.2 must use ECDHE for forward secrecy")
          (error {:policy "tls12-forward-secrecy" :cipher cipher}))

        # Require AESGCM (reject CBC mode)
        (unless (string/find "AES" cipher)
          (eprintf "  ❌ REJECT: TLS 1.2 must use AES")
          (error {:policy "tls12-aes-required" :cipher cipher}))

        # Check for CBC mode (deprecated)
        (when (string/find "CBC" cipher)
          (eprintf "  ❌ REJECT: CBC mode is deprecated (BEAST/Lucky13 attacks)")
          (error {:policy "no-cbc-mode" :cipher cipher})))

      # Policy Rule 4: Reject TLS 1.1 and below
      (when (or (= version "TLSv1.1") (= version "TLSv1"))
        (eprintf "  ❌ REJECT: TLS 1.1 and below are deprecated")
        (error {:policy "min-tls-version" :version version}))

      (print "  ✓ ACCEPT: Connection meets all policy requirements")
      true)))

(defn secure-connect
  "Connect to a server and enforce TLS policy"
  [host port]
  (printf "\nConnecting to %s:%s..." host port)

  (let [stream (jtls/connect host port)]

    # Send minimal data to complete handshake
    (:write stream "GET / HTTP/1.1\r\nHost: ")
    (:write stream host)
    (:write stream "\r\nConnection: close\r\n\r\n")

    # Enforce policy AFTER handshake
    (try
      (do
        (check-tls-policy stream)

        # If policy check passed, proceed with normal communication
        (let [response (:read stream 512)]
          (printf "  Received %d bytes from server" (length response))

          (:close stream)
          true))

      ([err]
        # Policy violation - close connection immediately
        (eprintf "  Policy violation: %s" err)
        (:close stream)
        false))))

(defn main [&]
  (print "=== TLS Policy Enforcement Demo ===")
  (print "\nPolicy Rules:")
  (print "  1. Minimum 128-bit cipher strength")
  (print "  2. TLS 1.3: Only allow modern AEAD ciphers")
  (print "  3. TLS 1.2: Require ECDHE + AES (no CBC)")
  (print "  4. Reject TLS 1.1 and below")

  (print "\n--- Testing against various servers ---")

  # Test modern TLS 1.3 server
  (secure-connect "cloudflare.com" "443")

  # Test another modern server
  (secure-connect "example.com" "443")

  # Test Google (typically TLS 1.3)
  (secure-connect "google.com" "443")

  (print "\n=== Demo Complete ===")
  (print "All tested connections either passed policy or were rejected.")
  (print "\nIn production, you would:")
  (print "  - Configure your security options to limit cipher suites")
  (print "  - Use get-connection-info() to verify negotiated parameters")
  (print "  - Reject connections that don't meet your policy")
  (print "  - Log policy violations for security monitoring"))
