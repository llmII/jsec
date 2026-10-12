# IP-literal host verification regression test
# Ticket 118035835628be797f7f7d85d891a1227b526b5c
#
# "IP-literal hosts cannot verify certificates with iPAddress SANs"
#
# Mechanism (this tree, 0.2.0 basis at 599e82e288):
#   src/jtls/api/connect.c:300  - cfun_wrap sends SNI with
#     SSL_set_tlsext_host_name for EVERY hostname, IP literals included
#   src/jtls/api/connect.c:307  - cfun_wrap sets the expected name with
#     SSL_set1_host(host_to_verify) - a DNS-name expectation
#   src/jtls/api/connect.c:316  - cfun_wrap: SSL_set1_host(verify_hostname)
#   src/jtls/api/connect.c:621  - tls_connect_callback (the tls/connect
#     path): SSL_set_tlsext_host_name(sni_hostname)
#   src/jtls/api/connect.c:632  - tls_connect_callback:
#     SSL_set1_host(cert_verify_host)
#   same shape on the jdtls side: src/jdtls/api/upgrade.c:182, :188,
#   :193 and src/jdtls/api/connect.c:237, :244.
#
# SSL_set1_host installs X509_VERIFY_PARAM_set1_host: the host string is
# matched against dNSName SANs (and the CN only when no DNS SAN exists),
# NEVER against iPAddress SANs. A certificate whose only SAN is
# IP:127.0.0.1 therefore cannot verify for a client that connects to the
# literal 127.0.0.1 - OpenSSL needs X509_VERIFY_PARAM_set1_ip_asc
# (X509_check_ip_asc) for literals. Sending SNI for a literal IP
# additionally violates RFC 6066 section 3, which forbids literal
# addresses in the server_name extension.
#
# This test demonstrates:
#   (a) tls/connect to the literal IP 127.0.0.1, with verification on,
#       against a certificate whose only SAN is IP:127.0.0.1, verifies
#       successfully and carries application data,
#   (b) no SNI extension is sent for that literal: the server-side view
#       of the handshake (:connection-info, fed by SSL_get_servername at
#       src/jtls/api/info.c:155-159) sees no server name at all.
#
# The server certificate is issued by an in-suite CA with
# :common-name "jsec-ip-literal-test" - deliberately NOT the IP - and
# :san ["IP:127.0.0.1"] as its ONLY SAN, so no CN fallback can mask the
# defect: X509_check_host consults the CN only when no dNSName SAN is
# present, and here the CN is not the IP either.
#
# Proof contract: under the defect (b) fails with the server receiving
# server name 127.0.0.1, and (a) fails with the certificate
# verification error wherever SSL_set1_host is DNS-only (OpenSSL
# 3.0.x, 1.1.1, LibreSSL); OpenSSL 3.1 and newer take IP literals in
# SSL_set1_host natively so (a) passes there (measured on this host's
# OpenSSL 3.6.5). Exactly those symptoms and
# nothing else; under the fix both tests pass and guard the fix.

(use assay)
(import jsec/tls :as tls)
(import jsec/ca)
(import ../helpers :prefix "")

# One CA and one leaf for the suite. The leaf's ONLY SAN is
# IP:127.0.0.1 and its CN is a plain name that does not contain the IP.
(def ca
  (ca/generate {:common-name "jsec IP literal test CA"
                :key-type :ec-p256
                :days-valid 1}))

(def leaf
  (:issue ca {:common-name "jsec-ip-literal-test"
              :san ["IP:127.0.0.1"]
              :key-type :ec-p256
              :days-valid 1}))

(def-suite :name "IP Literal Host Verification Regression"
  :description "Ticket 1180358356: IP-literal hosts cannot verify certificates with iPAddress SANs"

  (def-test "ip-literal-connect-verifies-certificate-with-ip-address-san"
    :timeout 15

    (let [[server _] (make-server :tcp)
          [host port] (net/localname server)]

      (defer (:close server)

        # Server: present the IP-SAN-only certificate and push "ok".
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:write s "ok")
                       (ev/sleep 0.5)))
                   ([_] nil))))

        # (a) Client connects to the LITERAL IP with verification on,
        # trusting the in-suite CA. Correct behaviour: the handshake
        # verifies the certificate against its iPAddress SAN
        # (X509_VERIFY_PARAM_set1_ip_asc semantics) and the round trip
        # completes.
        (var data nil)
        (var err nil)
        (try
          (with [c (tls/connect host port {:verify true
                                           :trusted-cert (:get-cert ca)})]
            (set data (:read c 2 nil 5.0)))
          ([e] (set err e)))

        (assert (nil? err)
                (string/format
                  (string "tls/connect to the literal IP %s against a "
                          "certificate whose only SAN is IP:%s must "
                          "verify successfully (iPAddress SAN, not "
                          "SSL_set1_host DNS matching); the handshake "
                          "failed: %v")
                  host host err))
        (assert (= "ok" (string data))
                "verified IP-literal connection must carry application data"))))

  (def-test "ip-literal-connect-sends-no-sni-extension"
    :timeout 15

    (let [[server _] (make-server :tcp)
          [host port] (net/localname server)
          seen (ev/chan 1)]

      (defer (:close server)

        # Server: complete the handshake with a read, then report the
        # server_name SNI value the ClientHello carried - nil when the
        # client sent no SNI extension.
        (ev/go (fn []
                 (try
                   (with [conn (:accept server)]
                     (with [s (tls/wrap conn {:cert (leaf :cert)
                                              :key (leaf :key)})]
                       (:read s 2 nil 5.0)
                       (ev/give seen ((:connection-info s) :server-name))))
                   ([e] (ev/give seen (string "server error: " e))))))

        # (b) Client connects to the LITERAL IP. RFC 6066 section 3:
        # literal addresses must not appear in server_name, so no SNI
        # extension may be sent at all. :verify false keeps this test
        # about SNI only - the handshake completes either way.
        (with [c (tls/connect host port {:verify false})]
          (:write c "hi")

          (def server-name (ev/take seen))
          (assert (nil? server-name)
                  (string/format
                    (string "tls/connect to the literal IP %s must send "
                            "no SNI extension (RFC 6066 section 3 "
                            "forbids literal addresses in server_name), "
                            "but the server received server name %q")
                    host server-name)))))))
