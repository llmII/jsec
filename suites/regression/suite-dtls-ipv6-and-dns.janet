# DTLS IPv6 and DNS regression test
# Ticket a4a8eb43012980d19bdda2fa3acb3657b5be3a72
#
# "DTLS connect/listen hardcoded AF_INET (no IPv6, no DNS)"
#
# Mechanism (this tree, 0.2.0 basis at 599e82e288):
#   src/jdtls/api/connect.c:101 - cfun_dtls_connect creates the UDP
#     socket with socket(AF_INET, SOCK_DGRAM, 0); the Windows twin is
#     WSASocketW(AF_INET, ...) at :99.
#   src/jdtls/api/connect.c:117-125 - struct sockaddr_in with
#     addr.sin_family = AF_INET (:119) and inet_pton(AF_INET, host,
#     addr.sin_addr) (:122); any host that is not a dotted-quad
#     IPv4 falls into dtls_panic_param("invalid address: %s", host)
#     at :123-124.
#   src/jdtls/server.c:251 - cfun_dtls_listen creates its UDP socket
#     with socket(AF_INET, SOCK_DGRAM, 0); Windows twin at :246.
#   src/jdtls/server.c:276-285 - struct sockaddr_in,
#     addr.sin_family = AF_INET (:278), inet_pton(AF_INET, host,
#     addr.sin_addr) (:283), the same "invalid address" panic at
#     :284-285.
# So DTLS cannot bind or connect over IPv6 literals (::1) and cannot
# resolve DNS names (localhost): both are rejected at the address
# parse before any socket work. The TLS side already does it right -
# getaddrinfo with hints.ai_family = AF_UNSPEC at
# src/jtls/api/connect.c:774-785, trying each result until the
# connection starts.
#
# This test demonstrates:
#   (a) dtls/listen and dtls/connect accept the IPv6 literal ::1 and
#       complete a datagram round trip over it,
#   (b) dtls/listen and dtls/connect accept the DNS name localhost
#       and complete a datagram round trip over it.
# Neither is a dotted-quad IPv4, so both exercise exactly the hosts
# the AF_INET-only parse rejects.
#
# Proof contract: under the defect each test fails with exactly its
# "invalid address: ..." rejection from the inet_pton(AF_INET) parse
# and nothing else (no crash, no hang, no unrelated error); under
# fixed code (AF_UNSPEC/getaddrinfo matching the TLS path at
# src/jtls/api/connect.c:774-785) both tests pass and become the
# regression guard for the fix.

(use assay)
(import jsec/dtls-stream)
(import jsec/cert)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- round-trip
  "Bind a DTLS server on host, connect a DTLS client to the same host,
   and exchange Ping/Pong. Returns nothing; raises on any failure.
   Used to prove the whole accept/connect/send/receive path works for
   hosts that are not dotted-quad IPv4."
  [host]
  (var server nil)
  (var err nil)
  (try
    (set server
         (dtls-stream/listen host 0 {:cert (certs :cert) :key (certs :key)}))
    ([e] (set err e)))
  (assert (nil? err)
          (string/format
            (string "dtls/listen must accept %s (resolve with "
                    "AF_UNSPEC/getaddrinfo like the TLS path at "
                    "src/jtls/api/connect.c:774-785, instead of "
                    "inet_pton(AF_INET)); it was rejected: %v")
            host err))
  (defer (:close server)
    (def [_ port] (dtls-stream/localname server))
    (def done (ev/chan 1))

    (ev/go (fn []
             (try
               (do
                 (def buf (buffer/new 1024))
                 (def addr (dtls-stream/recv-from server 1024 buf))
                 (if addr
                   (do
                     (dtls-stream/send-to server addr "Pong")
                     (ev/give done true))
                   (ev/give done (string "no datagram received on " host))))
               ([e] (ev/give done (string "server error: " e))))))

    (ev/sleep 0.2)

    (var client nil)
    (set err nil)
    (try
      (set client (dtls-stream/connect host port {:verify false}))
      ([e] (set err e)))
    (assert (nil? err)
            (string/format
              (string "dtls/connect must accept %s (resolve with "
                      "AF_UNSPEC/getaddrinfo like the TLS path at "
                      "src/jtls/api/connect.c:774-785, instead of "
                      "inet_pton(AF_INET)); it was rejected: %v")
              host err))

    (defer (:close client true)
      (dtls-stream/write client "Ping")
      (def reply (dtls-stream/read client 1024))
      (assert (= "Pong" (string reply))
              (string/format
                "datagram round trip over %s must deliver the Pong reply, got %v"
                host reply)))

    (def server-msg (ev/take done))
    (assert (= true server-msg)
            (string/format "server side of the %s round trip failed: %v"
                           host server-msg))))

(def-suite :name "DTLS IPv6 And DNS Regression"
  :description "Ticket a4a8eb4301: DTLS connect/listen hardcoded AF_INET (no IPv6, no DNS)"

  (def-test "dtls-listen-and-connect-accept-ipv6-literal"
    :timeout 15

    (round-trip "::1"))

  (def-test "dtls-listen-and-connect-accept-dns-name"
    :timeout 15

    (round-trip "localhost")))
