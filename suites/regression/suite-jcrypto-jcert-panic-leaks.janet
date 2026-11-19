# jcrypto raises unwind past live OpenSSL allocations on their panic paths
# Ticket 5c41cf2c709615fc6785dd7f10553c797d405deb
#
# "Free live OpenSSL allocations before janet_panic paths in jcrypto and jcert"
#
# Mechanism (this tree):
#   (1) (crypto/ec-point-mul curve scalar point) allocates the curve
#       group (src/jcrypto/ec.c:79), the BN_CTX (src/jcrypto/ec.c:84)
#       and the scalar BIGNUM (src/jcrypto/ec.c:91), then extracts the
#       point coordinates with janet_getbytes (src/jcrypto/ec.c:135-136).
#       A non-byte :x or :y value (for example {:x 1 :y 2}) makes that
#       janet_getbytes raise with the group, context and scalar still
#       held - the free-then-panic shapes around the later allocations
#       (src/jcrypto/ec.c:112-115, :129-132, :142-150) never run. Leaks the
#       EC_GROUP, the BN_CTX and the scalar BIGNUM per raise.
#   (2) (crypto/ec-point-add curve point1 point2) allocates the group
#       (src/jcrypto/ec.c:269), the BN_CTX (src/jcrypto/ec.c:272) and
#       three EC_POINTs (src/jcrypto/ec.c:279-281), then extracts each
#       point's coordinates with janet_getbytes (src/jcrypto/ec.c:318-319).
#       A non-byte :x or :y raises with all of them held - the
#       free-then-panic shapes (src/jcrypto/ec.c:283-291, :302-310)
#       cover only the allocation failures and the not-a-table case.
#       Leaks the EC_GROUP, the BN_CTX and the three EC_POINTs per raise.
#   (3) (crypto/ec-point-to-bytes curve point) allocates the group
#       (src/jcrypto/ec.c:413), the BN_CTX (src/jcrypto/ec.c:416) and an
#       EC_POINT (src/jcrypto/ec.c:417), then extracts the coordinates
#       with janet_getbytes (src/jcrypto/ec.c:445-446). A non-byte :x or
#       :y raises with all of them held - the free-then-panic shape
#       (src/jcrypto/ec.c:432-438) covers only the not-a-table case.
#       Leaks the EC_GROUP, the BN_CTX and the EC_POINT per raise.
#   (4) (crypto/create-pkcs12 cert-pem key-pem opts) parses and holds
#       the certificate (src/jcrypto/pkcs12.c:202), the private key
#       (src/jcrypto/pkcs12.c:216) and the chain STACK_OF(X509)
#       (src/jcrypto/pkcs12.c:228), then extracts each :chain element
#       with janet_getbytes (src/jcrypto/pkcs12.c:230). A non-byte
#       :chain element (for example {:password "pw" :chain [123]})
#       raises with the certificate, key and chain stack still held.
#       Leaks the X509, the EVP_PKEY and the STACK_OF(X509) (with any
#       members already pushed) per raise.
#   Each raise leaves its earlier allocations unfreed.
#
# Recorded without a guard (cannot be exhibited from the public surface
# on this host):
#   - src/jcrypto/keys.c (cfun_generate_key): the cited option-parsing
#     and curve-lookup panics run BEFORE any OpenSSL allocation here
#     (option extraction at src/jcrypto/keys.c:9-33, the unsupported
#     algorithm panic at src/jcrypto/keys.c:36), and the post-allocation
#     failure paths free the key context first (src/jcrypto/keys.c:50,
#     :55, :60, :68, :77). No input raises while an allocation is held.
#   - src/jcrypto/pkcs12.c (cfun_parse_pkcs12): the empty CA-stack
#     container is only freed when it holds members
#     (src/jcrypto/pkcs12.c:92-108), but PKCS12_parse on this OpenSSL
#     (3.6.5) returns a NULL ca stack for a bundle without CA certs, so
#     the unfreed-empty-container path is never taken from a test here;
#     the free is still owed for implementations that return a non-NULL
#     empty stack.
#   - src/jcert/jcert.c (cfun_generate_self_signed_cert,
#     cfun_generate_self_signed_from_key): every failure routes through
#     the freeing cleanup labels (src/jcert/jcert.c:243-249,
#     :398-404) and the option panics run before the first allocation
#     (src/jcert/jcert.c:47, :107, :273); no input raises while an
#     X509 or X509_NAME is held.
#
# This test demonstrates:
#   (a) each bad-input raise produces its named error and the process
#       survives: the four raises are normal error conditions, not
#       process-fatal ones,
#   (b) each raise path leaks its earlier allocations: forcing the same
#       raise 50000 times in a fresh subprocess grows the process by
#       the unfreed objects - measured on this host at 50000 forced
#       raises (OpenSSL 3.6.5): site 1 grew about 88000 kB, site 2
#       about 103000 kB, site 3 about 87000 kB, site 4 about 257000 kB,
#   (c) under fixed code each raise frees its earlier allocations
#       before unwinding, forcing it 50000 times plateaus in the late
#       iteration window (V_N2 - V_N1 near zero), and the raise still
#       happens.
#
# Shape: leak-class, driven via suites/helpers/leaks.janet two-window
# plateau measurement in a SUBPROCESS child (janet -e).

(use assay)
(import ../helpers :prefix "")

(def- ec-point-mul-non-byte-coordinate-child
  (make-plateau-leak-child
    ```
(import jsec/crypto)

(defn force-once
  "Force the ec-point-mul non-byte :x/:y raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-mul :p-256 "\x01" {:x 1 :y 2}) nil)
       ([e] e)))
```))

(def- ec-point-add-non-byte-coordinate-child
  (make-plateau-leak-child
    ```
(import jsec/crypto)

(defn force-once
  "Force the ec-point-add non-byte :x/:y raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-add :p-256 {:x 1 :y 2} {:x 3 :y 4}) nil)
       ([e] e)))
```))

(def- ec-point-to-bytes-non-byte-coordinate-child
  (make-plateau-leak-child
    ```
(import jsec/crypto)

(defn force-once
  "Force the ec-point-to-bytes non-byte :x/:y raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-to-bytes :p-256 {:x 1 :y 2}) nil)
       ([e] e)))
```))

(def- create-pkcs12-bad-chain-element-child
  (make-plateau-leak-child
    ```
(import jsec/cert)
(import jsec/crypto)

(def pair (cert/generate-self-signed-cert {:common-name "Leak Cert"}))
(def cert-pem (pair :cert))
(def key-pem (pair :key))

(defn force-once
  "Force the create-pkcs12 non-byte :chain element raise once. Returns
   the error raised, or nil when the call did not raise."
  []
  (try (do (crypto/create-pkcs12 cert-pem key-pem
                                 {:password "pw" :chain [123]})
           nil)
       ([e] e)))
```))

(def-suite :name "Jcrypto Jcert Panic Leak Regression"
  :description "Ticket 5c41cf2c70: jcrypto and jcert raise paths must free their earlier OpenSSL allocations"

  (def-test "ec-point-mul-non-byte-coordinate-must-free-group-ctx-and-scalar"
    :timeout 120

    (def child (run-leak-child ec-point-mul-non-byte-coordinate-child))
    (assert-plateau-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:79, the BN_CTX at "
              "src/jcrypto/ec.c:84 and the scalar BIGNUM at "
              "src/jcrypto/ec.c:91")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:135-136 with them held")))

  (def-test "ec-point-add-non-byte-coordinate-must-free-group-ctx-and-points"
    :timeout 120

    (def child (run-leak-child ec-point-add-non-byte-coordinate-child))
    (assert-plateau-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:269, the BN_CTX at "
              "src/jcrypto/ec.c:272 and the EC_POINTs at "
              "src/jcrypto/ec.c:279-281")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:318-319 with them held")))

  (def-test "ec-point-to-bytes-non-byte-coordinate-must-free-group-ctx-and-point"
    :timeout 120

    (def child (run-leak-child ec-point-to-bytes-non-byte-coordinate-child))
    (assert-plateau-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:413, the BN_CTX at "
              "src/jcrypto/ec.c:416 and the EC_POINT at "
              "src/jcrypto/ec.c:417")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:445-446 with them held")))

  (def-test "create-pkcs12-bad-chain-element-must-free-cert-key-and-chain-stack"
    :timeout 120

    (def child (run-leak-child create-pkcs12-bad-chain-element-child))
    (assert-plateau-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the X509 at src/jcrypto/pkcs12.c:202, the EVP_PKEY at "
              "src/jcrypto/pkcs12.c:216 and the chain STACK_OF(X509) at "
              "src/jcrypto/pkcs12.c:228")
      (string "janet_getbytes on the :chain element raises at "
              "src/jcrypto/pkcs12.c:230 before any free"))))
