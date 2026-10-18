# OCSP CertID serial ceiling regression test
# Ticket 1921202ef64f5acaeceb15e6eee597121482c1c2
#
# "OCSP CertID serial ceiling: parse returns a canonical decimal string
# and create accepts number or string"
#
# Mechanism (this tree): ca/parse-ocsp-request reads the CertID serial via
# ASN1_INTEGER_get_int64 (src/jca/ocsp.c:116-123). RFC 5280 section 4.1.2.2
# allows certificate serial numbers up to 20 octets (160 bits). Furthermore,
# jsec's own ca/issue draws uniform random 64-bit serials (BN_rand(bn, 64)),
# approximately half of which have bit 63 set, exceeding the signed 64-bit
# integer range. When a serial exceeds signed 64 bits, ASN1_INTEGER_get_int64
# fails (<= 0) with OpenSSL error "error:068000DF:asn1 encoding routines::too large"
# and ca/parse-ocsp-request raises ca_panic_ssl.
#
# In ca/create-ocsp-response (src/jca/ocsp.c:335-343), :serial is extracted
# strictly using janet_getinteger64 and passed to ASN1_INTEGER_set_int64,
# which rejects string serials and overflows on values > int64_max.
#
# The fix:
# 1. ca/parse-ocsp-request converts ASN1_INTEGER to BIGNUM via ASN1_INTEGER_to_BN
#    and formats it via BN_bn2dec, returning a canonical decimal string
#    (no leading zeros; '-' prefix only for non-conforming negative serials).
# 2. ca/create-ocsp-response symmetrically accepts :serial as a canonical decimal
#    string or as a Janet integer / s64.
#
# Proof contract:
# Under current defective code, guards testing >64-bit unsigned serials and
# 160-bit RFC 5280 ceiling serials fail with the predicted OpenSSL "too large" error
# or type error on string serial.
# Under fixed code, all guards pass and generate valid OCSP responses.

(use assay)
(import jsec/ca :as ca)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

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

(defn- openssl
  ``Run the openssl CLI and return its combined stdout and stderr text.``
  [& args]
  (def proc (os/spawn ["openssl" ;args] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))
  (os/proc-wait proc)
  (:close (proc :out))
  (:close (proc :err))
  (string out-buf "\n" err-buf))

(defn- build-ocsp-fixture
  ``Build a root CA and a leaf certificate with a specific hex serial,
   then generate a DER OCSP request via the openssl CLI.``
  [dir hex-serial]
  (def ca-key-path (abspath (string dir "/ca.key")))
  (def ca-cert-path (abspath (string dir "/ca.pem")))
  (def csr-path (abspath (string dir "/leaf.csr")))
  (def leaf-key-path (abspath (string dir "/leaf.key")))
  (def leaf-cert-path (abspath (string dir "/leaf.pem")))
  (def req-path (abspath (string dir "/req.der")))

  # Generate root CA certificate and private key
  (openssl "req" "-x509" "-newkey" "rsa:2048" "-nodes" "-keyout" ca-key-path
           "-out" ca-cert-path "-subj" "/CN=jsec serial ceiling root" "-days" "2")

  # Load root CA into JanetCA object
  (def root (ca/create (slurp ca-cert-path) (slurp ca-key-path)))

  # Generate leaf key and CSR
  (openssl "req" "-newkey" "rsa:2048" "-nodes" "-keyout" leaf-key-path
           "-out" csr-path "-subj" "/CN=serial-ceiling-leaf")

  # Sign leaf certificate with the exact given hex serial using openssl x509
  (openssl "x509" "-req" "-in" csr-path "-CA" ca-cert-path
           "-CAkey" ca-key-path "-set_serial" hex-serial
           "-out" leaf-cert-path "-days" "1")

  # Generate OCSP request
  (def ocsp-out (openssl "ocsp" "-issuer" ca-cert-path "-cert" leaf-cert-path
                         "-nonce" "-reqout" req-path))
  (unless (os/stat req-path)
    (error (string "failed to generate OCSP request: " ocsp-out)))

  {:root root
   :root-path ca-cert-path
   :leaf-path leaf-cert-path
   :req-path req-path
   :req-der (slurp req-path)})

(def-suite :name "CA OCSP CertID Serial Ceiling Regression"
  :description "Ticket 1921202ef6: ca/parse-ocsp-request returns canonical decimal string for serials up to 160 bits; ca/create-ocsp-response accepts string or number symmetrically"

  (def-test "parse-ocsp-request-64bit-unsigned-overflow-serial"
    :timeout 60
    # 0x8000000000000001 = 9223372036854775809 (2^63 + 1, bit 63 set, overflows signed int64)
    (def fx (build-ocsp-fixture (scratch-dir) "0x8000000000000001"))
    (def info (ca/parse-ocsp-request (fx :req-der)))
    (assert (string? (info :serial)) "serial must be returned as a string")
    (assert (= "9223372036854775809" (info :serial))
            (string "expected serial 9223372036854775809, got " (info :serial))))

  (def-test "parse-ocsp-request-160bit-rfc5280-ceiling-serial"
    :timeout 60
    # 160-bit serial (20 octets max per RFC 5280): 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # Decimal: 1461501637330902918203684832716283019655932542975
    (def fx (build-ocsp-fixture (scratch-dir) "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
    (def info (ca/parse-ocsp-request (fx :req-der)))
    (assert (string? (info :serial)) "serial must be returned as a string")
    (assert (= "1461501637330902918203684832716283019655932542975" (info :serial))
            (string "expected serial 1461501637330902918203684832716283019655932542975, got " (info :serial))))

  (def-test "create-ocsp-response-accepts-canonical-decimal-string-serial"
    :timeout 60
    (def dir (scratch-dir))
    (def fx (build-ocsp-fixture dir "0x8000000000000001"))
    # Parse request info or build request table with string serial
    (def req-info {:serial "9223372036854775809"
                   :digest "sha1"})
    (def resp-der (ca/create-ocsp-response (fx :root) req-info :good))
    (assert (string? resp-der) "response must be DER string")
    (def resp-path (write-pem dir "resp.der" resp-der))
    (def out (openssl "ocsp" "-respin" resp-path "-CAfile" (fx :root-path) "-no_cert_checks"))
    (assert (string/find "Response verify OK" out)
            (string "OCSP response verify failed: " out)))

  (def-test "create-ocsp-response-accepts-number-serial-symmetrically"
    :timeout 60
    (def dir (scratch-dir))
    (def root (ca/generate {:common-name "jsec sym root" :days-valid 2 :serial 1}))
    (def root-path (write-pem dir "root.pem" (ca/get-cert root)))
    (def req-info {:serial 4660 :digest "sha1"})
    (def resp-der (ca/create-ocsp-response root req-info :good))
    (assert (string? resp-der) "response must be DER string")
    (def resp-path (write-pem dir "resp.der" resp-der))
    (def out (openssl "ocsp" "-respin" resp-path "-CAfile" root-path "-no_cert_checks"))
    (assert (string/find "Response verify OK" out)
            (string "OCSP response verify failed: " out))))
