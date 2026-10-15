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
#       before unwinding, forcing it 50000 times leaves the process
#       memory flat (the same-size alloc/free cycle reuses its chunks),
#       and the raise still happens.
#
# Shape: leak-class, driven like crash-class - each scenario runs in a
# SUBPROCESS child (janet -e) that self-measures its virtual size with
# assay/memory around the forced-raise loop and reports
# RESULT:<raised>:<growth-kb> and ERR:<first error>. The parent asserts
# the child survived with exit 0, every forced raise produced the named
# error, and the growth stays under the leak-freedom bound. The
# subprocess shape keeps the measurement clean: the worker process
# itself never holds the leaks and concurrent tests cannot pollute the
# sample.
#
# Proof contract: plain tests asserting the correct behaviour - each
# bad-input raise raises AND its earlier allocations are freed. Under
# the defect the leak-freedom assertions fail on purpose with the
# predicted growth (the raise leaves its earlier allocations unfreed)
# and they become the regression guard once the fix lands.

(use assay)
(import assay/memory)
(import jsec/crypto)
(import jsec/cert)

# Forced raises per child run. The leak is under a kB to a few kB per
# raise (about 1.8 kB for the ec-point-mul objects and about 5.1 kB for
# the parsed certificate, key and chain stack on this host's OpenSSL),
# so the proof amplifies it: 50000 forced raises leak tens to hundreds
# of MB under the defect while the fixed path reuses its chunks and
# stays flat.
(def- forced-raises 50000)

# Leak-freedom bound in kB for the whole forced-raise loop. The defect
# side grows by tens to hundreds of MB (measured); the fixed side stays
# in the low kB (chunk reuse after the per-raise free).
(def- leak-bound-kb 4096)

(defn- run-leak-child
  "Spawn the leak scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  [program]
  (def proc (os/spawn ["janet" "-e" program] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(defn- result-fields
  "Parse the child's RESULT:<raised>:<growth-kb> line into [raised growth]
   or nil when absent."
  [out]
  (when-let [idx (string/find "RESULT:" out)]
    (def start (+ idx (length "RESULT:")))
    (def stop (or (string/find "\n" out start) (length out)))
    (def parts (string/split ":" (string/slice out start stop)))
    (when (= 2 (length parts))
      (def raised (scan-number (parts 0)))
      (def growth (scan-number (parts 1)))
      (when (and raised growth) [raised growth]))))

(def- ec-point-mul-non-byte-coordinate-child
  ```
(import jsec/crypto)
(import assay/memory)

(defn force-once
  "Force the ec-point-mul non-byte :x/:y raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-mul :p-256 "\x01" {:x 1 :y 2}) nil)
       ([e] e)))

# Warm the allocator first so the growth sample is not arena slop.
(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(def- ec-point-add-non-byte-coordinate-child
  ```
(import jsec/crypto)
(import assay/memory)

(defn force-once
  "Force the ec-point-add non-byte :x/:y raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-add :p-256 {:x 1 :y 2} {:x 3 :y 4}) nil)
       ([e] e)))

# Warm the allocator first so the growth sample is not arena slop.
(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(def- ec-point-to-bytes-non-byte-coordinate-child
  ```
(import jsec/crypto)
(import assay/memory)

(defn force-once
  "Force the ec-point-to-bytes non-byte :x/:y raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (crypto/ec-point-to-bytes :p-256 {:x 1 :y 2}) nil)
       ([e] e)))

# Warm the allocator first so the growth sample is not arena slop.
(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(def- create-pkcs12-bad-chain-element-child
  ```
(import jsec/crypto)
(import jsec/cert)
(import assay/memory)

(def kp (cert/generate-self-signed-cert {:common-name "Leak PKCS12"
                                        :bits 1024}))
(def cert-pem (kp :cert))
(def key-pem (kp :key))

(defn force-once
  "Force the create-pkcs12 non-byte :chain element raise once. Returns
   the error raised, or nil when the call did not raise."
  []
  (try (do (crypto/create-pkcs12 cert-pem key-pem
                                 {:password "pw" :chain [123]})
           nil)
       ([e] e)))

# Warm the allocator first so the growth sample is not arena slop.
(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(defn- assert-leak-freedom
  "Shared parent-side contract for one raise path: the child survives,
   every forced raise produced the named error, and the process growth
   stays under the leak-freedom bound."
  [child error-fragment alloc-note raise-note]
  (def exit (child :exit))
  (def out (child :out))
  (def err (child :err))
  (assert (= 0 exit)
          (string/format
            (string "the forced-raise child must survive (the bad input is "
                    "a normal error condition, not a process-fatal one); "
                    "child exit status %d; child stdout: %s; child "
                    "stderr: %s")
            exit (string/trim out) (string/trim err)))
  (assert (string/find error-fragment out)
          (string/format
            (string "every forced raise must produce the named error %q "
                    "(the raise contract the fix must keep); child "
                    "stdout: %s; child stderr: %s")
            error-fragment (string/trim out) (string/trim err)))
  (def fields (result-fields out))
  (assert (not (nil? fields))
          (string/format
            (string "the child must report RESULT:<raised>:<growth-kb>; "
                    "child stdout: %s; child stderr: %s")
            (string/trim out) (string/trim err)))
  (def [raised growth] fields)
  (assert (= raised forced-raises)
          (string/format
            (string "the child must force the raise on every one of the %d "
                    "iterations (raise contract); it reported %d raises; "
                    "child stdout: %s")
            forced-raises raised (string/trim out)))
  (assert (<= growth leak-bound-kb)
          (string/format
            (string "each raise must free its earlier allocations: forcing "
                    "this raise %d times must stay under %d kB of process "
                    "growth, but the process grew by %d kB - the raise "
                    "leaves its earlier allocations unfreed (%s; %s)")
            raised leak-bound-kb growth alloc-note raise-note)))

(def-suite :name "Jcrypto Jcert Panic Leak Regression"
  :description "Ticket 5c41cf2c70: jcrypto and jcert raise paths must free their earlier OpenSSL allocations"

  (def-test "ec-point-mul-non-byte-coordinate-must-free-group-ctx-and-scalar"
    :timeout 120

    (def child (run-leak-child ec-point-mul-non-byte-coordinate-child))
    (assert-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:79, the BN_CTX at "
              "src/jcrypto/ec.c:84 and the scalar BIGNUM at "
              "src/jcrypto/ec.c:91")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:135-136 with them held")))

  (def-test "ec-point-add-non-byte-coordinate-must-free-group-ctx-and-points"
    :timeout 120

    (def child (run-leak-child ec-point-add-non-byte-coordinate-child))
    (assert-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:269, the BN_CTX at "
              "src/jcrypto/ec.c:272 and the EC_POINTs at "
              "src/jcrypto/ec.c:279-281")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:318-319 with them held")))

  (def-test "ec-point-to-bytes-non-byte-coordinate-must-free-group-ctx-and-point"
    :timeout 120

    (def child (run-leak-child ec-point-to-bytes-non-byte-coordinate-child))
    (assert-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the EC_GROUP at src/jcrypto/ec.c:413, the BN_CTX at "
              "src/jcrypto/ec.c:416 and the EC_POINT at "
              "src/jcrypto/ec.c:417")
      (string "janet_getbytes on the point :x and :y values raises at "
              "src/jcrypto/ec.c:445-446 with them held")))

  (def-test "create-pkcs12-bad-chain-element-must-free-cert-key-and-chain-stack"
    :timeout 120

    (def child (run-leak-child create-pkcs12-bad-chain-element-child))
    (assert-leak-freedom
      child "expected string, symbol, keyword or buffer"
      (string "the X509 at src/jcrypto/pkcs12.c:202, the EVP_PKEY at "
              "src/jcrypto/pkcs12.c:216 and the chain STACK_OF(X509) at "
              "src/jcrypto/pkcs12.c:228")
      (string "janet_getbytes on the :chain element raises at "
              "src/jcrypto/pkcs12.c:230 before any free"))))
