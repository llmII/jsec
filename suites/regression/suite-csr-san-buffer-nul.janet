# CSR SAN buffer NUL termination regression test
# Ticket 714e240b3f9059216f47b782697b0d6c09723945
#
# "Non-NUL-terminated buffer passed as C string in csr.c SAN list"
#
# Mechanism (this tree, branch ticket-714e240b3f9059216f47b782697b0d6c09723945
# off 0.2.0 at 599e82e288): cfun_generate_csr builds the SubjectAltName
# list in a JanetBuffer and hands it to OpenSSL as a C string without a
# NUL terminator:
#   src/jcrypto/csr.c:97   JanetBuffer *san_buf = janet_buffer(256);
#   src/jcrypto/csr.c:103  janet_buffer_push_cstring(san_buf, (const char *)san);
#   src/jcrypto/csr.c:106-107  X509V3_EXT_conf_nid(..., (char *)san_buf->data)
# janet_buffer_push_cstring appends strlen bytes and no NUL (janet
# 1.40.1 src/core/buffer.c:137-140), so the comma-joined SAN string has
# no terminator. X509V3_EXT_conf_nid reads past count through the
# uninitialized slack of the janet_buffer(256) allocation - and past the
# allocation itself for a list that grows the buffer - absorbing garbage
# into the final SAN entry (or failing the extension outright). The
# correct pattern is janet_buffer_push_u8(san_buf, 0) before use,
# exactly as src/jca/sign.c:58 does.
#
# Determinism: the bytes past count are uninitialized allocator memory
# whose content depends on the process's allocation history, so an
# in-process call can land on fresh zeroed memory and round-trip by
# accident. Each scenario therefore runs in a fresh janet SUBPROCESS
# (os/spawn, the pattern of suites/regression/suite-timed-read-timeout-crash.janet):
# a fresh process that first generates an RSA key and a CA churns the
# 256-byte allocator bin with key material, and in that state the
# generate-csr buffer is always dirty (measured 40/40 failing trials on
# this platform). Each def-test runs three independent child trials and
# requires every one to round-trip exactly. Under fixed code the
# terminating NUL makes the slack irrelevant and every trial passes.
#
# This test demonstrates:
#   (a) a CSR SAN list with many entries survives generate-csr, then
#       ca/sign with :copy-extensions (so the CSR's own SAN extension is
#       what is examined), then cert/parse - the SANs must round-trip
#       exactly,
#   (b) a CSR SAN list with long entries round-trips exactly the same
#       way,
# so the buffer is never read past its count: no crash, no garbage
# entry, no dropped extension.
#
# Under the defect the test fails with exactly the predicted symptom -
# the round-trip assertion fails because a child trial reports a parsed
# SAN list that differs from the requested list (the trailing bytes past
# the buffer count are absorbed into the final entry); under fixed code
# the whole test passes.

(use assay)
(import ../helpers :prefix "")

# Child programs: each generates a key and CA, builds a CSR with the
# given SAN list, signs it with :copy-extensions so the CSR's own SAN
# extension flows into the certificate, and compares the SAN entries
# cert/parse reads back against the requested list. Prints RESULT:ok on
# an exact round-trip, RESULT:mismatch:<got> otherwise. Exits 0 either
# way: under the defect the symptom is the mismatch (or a dropped
# extension), not a crash.
(def- child-template
  ```
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import jsec/ca)

(def key (crypto/generate-key :rsa 2048))
(def authority (ca/generate {:common-name "csr-san-regression-ca" :days-valid 30}))
(def san SAN-LITERAL)
(def csr (crypto/generate-csr key {:common-name "csr-san-regression.local" :san san}))
(def signed (ca/sign authority csr {:copy-extensions true :days-valid 10}))
(def got (get (cert/parse signed) :san))
(if (and got (deep= (tuple ;got) (tuple ;san)))
  (print "RESULT:ok")
  (print "RESULT:mismatch:" (if got (string/format "%q" (array ;got)) "no SAN extension")))
(os/exit 0)
```)

(def- many-entry-san
  (seq [i :range [0 10]] (string "DNS:san-" i ".example.com")))

(def- long-entry-san
  ["DNS:long-subdomain-name-for-csr-san-regression-first.example.com"
   "DNS:long-subdomain-name-for-csr-san-regression-second.example.com"])

(defn- child-program-for
  "Child source for one SAN list, splicing the list into the template."
  [san]
  (string/replace "SAN-LITERAL" (string/format "%q" (array ;san)) child-template))

(defn- run-roundtrip-child
  "Spawn one round-trip trial under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  [san]
  (def proc (os/spawn ["janet" "-e" (child-program-for san)] :p
                      {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(defn- assert-roundtrip
  "Run `trials` fresh-process round-trip trials of `san` and assert every
   one round-trips exactly. The failure message names the first bad
   trial and embeds its RESULT line."
  [label san trials]
  (var failure nil)
  (for i 1 (+ trials 1)
    (def child (run-roundtrip-child san))
    (def out (string/trim (child :out)))
    (def err (string/trim (child :err)))
    (when (or (not= 0 (child :exit)) (not (string/find "RESULT:ok" out)))
      (when (not failure)
        (set failure
             (string/format
               (string "csr SAN list with %s did not round-trip exactly "
                       "through generate-csr and cert/parse in child trial "
                       "%d of %d (child exit status %d); the buffer passed "
                       "to X509V3_EXT_conf_nid is not NUL-terminated, so "
                       "bytes past the buffer count are absorbed into the "
                       "final SAN entry; child stdout: %s; child stderr: %s")
               label i trials (child :exit) out err)))))
  (assert (not failure) failure))

(def-suite :name "CSR SAN Buffer NUL Regression"
  :description "Ticket 714e240b3f: the CSR SAN buffer must be NUL-terminated before X509V3_EXT_conf_nid"

  (def-test "many-entry san list round-trips exactly through generate-csr and cert-parse"
    :timeout 60

    # 10 entries, the "many entries" shape of the ticket.
    (assert-roundtrip "many entries" many-entry-san 3))

  (def-test "long-entry san list round-trips exactly through generate-csr and cert-parse"
    :timeout 60

    # 2 long entries, the "long entries" shape of the ticket.
    (assert-roundtrip "long entries" long-entry-san 3)))
