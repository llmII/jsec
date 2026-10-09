# strlen() on non-NUL-terminated janet_getbytes results regression test
# Ticket eabb83acf67bf1ae7e73a171f2fd5069d2a6e517
#
# "strlen() on non-NUL-terminated janet_getbytes results (passwords, paths)"
#
# janet_getbytes returns {bytes,len} from a Janet value. Strings are
# NUL-terminated (core/string.c) but BUFFERS are NOT: their byte view
# ends at count and the capacity behind it holds stale data. Several
# sites hand the bytes to strlen() or C-string OpenSSL APIs as if they
# were terminated. Sites re-derived against this tree:
#   src/jcrypto/keys.c:133-134  cfun_load_key keeps only pwd.bytes and
#       drops pwd.len; the pointer reaches jutils_password_cb
#       (src/jutils/cert_loading.c:30-43) whose strlen at :36 computes
#       the password length,
#   src/jcrypto/convert.c:33-34, :41-42  same shape; strlen at :103,
#       :106, :113, :121,
#   src/jcrypto/pkcs12.c:22-23  password bytes -> PKCS12_parse C-string
#       at :41; strlen(password) at :177 and strlen(friendly_name) at
#       :228 (friendly_name from janet_getbytes at :148-158); the
#       PKCS12_create call takes the password as a C string,
#   src/jcert/verify.c:217  :trusted-dir bytes -> trusted_dir fed to
#       X509_STORE_load_path/locations at :288-293 as a C string, and
#   src/jcert/verify.c:233-234  :hostname bytes -> strlen(hostname) at
#       :378 before X509_check_host.
# The fix shape is one pattern: copy len+1 NUL-terminated (or take the
# length, or type-reject buffers).
#
# Deterministic observation (the buffer-reuse trick): a buffer that has
# previously held 200 "A" bytes and now visibly holds just "pw" still
# carries the "A"s in its capacity behind count. strlen() walks off the
# end of the view into that stale region and computes a 200+ byte
# password - a WRONG password - from an argument whose Janet value is
# exactly "pw". The same argument as a string (NUL-terminated, no
# over-read) opens the key. A plain fresh buffer is not a reliable
# witness (its byte behind count is heap-dependent; a string literal
# converted to a buffer can even keep the source string's NUL), which
# is why the proof uses the reuse buffer and the string as control.
#
# This test demonstrates:
#   (a) password path: crypto/load-key with the reuse buffer carrying
#       exactly "pw" must open the key encrypted with "pw" exactly as
#       the string "pw" does; under the defect strlen at
#       src/jutils/cert_loading.c:36 over-reads the buffer's stale
#       "A"s and the correct password is rejected as wrong ("failed to
#       load private key" on the encrypted key the control opens).
#   (b) hostname path: cert/verify-chain with the reuse buffer carrying
#       exactly "127.0.0.1" must verify exactly as the string does;
#       under the defect strlen at src/jcert/verify.c:378 over-reads
#       and X509_check_host compares "127.0.0.1" plus stale "A"s, so
#       a matching certificate reports "hostname mismatch".
#   (c) under fixed code both buffer arguments behave identically to
#       their string controls and the whole test passes.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (a correct password/hostname passed as a buffer is
# rejected as if it were a wrong one, because strlen computed the wrong
# length); under fixed code the whole test passes.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import ../helpers :prefix "")

(defn- reuse-buffer
  ``Buffer whose Janet value is exactly `payload` but whose capacity
   behind count still holds 200 stale "A" bytes - the deterministic
   over-read witness.``
  [payload]
  (def buf @"")
  (buffer/push buf (string/repeat "A" 200))
  (buffer/clear buf)
  (buffer/push buf payload)
  buf)

(defn- try-load-key
  ``crypto/load-key returning [pem err] instead of raising.``
  [pem pw]
  (try
    [(crypto/load-key pem pw) nil]
    ([err] [nil (string err)])))

(def-suite :name "Getbytes Buffer As CString Regression"
  :description "Ticket eabb83acf6: janet_getbytes buffers are not NUL-terminated and must not be strlen'd as C strings"

  (def-test "password-buffer-opens-key-like-the-same-string-password"
    :timeout 30

    (def key (crypto/generate-key :ec-p256))
    (def enc (crypto/export-key key {:password "pw"}))

    # Control: the string form of the password is NUL-terminated and
    # opens the key.
    (def [from-string str-err] (try-load-key enc "pw"))
    (assert from-string
            (string "control: string password must open the key: " str-err))

    # The same password as a BUFFER whose Janet value is exactly "pw".
    # Correct behaviour: it opens the key exactly like the string.
    # Under the defect strlen at src/jutils/cert_loading.c:36
    # over-reads the stale "A"s behind the buffer's count and the
    # correct password is rejected as wrong.
    (def [from-buffer buf-err] (try-load-key enc (reuse-buffer "pw")))
    (assert from-buffer
            (string/format
              (string "a password passed as a buffer must open the key exactly as "
                      "the same password as a string (buffers are not "
                      "NUL-terminated: strlen must not over-read stale capacity "
                      "and reject a correct password as wrong): got "
                      "(string-opened=%q buffer-error=%q)")
              (if from-string :opened :failed) buf-err))
    (assert (= from-string from-buffer)
            (string/format
              (string "the buffer-passed password must decrypt to the same key as "
                      "the string-passed password: got (string-key=%q buffer-key=%q)")
              from-string from-buffer)))

  (def-test "hostname-buffer-verifies-like-the-same-string-hostname"
    :timeout 30

    (def certs (generate-temp-certs {:common-name "127.0.0.1"}))

    # Control: the string hostname matches the certificate SAN.
    (def from-string (cert/verify-chain (certs :cert)
                                        {:trusted [(certs :cert)]
                                         :hostname "127.0.0.1"}))
    (assert (from-string :valid)
            (string/format "control: string hostname must verify: got %q"
                           from-string))

    # The same hostname as a BUFFER whose Janet value is exactly
    # "127.0.0.1". Correct behaviour: it verifies exactly like the
    # string. Under the defect strlen at src/jcert/verify.c:378
    # over-reads the stale "A"s and X509_check_host compares
    # "127.0.0.1AAAA...", so a matching certificate reports a
    # hostname mismatch.
    (def from-buffer (cert/verify-chain (certs :cert)
                                        {:trusted [(certs :cert)]
                                         :hostname (reuse-buffer "127.0.0.1")}))
    (assert (= (from-string :valid) (from-buffer :valid))
            (string/format
              (string "a hostname passed as a buffer must verify exactly as the "
                      "same hostname as a string (buffers are not NUL-terminated: "
                      "strlen must not over-read stale capacity and hand "
                      "X509_check_host a wrong hostname): got (string-valid=%q "
                      "buffer-valid=%q buffer-error=%q)")
              (from-string :valid) (from-buffer :valid) (from-buffer :error)))))
