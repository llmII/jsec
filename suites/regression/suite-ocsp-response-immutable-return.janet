# ca/create-ocsp-response returns a mutable buffer instead of an immutable string regression test
# Ticket f0da9bd744540d1c67e3c59c5af2f833b10363c7
#
# "ca/create-ocsp-response returns a mutable buffer instead of an immutable string"
#
# Mechanism (this tree, branch ticket-f0da9bd744540d1c67e3c59c5af2f833b10363c7
# off 0.2.0 at 2eef29afaf): cfun_ca_create_ocsp_response serializes the
# OCSP response with the two-pass i2d_OCSP_RESPONSE shape but targets a
# mutable JanetBuffer instead of Janet string memory:
#   src/jca/ocsp.c:368     int len = i2d_OCSP_RESPONSE(resp, NULL);
#   src/jca/ocsp.c:382-385 JanetBuffer *result = janet_buffer(len);
#                          write the DER through the result data
#                          pointer, then set the result count field
#   src/jca/ocsp.c:398     return janet_wrap_buffer(result);
# so ca/create-ocsp-response hands back a MUTABLE buffer while every
# other serialized DER blob in tree returns an immutable Janet string -
# tls get-session at src/jtls/api/session.c:73, dtls get-session at
# src/jdtls/api/info.c:148-153, crypto/convert-key at
# src/jcrypto/convert.c:154. A buffer compares by identity and hashes
# by identity, so the returned blob cannot compare by value with its own
# bytes or pin as a table key by content - the shape certificate pinning
# needs - and it stays writable after return. The consumers of these
# bytes already take either form and must keep doing so: the stapling
# setter reads its argument with janet_getbytes
# (src/jtls/api/context.c:310), the :ocsp-response context option
# accepts a string or a buffer (extract_ocsp_response at
# src/jtls/api/context.c:20-35), and ca/parse-ocsp-request reads
# request bytes with janet_getbytes (src/jca/ocsp.c:48).
#
# This test demonstrates:
#   (a) ca/create-ocsp-response must return an immutable Janet string -
#       the blob must compare by value with its own bytes and pin as a
#       table key by content - instead of a mutable buffer,
#   (b) the byte consumers must keep accepting the same bytes as either
#       a string or a buffer, before and after the return shape changes,
#   (c) under the defect the return is a mutable buffer where an
#       immutable string is required; under fixed code the whole test
#       passes.
#
# Predicted symptom (verbatim): ca/create-ocsp-response returns a
# mutable buffer where an immutable string is required.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes.

(use assay)
(import jsec/ca :as ca)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)

(def-suite :name "OCSP Response Immutable Return Regression"
  :description "Ticket f0da9bd744: ca/create-ocsp-response must return an immutable Janet string and the byte consumers keep taking string or buffer"

  (def-test "create-ocsp-response returns an immutable string and consumers keep taking both byte forms"
    (def root (ca/generate {:common-name "jsec-ocsp-immutable-root"
                            :days-valid 2 :serial 1}))
    (def leaf (ca/issue root {:common-name "localhost" :days-valid 2
                              :key-type :rsa-2048}))
    (def resp (ca/create-ocsp-response root @{:serial 1} :good))
    (def resp-str (string resp))
    (def resp-buf (buffer resp))

    # (a) the return must be an immutable Janet string.
    (def string-return (string? resp))
    (def not-buffer-return (not (buffer? resp)))
    (def value-equality (= resp resp-str))
    (def pins-as-table-key (not (nil? (get @{resp true} resp-str))))

    # (b) the byte consumers keep taking either form.
    (def ctx (tls/new-context {:cert (leaf :cert) :key (leaf :key)}))
    (def set-takes-string
      (try (do (tls-stream/set-ocsp-response ctx resp-str) true) ([_] false)))
    (def set-takes-buffer
      (try (do (tls-stream/set-ocsp-response ctx resp-buf) true) ([_] false)))
    (def option-takes-string
      (try (do (tls/new-context {:cert (leaf :cert) :key (leaf :key)
                                 :ocsp-response resp-str}) true)
           ([_] false)))
    (def option-takes-buffer
      (try (do (tls/new-context {:cert (leaf :cert) :key (leaf :key)
                                 :ocsp-response resp-buf}) true)
           ([_] false)))

    # One DER OCSP request for the parse side, serial 1: one OCSPRequest
    # wrapping one TBSRequest holding one Request holding one CertID with
    # SHA-1 (1.3.14.3.2.26) as the hash algorithm and 20-byte name/key
    # hash octet strings - assembled here so the suite carries its own
    # fixture and needs no network peer.
    (def request-der
      (string "\x30\x42\x30\x40\x30\x3e\x30\x3c\x30\x3a"
              "\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00"
              "\x04\x14" (string/repeat "A" 20)
              "\x04\x14" (string/repeat "B" 20)
              "\x02\x01\x01"))
    (def parse-takes-string
      (try (do (ca/parse-ocsp-request request-der) true) ([_] false)))
    (def parse-takes-buffer
      (try (do (ca/parse-ocsp-request (buffer request-der)) true) ([_] false)))

    (assert (and string-return not-buffer-return value-equality
                 pins-as-table-key set-takes-string set-takes-buffer
                 option-takes-string option-takes-buffer
                 parse-takes-string parse-takes-buffer)
            (string/format
              (string "ca/create-ocsp-response must return an immutable "
                      "Janet string - every other serialized DER blob in "
                      "tree returns one - where the encode at "
                      "src/jca/ocsp.c:382-385 serializes into a mutable "
                      "JanetBuffer and the return at :398 wraps it; "
                      "instead it returned a mutable buffer where an "
                      "immutable string is required; observed: %q")
              {:string-return string-return
               :buffer-return (buffer? resp)
               :value-equality value-equality
               :pins-as-table-key pins-as-table-key
               :set-accepts-string set-takes-string
               :set-accepts-buffer set-takes-buffer
               :option-accepts-string option-takes-string
               :option-accepts-buffer option-takes-buffer
               :parse-accepts-string parse-takes-string
               :parse-accepts-buffer parse-takes-buffer}))))
