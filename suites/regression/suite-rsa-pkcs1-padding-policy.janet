# RSA PKCS#1 v1.5 padding policy regression test
# Ticket 609c46cbc597e82e55a7ed3dc9343137f4999ff0
#
# "PKCS#1 v1.5 padding allowed for RSA encryption/decryption"
#
# Mechanism (this tree, branch ticket-609c46cbc597e82e55a7ed3dc9343137f4999ff0
# off 0.2.0 at 599e82e288): get_rsa_padding (src/jcrypto/rsa.c:24-44)
# still maps the :pkcs1 keyword to RSA_PKCS1_PADDING:
#   src/jcrypto/rsa.c:43-44  if (strcmp(name, "pkcs1") == 0) return RSA_PKCS1_PADDING;
# so crypto/rsa-encrypt (src/jcrypto/rsa.c:54-...) and crypto/rsa-decrypt
# (src/jcrypto/rsa.c:191-...) accept :padding :pkcs1 on both sides and
# perform raw PKCS#1 v1.5 encryption - the Bleichenbacher surface. The
# padding is advertised as supported in the encrypt-side error string at
# src/jcrypto/rsa.c:85-87 ("... oaep-sha512, pkcs1)"), is accepted
# without complaint by the decrypt-side check at src/jcrypto/rsa.c:218-221,
# has its own max-plaintext branch at src/jcrypto/rsa.c:381-383, and is
# documented in the rsa-encrypt docstring at src/jcrypto/module.c:227
# ("pkcs1 (legacy, NOT recommended)"). Defaults are already OAEP-SHA256
# (src/jcrypto/rsa.c:62, :198, :322) but the opt-in remains.
#
# This test demonstrates:
#   (a) crypto/rsa-encrypt with :padding :pkcs1 must be rejected (raise)
#       - or require an explicitly named unsafe/legacy option not passed
#       here - instead of encrypting with PKCS#1 v1.5,
#   (b) crypto/rsa-decrypt with :padding :pkcs1 must likewise be
#       rejected - under the defect the pair round-trips "hello" through
#       PKCS#1 v1.5,
#   (c) OAEP remains the default: with no :padding option the round trip
#       works and crypto/rsa-max-plaintext reports the OAEP-SHA256
#       overhead (190 bytes for RSA-2048), not the PKCS#1 v1.5 figure
#       (245).
#
# Predicted symptom (verbatim): RSA encrypt/decrypt with :padding :pkcs1
# succeeds and the data round-trips - opt-in PKCS#1 v1.5 is still
# offered.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes.

(use assay)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(def-suite :name "RSA PKCS1 Padding Policy Regression"
  :description "Ticket 609c46cbc5: :padding :pkcs1 must be rejected or explicitly named unsafe, and OAEP stays the default"

  (def-test "rsa pkcs1 padding is rejected and oaep stays the default"
    (def keys (generate-temp-certs {:common-name "rsa-pkcs1-policy"
                                    :key-type :rsa :bits 2048}))
    (def key (keys :key))

    # (c) OAEP remains the default: no :padding option anywhere.
    (def oaep-roundtrip
      (try
        (do
          (def ct (crypto/rsa-encrypt key "hello"))
          (def pt (crypto/rsa-decrypt key ct))
          (= "hello" (string pt)))
        ([_] false)))
    (def default-max
      (try (crypto/rsa-max-plaintext key) ([_] -1)))

    # (a) :padding :pkcs1 on the encrypt side must be refused.
    (def pkcs1-encrypt
      (try
        (do
          (def ct (crypto/rsa-encrypt key "hello" {:padding :pkcs1}))
          {:proceeded true :ciphertext-len (length ct)})
        ([err] {:raised err})))

    # (b) :padding :pkcs1 on the decrypt side must be refused.
    (def pkcs1-decrypt
      (try
        (do
          (def ct (crypto/rsa-encrypt key "hello" {:padding :pkcs1}))
          (def pt (crypto/rsa-decrypt key ct {:padding :pkcs1}))
          {:proceeded true :plaintext (string pt)})
        ([err] {:raised err})))

    (assert (and (pkcs1-encrypt :raised)
                 (pkcs1-decrypt :raised)
                 oaep-roundtrip
                 (= 190 default-max))
            (string/format
              (string "crypto/rsa-encrypt and crypto/rsa-decrypt with "
                      ":padding :pkcs1 must reject the legacy PKCS#1 v1.5 "
                      "padding (get_rsa_padding maps it at "
                      "src/jcrypto/rsa.c:43-44 and the encrypt-side error "
                      "string at :85-87 advertises it) or require an "
                      "explicitly named unsafe option; instead the pair "
                      "accepted it and the data round-tripped - opt-in "
                      "PKCS#1 v1.5 is still offered; observed: %q")
              {:oaep-default-round-trip oaep-roundtrip
               :oaep-default-max-plaintext default-max
               :pkcs1-encrypt pkcs1-encrypt
               :pkcs1-decrypt pkcs1-decrypt}))))
