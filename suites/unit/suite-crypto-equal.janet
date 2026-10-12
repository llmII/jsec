# crypto/equal? Acceptance Suite (janet-assay version)
#
# Acceptance guard for the proposed crypto/equal? constant-time compare
# (ticket 788abbb9f951b2223f6059d741504bfcb0af61c3). Written to the
# RECOMMENDED contract:
#   - two byte sequences of equal length compare in constant time and the
#     result is a boolean
#   - unequal lengths return false without reading content (no raise)
#
# The binding is resolved at run time so this suite compiles and runs while
# the API is still unexported: every case then fails with its pinned
# contract message, and these same cases become the acceptance guard once
# crypto/equal? lands. If the maintainer instead picks the raising contract
# for unequal lengths, the wrong-length cases switch to assert-error
# (suites/helpers/init.janet) and the rest is unchanged.

(use assay)
(import ../helpers :prefix "")

(def- crypto-env (require "jsec/crypto"))

(defn- equal?-fn
  []
  (def entry (get crypto-env 'equal?))
  (def f (if (and (table? entry) (entry :value)) (entry :value) entry))
  (unless (or (function? f) (cfunction? f))
    (error (string "crypto/equal? is not exported (src/jcrypto/module.c "
                   "registers no equal?); this acceptance test pins the "
                   "constant-time compare contract and must fail until "
                   "the API lands")))
  f)

(defn- ct-equal?
  [a b]
  ((equal?-fn) a b))

(def-suite :name "Crypto Equal Suite"
  :description "Acceptance guard for the crypto/equal? constant-time compare"

  (def-test "equal? identical content compares equal"
    (assert (ct-equal? "deadbeef" "deadbeef")
            "equal-length identical content must return true (crypto/equal? \"deadbeef\" \"deadbeef\")"))

  (def-test "equal? differing content compares unequal"
    (assert (not (ct-equal? "deadbeef" "deadbeee"))
            "a difference in the last byte must return false")
    (assert (not (ct-equal? "Xeadbeef" "deadbeef"))
            "a difference in the first byte must return false")
    (assert (not (ct-equal? "deadXeef" "deadbeef"))
            "a difference in the middle must return false"))

  (def-test "equal? empty sequences compare equal"
    (assert (ct-equal? "" "")
            "two empty byte sequences must return true"))

  (def-test "equal? unequal lengths return false without raising"
    (assert-no-error (ct-equal? "abc" "abcd")
                     "a shorter left side must not raise")
    (assert (not (ct-equal? "abc" "abcd"))
            "a shorter left side must return false without a content compare")
    (assert-no-error (ct-equal? "abcd" "abc")
                     "a shorter right side must not raise")
    (assert (not (ct-equal? "abcd" "abc"))
            "a shorter right side must return false without a content compare")
    (assert-no-error (ct-equal? "" "x")
                     "empty vs non-empty must not raise")
    (assert (not (ct-equal? "" "x"))
            "empty vs non-empty must return false"))

  (def-test "equal? accepts buffers as byte sequences"
    (assert (ct-equal? (buffer "ab") (buffer "ab"))
            "buffer vs buffer identical content must return true")
    (assert (ct-equal? "ab" (buffer "ab"))
            "string vs buffer identical content must return true")
    (assert (ct-equal? (buffer "ab") "ab")
            "buffer vs string identical content must return true")
    (assert (not (ct-equal? (buffer "ab") (buffer "ac")))
            "buffer vs buffer differing content must return false")))
