# BIO Test Suite (janet-assay version)
#
# Tests for jsec's BIO (Basic I/O) module.

(use assay)
(import jsec/bio :as bio)

(def-suite :name "BIO Suite"

  (def-test "Memory BIO write/read"
    (let [b (bio/new-mem)]
      (defer (:close b)
        (:write b "hello")
        (assert (= "hello" (:read b 10)) "Read matches write"))))

  (def-test "Memory BIO to-string"
    (let [b (bio/new-mem)]
      (defer (:close b)
        (:write b "world")
        (assert (= "world" (bio/to-string b)) "to-string matches write"))))

  (def-test "Memory BIO with 'with' macro"
    (with [b (bio/new-mem)]
      (:write b "test")
      (assert (= "test" (:read b 10)) "BIO works with 'with'"))))
