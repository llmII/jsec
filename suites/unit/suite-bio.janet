# BIO Test Suite (janet-assay version)
#
# Tests for jsec's BIO (Basic I/O) module.

(import assay)
(import jsec/bio :as bio)

(assay/def-suite :name "BIO Suite"

                 (assay/def-test "Memory BIO write/read"
                                 (let [b (bio/new-mem)]
                                   (defer (:close b)
                                     (:write b "hello")
                                     (assay/assert (= "hello" (:read b 10)) "Read matches write"))))

                 (assay/def-test "Memory BIO to-string"
                                 (let [b (bio/new-mem)]
                                   (defer (:close b)
                                     (:write b "world")
                                     (assay/assert (= "world" (bio/to-string b)) "to-string matches write"))))

                 (assay/def-test "Memory BIO with 'with' macro"
                                 (with [b (bio/new-mem)]
                                   (:write b "test")
                                   (assay/assert (= "test" (:read b 10)) "BIO works with 'with'"))))
