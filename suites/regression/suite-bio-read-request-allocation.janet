# Unchecked request-sized allocation in the BIO read helper regression test
# Ticket 28256ea12e1fb462e143da650c7b9f7706b67cad
#
# "Unchecked request-sized allocation in the BIO read helper"
#
# Mechanism (this tree, ticket branch off 0.2.0): cfun_bio_read
# (src/jbio.c:63-83) takes an integer length at argument 1
# (src/jbio.c:69, janet_getinteger) and rejects only negative values
# (src/jbio.c:70, crypto_panic_param "length must be non-negative").
# A caller-controlled len up to INT32_MAX then reaches
# janet_malloc(len) at src/jbio.c:72 - plain malloc, no NULL check, no
# bound on the request - and the buffer goes to BIO_read at
# src/jbio.c:73, freed on the error path at src/jbio.c:75-77. Nothing
# validates the requested size against any maximum, so one ordinary
# call demands a multi-gigabyte allocation for data that is at most a
# few bytes.
#
# This test demonstrates:
#   (a) sane and multi-chunk reads return the requested bytes normally,
#   (b) requesting an absurd length - INT32_MAX = 2147483647, the
#       largest integer the argument accepts - from jsec/bio/read
#       returns the available bytes ("hello") without allocating a
#       request-sized buffer: the process virtual-memory peak must not
#       jump by the request size around the call (under the defect
#       VmPeak grows by ~2 GiB even though only 5 bytes are in the BIO).
#
# Predicted symptom: janet_malloc(len) at src/jbio.c:72 allocates the
# full 2 GiB request buffer up front, causing VmPeak to jump by
# ~2097120 kB around a 5-byte read.
#
# Proof contract: under the defect the test fails with the ~2 GiB VmPeak
# jump symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code (Option 2: JSEC_READ_CHUNK slice-loop / data-sized
# allocation matching commit 40f34a5677) the whole test passes.

(use assay)
(import jsec/bio :as bio)
(import ../helpers :prefix "")

(defn- vmpeak-kb
  "Process peak virtual size in kB from /proc/self/status (VmPeak)."
  []
  (when-let [status (try (slurp "/proc/self/status") ([_] nil))]
    (var result nil)
    (each line (string/split "\n" status)
      (when (and (nil? result) (string/has-prefix? "VmPeak:" line))
        (def cleaned (string/replace-all "\t" " " line))
        (def parts (filter |(not (empty? $)) (string/split " " cleaned)))
        (when (>= (length parts) 2)
          (set result (scan-number (parts 1))))))
    result))

(def-suite :name "BIO Read Request Allocation Regression"
  :description "Ticket 28256ea12e: jsec/bio/read must bound allocation to data read rather than allocating a request-sized buffer"

  (def-test "absurd-read-length-bounds-allocation-to-data-read"
    :timeout 20

    # Control 1: sane small read length returns the bytes normally
    (let [ctl (bio/new-mem)]
      (bio/write ctl "hello")
      (assert (= "he" (string (bio/read ctl 2)))
              "control: a sane read length returns the bytes normally"))

    # Control 2: multi-chunk read (> 4096 bytes) returns all written bytes
    (let [ctl2 (bio/new-mem)
          big (string/repeat "abcd" 4096)] # 16384 bytes
      (bio/write ctl2 big)
      (assert (= big (string (bio/read ctl2 65536)))
              "control: multi-chunk read returns all available bytes up to len"))

    (let [b (bio/new-mem)]
      (bio/write b "hello")
      (def vm0 (vmpeak-kb))
      (def data (bio/read b 2147483647))
      (def vm1 (vmpeak-kb))
      (def peak-delta (if (and vm0 vm1) (- vm1 vm0) 0))

      (assert (= "hello" (string data))
              (string/format
                "expected jsec/bio/read to return the 5 available bytes \"hello\", got %q"
                data))

      # Under the defect, janet_malloc(2147483647) at src/jbio.c:72
      # allocates a 2 GiB buffer up front and VmPeak jumps by ~2097120 kB.
      # With JSEC_READ_CHUNK slice-bounded reading, VmPeak delta is near 0.
      (assert (< peak-delta 16384)
              (string/format
                (string "requesting an absurd length (INT32_MAX = 2147483647) "
                        "from jsec/bio/read must not allocate a request-sized "
                        "buffer (janet_malloc(len) at src/jbio.c:72 has no "
                        "bound on the caller-controlled len); observed VmPeak "
                        "delta %d kB around a 5-byte read (expected < 16384 kB)")
                peak-delta)))))

