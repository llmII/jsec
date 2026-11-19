# Shared multi-window plateau heuristic helpers for leak-class regression suites.
# Ticket 8437d94e5c847e9435be0e3f634321963bdb0487
#
# Testing division of labor:
#   - LeakSanitizer (LSan via sanitizers/run-with-lsan.sh) is the byte-exact
#     heap leak oracle on supported platforms (Linux).
#   - On platforms without LSan (FreeBSD jemalloc, macOS libmalloc, Windows,
#     Solaris/Illumos), these subprocess suites amplify error/panic paths
#     over 50,000 iterations and measure late-window virtual-size growth
#     (V_N2 - V_N1 after N1 = 10,000 warm-up iterations) so legitimate
#     early allocator arena/extent retention plateaus cleanly without
#     per-OS thresholds or metric branching.

(def- san-active?
  (truthy? (or (os/getenv "JSEC_SANITIZER")
               (os/getenv "ASAN_OPTIONS")
               (os/getenv "LSAN_OPTIONS"))))

(def leak-warmup-iterations 200)
(def leak-plateau-start (if san-active? 1000 10000))
(def leak-total-iterations (if san-active? 5000 50000))
(def leak-plateau-bound-kb 2048)

(defn make-plateau-leak-child
  "Wrap a scenario setup+force-once body in the standard two-window
   plateau leak-measurement child script."
  [setup-and-force-once]
  (string
    "(import assay/memory)\n"
    setup-and-force-once "\n"
    "(for i 0 " leak-warmup-iterations " (force-once))\n"
    "(gccollect)\n"
    "(def v0 (get (memory/info) :vsize))\n"
    "(var v1 v0)\n"
    "(var raised 0)\n"
    "(var first-err nil)\n"
    "(for i 0 " leak-total-iterations "\n"
    "  (def e (force-once))\n"
    "  (if (nil? e)\n"
    "    (error \"scenario did not raise\")\n"
    "    (do (++ raised) (unless first-err (set first-err e))))\n"
    "  (when (zero? (mod i 1000)) (gccollect))\n"
    "  (when (= i " (- leak-plateau-start 1) ")\n"
    "    (gccollect)\n"
    "    (set v1 (get (memory/info) :vsize))))\n"
    "(gccollect)\n"
    "(def v2 (get (memory/info) :vsize))\n"
    "(print \"RESULT:\" raised \":\" (div (- v2 v1) 1024) \":\" (div (- v1 v0) 1024))\n"
    "(print \"ERR:\" (string first-err))\n"))

(defn run-leak-child
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

(defn parse-plateau-result
  "Parse RESULT:<raised>:<plateau-kb>:<early-kb> into [raised plateau-kb early-kb]
   or nil when absent."
  [out]
  (when-let [idx (string/find "RESULT:" out)]
    (def start (+ idx (length "RESULT:")))
    (def stop (or (string/find "\n" out start) (length out)))
    (def parts (string/split ":" (string/trim (string/slice out start stop))))
    (when (= 3 (length parts))
      (def raised (scan-number (parts 0)))
      (def plateau-kb (scan-number (parts 1)))
      (def early-kb (scan-number (parts 2)))
      (when (and raised plateau-kb early-kb)
        [raised plateau-kb early-kb]))))

(defn assert-plateau-leak-freedom
  "Shared parent-side contract for one error/panic leak path: the child
   survives, every forced raise produced the named error, and late-window
   growth (V_N2 - V_N1) plateaus under leak-plateau-bound-kb."
  [child error-fragment alloc-note panic-note]
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
  (def fields (parse-plateau-result out))
  (assert (not (nil? fields))
          (string/format
            (string "the child must report RESULT:<raised>:<plateau-kb>:<early-kb>; "
                    "child stdout: %s; child stderr: %s")
            (string/trim out) (string/trim err)))
  (def [raised plateau-kb early-kb] fields)
  (assert (= raised leak-total-iterations)
          (string/format
            (string "the child must force the raise on every one of the %d "
                    "iterations (raise contract); it reported %d raises; "
                    "child stdout: %s")
            leak-total-iterations raised (string/trim out)))
  (assert (<= plateau-kb leak-plateau-bound-kb)
          (string/format
            (string "each raise must free its earlier allocations: late-window "
                    "growth (iters %d..%d) must plateau under %d kB, but grew "
                    "by %d kB (early window 0..%d grew %d kB) - allocations "
                    "remain unfreed (%s; %s)")
            leak-plateau-start leak-total-iterations leak-plateau-bound-kb
            plateau-kb leak-plateau-start early-kb alloc-note panic-note)))
