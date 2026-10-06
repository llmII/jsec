###
### Regression: (:read s :all) allocates 2 GiB
###
### Ticket: 9406d9396cd8df1495d8a651570537a8ba665311
###
### Drives (:read s :all) on a TLS loopback connection with 100 bytes
### of data available and asserts the process does not acquire a
### multi-gigabyte buffer allocation.
###
### Defect: state_machine.c TLS_OP_CHUNK calls
###   janet_buffer_ensure(user_buf, count + remaining, 2)
### where remaining = INT32_MAX for :all, so the buffer is grown to
### ~2 GiB regardless of how much data is actually available.
### janet_buffer_ensure multiplies by growth=2 and clamps to INT32_MAX,
### then calls janet_gcpressure with ~2 GiB and janet_realloc for ~2 GiB.
###
### Observable: process virtual-size delta in kB, sampled around the read
### by get-vmsize-kb, which dispatches per platform and returns nil when
### no probe is available:
###   - Linux / Chimera (os/which = :linux): VmSize: from
###     /proc/self/status (kB)
###   - macOS / FreeBSD / OpenBSD / NetBSD / DragonFly / Solaris-Illumos:
###     `ps -o vsz= -p <pid>` run directly via os/spawn (vsz is kB);
###     Solaris-family builds report :illumos or :posix
###   - Windows (:windows/:mingw): PowerShell Get-Process
###     VirtualMemorySize64, falling back to wmic VirtualSize -- both
###     report BYTES, divided by 1024 for kB
###   - anything else, or any probe failure: nil
### The memory assertion runs wherever the probe works (Linux, Chimera,
### macOS, the BSDs, Solaris/Illumos, Windows); when the probe is
### unavailable the test is SKIPPED via skip-no-memory-probe?
### (:skip-cases). Under the defect the delta is ~2 GiB; under the fix
### the buffer grows to fit the data (~100 bytes), not the request
### (INT32_MAX).
###

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# =============================================================================
# Portable virtual-memory probe (every path reports kB)
# =============================================================================

(defn clean-output
  "Normalize captured tool output for parsing: drop UTF-16 NUL bytes and
  any UTF-16/UTF-8 BOM so redirected cmd/PowerShell text (often UTF-16LE)
  parses like plain ASCII."
  [text]
  (var s (string/replace-all "\x00" "" text))
  (set s (string/replace-all "\xFF\xFE" "" s))
  (set s (string/replace-all "\xFE\xFF" "" s))
  (string/replace-all "\xEF\xBB\xBF" "" s))

(defn parse-int
  "Value of the first run of decimal digits in text, or nil if none."
  [text]
  (def n (length text))
  (var i 0)
  (while (and (< i n) (not (<= 48 (text i) 57)))
    (++ i))
  (def start i)
  (while (and (< i n) (<= 48 (text i) 57))
    (++ i))
  (when (> i start)
    (scan-number (string/slice text start i))))

(defn read-vm-kb
  "Read a Vm* value in kB from /proc/self/status. nil if unavailable."
  [key]
  (when-let [status (try (slurp "/proc/self/status") ([_] nil))]
    (var result nil)
    (each line (string/split "\n" status)
      (when (and (nil? result) (string/has-prefix? key line))
        (def cleaned (string/replace-all "\t" " " line))
        (def parts (filter |(not (empty? $)) (string/split " " cleaned)))
        (when (>= (length parts) 2)
          (set result (scan-number (parts 1))))))
    result))

(defn capture
  "Run argv directly (no shell), return captured stdout text, or nil on
  any failure. Mirrors the subprocess capture in
  suites/performance/lib/metrics.janet."
  [argv]
  (try
    (do
      (def proc (os/spawn argv :p {:out :pipe}))
      (def out (get proc :out))
      (def output (:read out :all))
      (:close out)
      (os/proc-wait proc)
      output)
    ([_] nil)))

(defn ps-vsz-kb
  "Virtual size in kB via `ps -o vsz= -p <pid>`, run without a shell.
  vsz is reported in kB on macOS, the BSDs, and Solaris/Illumos.
  nil on any failure."
  []
  (when-let [output (capture ["ps" "-o" "vsz=" "-p" (string (os/getpid))])]
    (scan-number (string/trim output))))

(defn windows-vsize-kb
  "Windows virtual size in kB. PowerShell Get-Process reports
  VirtualMemorySize64 in BYTES; wmic reports VirtualSize in BYTES; both
  are divided by 1024 here so the result is kB like the other probes.
  nil when neither tool yields a parseable value."
  []
  (def pid (os/getpid))
  (def ps-out (capture ["powershell" "-NoProfile" "-NonInteractive" "-Command"
                        (string "Get-Process -Id " pid
                                " | Select-Object -ExpandProperty "
                                "VirtualMemorySize64")]))
  (def from-powershell
    (when ps-out
      (when-let [bytes (scan-number (string/trim (clean-output ps-out)))]
        (div bytes 1024))))
  (or from-powershell
      (when-let [wmic-out
                 (capture ["wmic" "process" "where" (string "processid=" pid)
                           "get" "VirtualSize" "/value"])]
        (def cleaned (clean-output wmic-out))
        (when-let [idx (string/find "VirtualSize=" cleaned)]
          (when-let [bytes (parse-int (string/slice cleaned
                                                   (+ idx (length "VirtualSize="))))]
            (div bytes 1024))))))

(defn get-vmsize-kb
  "Best-effort process virtual size in kB, or nil when unavailable.
  Never throws."
  []
  (try
    (do
      (def hostos (os/which))
      (cond
        (= hostos :linux) (read-vm-kb "VmSize:")
        (or (= hostos :windows) (= hostos :mingw)) (windows-vsize-kb)
        (or (= hostos :macos) (= hostos :freebsd) (= hostos :openbsd)
            (= hostos :netbsd) (= hostos :dragonfly) (= hostos :bsd)
            (= hostos :illumos) (= hostos :posix))
        (ps-vsz-kb)
        nil))
    ([_] nil)))

(defn skip-no-memory-probe?
  "Skip when no virtual-memory probe is available on this platform."
  [_]
  (if (nil? (get-vmsize-kb))
    "no virtual-memory probe on this platform"
    false))

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Read All Allocation Regression"
  :timeout 10

  (def-test ":read :all does not allocate multi-gigabyte buffer"
    :skip-cases [skip-no-memory-probe?]

    (with [server (tls/listen "127.0.0.1" "0")]
      (let [[_ port] (net/localname server)
            payload (string/repeat "A" 100)]
        (ev/go
          (fn []
            (with [client (tls/accept server
                                      {:cert (certs :cert) :key (certs :key)})]
              (:write client payload)
              (ev/sleep 0.1))))
        (ev/sleep 0.15)
        (with [conn (tls/connect "127.0.0.1" (string port) {:verify false})]
          (def vm-before (get-vmsize-kb))
          (def result (:read conn :all))
          (def vm-after (get-vmsize-kb))
          (assert (and vm-before vm-after)
                  "virtual memory probe unavailable mid-test")
          (def vm-delta (- vm-after vm-before))
          (assert (buffer? result) ":read :all should return a buffer")
          (assert (= (length result) 100)
                  (string/format "should read 100 bytes of available data, got %d"
                                 (length result)))
          (assert (= (string result) payload)
                  "data read should match payload sent by server")
          (assert (< vm-delta (* 256 1024))
                  (string/format
                    (string "read :all acquired %d kB virtual memory for 100 "
                            "bytes of data; expected < 256 MB (buffer should "
                            "grow to fit DATA, not REQUEST)")
                    vm-delta)))))))
