# DTLS read allocation regression guards
# Tickets f1ba4f59a15d50e84869c830cc677305a262b50b (f1ba4f59a1)
#         a1c896672fb83cfff18db10630a4ec16fdf5cf61 (a1c896672f)
#
# "DTLS reads grow buffer by request size, not bytes read" and
# "DTLS buffer capacity doubling per read iteration"
#
# Both tickets cite the same two calls - one fix closes both. Each carries
# its own named guard below: f1ba4f59a1 guards request-sized growth, and
# a1c896672f guards the per-read-iteration doubling that the growth factor
# of 2 applies on top of it. A third guard pins non-truncation: a datagram
# larger than 4096 bytes must arrive intact through both dtls read and
# dtls/recv-from.
#
# Mechanism (this tree, ticket branch off 0.2.0 at 599e82e288):
#   - cfun_dtls_read grows the caller-supplied buffer by the REQUEST size
#     before a single byte is read: janet_buffer_ensure(buf, buf->count + n, 2)
#     at src/jdtls/api/io.c:38, where n comes from janet_getinteger at
#     src/jdtls/api/io.c:24. janet_buffer_ensure (janet buffer.c:87) grows
#     capacity to (count + n) * 2 and feeds janet_gcpressure the
#     difference, so a 16 MiB request moves 32 MiB of capacity whether or
#     not one byte of data exists. Bytes delivered are counted correctly
#     afterwards (src/jdtls/api/io.c:49) - it is the CAPACITY that tracks
#     the request instead of the data. That is the f1ba4f59a1 half.
#   - The growth factor of 2 in that same call is the a1c896672f half:
#     every read iteration reserves TWICE what the iteration needs, so a
#     loop of reads pays the doubled reservation over and over instead of
#     growing with the bytes delivered. One iteration alone already
#     over-reserves 2x; the loop shows the total is not bounded by the
#     data.
#   - cfun_dtls_recv_from does the same for its user buffer at
#     src/jdtls/server.c:739: janet_buffer_ensure(buf, buf->count + nbytes, 2)
#     with nbytes from janet_getinteger at src/jdtls/server.c:731. The
#     datagram read afterwards is bounded by that fresh capacity
#     (process_datagram, src/jdtls/server.c:487-489) and counts only the
#     bytes actually delivered (src/jdtls/server.c:495). Same request-size
#     growth and same factor-2 doubling at this site.
#   - Same class, not asserted here: janet_buffer(n) at src/jdtls/api/io.c:40
#     (dtls/read with no user buffer) and janet_buffer(nbytes) at
#     src/jdtls/state_machine.c:567 (dtls_async_read, no callers today).
#   - Contrast the already-fixed jtls path (commit 40f34a5677): one want
#     value = min(request, JSEC_READ_CHUNK 4096) feeds both
#     janet_buffer_extra and the SSL_read length (src/jtls/state_machine.c
#     :265-269), so the buffer grows with the data actually read. That one
#     shape is the fix for both halves.
#
# Observable: process virtual-size delta in kB, sampled around the read by
# get-vmsize-kb, which dispatches per platform and returns nil when no
# probe is available:
#   - Linux / Chimera (os/which = :linux): VmSize: from
#     /proc/self/status (kB)
#   - macOS / FreeBSD / OpenBSD / NetBSD / DragonFly / Solaris-Illumos:
#     `ps -o vsz= -p <pid>` run directly via os/spawn (vsz is kB);
#     Solaris-family builds report :illumos or :posix
#   - Windows (:windows/:mingw): PowerShell Get-Process
#     VirtualMemorySize64, falling back to wmic VirtualSize -- both
#     report BYTES, divided by 1024 for kB
#   - anything else, or any probe failure: nil
# The memory assertion runs wherever the probe works (Linux, Chimera,
# macOS, the BSDs, Solaris/Illumos, Windows); when the probe is
# unavailable the tests are SKIPPED via skip-no-memory-probe?
# (:skip-cases).
#
# Request size: n = 16777216 (16 MiB), larger than the "say 1 MiB" the
# f1ba4f59a1 ticket text uses as an example, and deliberately so.
# janet_buffer_ensure doubles the request (2n = 32 MiB here), and the
# allocator absorbs any growth under its maximum mmap threshold (32 MiB on
# glibc) into already-mapped heap, so a 1 MiB request produced a FLAT
# virtual-size delta on repeated probe runs (2052, 2108, 0, 0 kB): it
# cannot prove the defect. At 2n = 32 MiB every growth is a fresh mapping
# and the delta is deterministic (32772 kB = 2n + 4 kB probe noise, four
# runs in a row).
#
# These tests demonstrate:
#   (a) [f1ba4f59a1] a DTLS read requesting 16 MiB with one 100-byte
#       datagram available delivers exactly those 100 bytes, and under the
#       defect grows the user buffer by 2x the REQUEST: the read window
#       shows about 32772 kB of virtual-memory growth for 100 bytes of
#       data,
#   (b) [f1ba4f59a1] dtls/recv-from on the server side does the same for
#       its user buffer: about 32772 kB of growth for its own 100-byte
#       datagram,
#   (c) [a1c896672f] a loop of reads on one session pays that doubled
#       reservation on every iteration: four reads delivering 400 bytes
#       in total grow virtual memory by about 131088 kB (4 x 2n), not by
#       anything bounded by the data,
#   (d) under fixed code (growth bounded to the bytes read, as on the jtls
#       path) every delta stays under 1024 kB, the delivered-data checks
#       still pass, and both tests pass,
#   (e) [non-truncation] an 8000-byte datagram - larger than the 4096-byte
#       JSEC_READ_CHUNK a truncating fix shape caps at - is delivered
#       intact by dtls read and by dtls/recv-from: exactly 8000 bytes,
#       byte-for-byte.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - f1ba4f59a1 with "dtls
# read and recv-from acquired 32772 kB and 32772 kB virtual memory for 100
# bytes of data each on 16777216-byte requests; expected under 1024 kB
# each (buffer should grow to fit DATA, not REQUEST)" and a1c896672f with
# "dtls read loop doubled buffer capacity per iteration: acquired 131088 kB
# virtual memory across 4 reads delivering 400 bytes; expected under 1024
# kB (capacity must follow data delivered, not the request)" - and nothing
# else: no crash, no hang, no unrelated error. Under fixed code both tests
# pass.
#
# The non-truncation guard is green under the allocation defect (which
# over-allocates but still delivers whole datagrams) and under the fix,
# and goes red only under a fix shape that caps reads at JSEC_READ_CHUNK
# 4096 - the truncation the 2026-10-10 ruling rejects. It pins the
# deliverable: an 8000-byte datagram arrives intact on both paths.
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

# 16 MiB request: janet_buffer_ensure doubles it to 32 MiB of capacity,
# which is above the allocator's maximum mmap threshold, so every growth
# is a fresh mapping and the virtual-size delta is deterministic. A 1 MiB
# request is absorbed into already-mapped heap and the delta flakes to 0
# (see the header).
(def request-bytes 16777216)
(def max-growth-kb 1024)
(def payload (string/repeat "A" 100))
(def loop-rounds 4)
# 8000-byte datagram for the non-truncation guard: larger than the
# 4096-byte JSEC_READ_CHUNK a truncating fix shape caps at.
(def big-payload (string/repeat "B" 8000))
(def big-bytes 8000)

(def-suite :name "DTLS Read Allocation Regression"
  :description "Tickets f1ba4f59a1 and a1c896672f: DTLS read buffers grow by request size and double capacity per read iteration"

  (def-test "dtls read does not allocate by request size (f1ba4f59a1)"
    :timeout 20
    :skip-cases [skip-no-memory-probe?]

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            payload-sent (ev/chan 1)
            start-recv-window (ev/chan 1)
            recv-result (ev/chan 1)]

        # Server fiber: three rounds.
        #   1. handshake + "Ping1" -> "pong" primes the session so the
        #      measurement windows below contain no handshake allocations.
        #   2. "Ping2" -> 100-byte payload for the measured client read.
        #   3. the measured recv-from: virtual size sampled before the
        #      call (the buffer growth is synchronous with the call), and
        #      completed by the client's second 100-byte datagram.
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (def addr2 (:recv-from server 1024 (buffer/new 1024)))
                (when addr2 (:send-to server addr2 payload))
                (ev/give payload-sent true)
                (ev/take start-recv-window)
                (gccollect)
                (def vm1 (get-vmsize-kb))
                (def recv-buf (buffer/new 0))
                (def addr3 (:recv-from server request-bytes recv-buf))
                (def vm2 (get-vmsize-kb))
                (ev/give recv-result
                         {:addr addr3
                          :len (length recv-buf)
                          :delta (if (and vm1 vm2) (- vm2 vm1) nil)}))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        # Force close: (:close conn) without force performs an RFC
        # close_notify round-trip and suspends until the peer answers
        # (src/jdtls/api/close.c:78-88) - the peer is done here, so a
        # plain close would block and mask the test outcome. The coverage
        # suites close DTLS clients the same way.
        (defer (:close conn true)

          # Priming round (1). Completes the handshake on both sides and
          # consumes one full read/write exchange, so nothing below mixes
          # handshake allocations into the measurement windows.
          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (assert (= "pong" (string r1))
                  "priming read should receive the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          # (a) The measured client read (cfun_dtls_read,
          # src/jdtls/api/io.c:38). Round 2 delivers one 100-byte
          # datagram; the request asks for 16 MiB. Under the defect the
          # user buffer grows by 2x the request at call entry.
          (:write conn "Ping2")
          (def sent-val (ev/take payload-sent))
          (assert (= true sent-val)
                  (string/format "server payload round failed: %v" sent-val))
          (def read-buf (buffer/new 0))
          (gccollect)
          (def vm1 (get-vmsize-kb))
          (def result (:read conn request-bytes read-buf))
          (def vm2 (get-vmsize-kb))
          (def delta-read (if (and vm1 vm2) (- vm2 vm1) nil))

          # (b) The measured recv-from (cfun_dtls_recv_from,
          # src/jdtls/server.c:739). Same shape on the server side: one
          # 100-byte datagram, 16 MiB request into a fresh user buffer.
          (ev/give start-recv-window true)
          (ev/sleep 0.1)
          (:write conn payload)
          (def recv (ev/take recv-result))
          (def delta-recv (recv :delta))

          # Delivered data: both reads must return exactly the 100 bytes
          # that were available - the defect is in the allocation, not in
          # the data path.
          (assert (buffer? result) "dtls read should return a buffer")
          (assert (= 100 (length result))
                  (string/format "dtls read should deliver 100 bytes, got %d"
                                 (length result)))
          (assert (= payload (string result))
                  "dtls read data should match the payload sent by the server")
          (assert (recv :addr)
                  "recv-from should return the peer address")
          (assert (= 100 (recv :len))
                  (string/format
                    "recv-from should deliver 100 bytes, got %d" (recv :len)))

          # The allocation assertion: growth must track the DATA (100
          # bytes), not the REQUEST (16 MiB). Under the defect both deltas
          # are 2x the request (~32772 kB) and this fails with the
          # predicted symptom above; under fixed code both are bounded by
          # the data actually read and the whole test passes.
          (assert (and delta-read delta-recv
                       (< delta-read max-growth-kb)
                       (< delta-recv max-growth-kb))
                  (string/format
                    (string "dtls read and recv-from acquired %d kB and %d kB "
                            "virtual memory for 100 bytes of data each on "
                            "%d-byte requests; expected under %d kB each "
                            "(buffer should grow to fit DATA, not REQUEST)")
                    (or delta-read -1) (or delta-recv -1)
                    request-bytes max-growth-kb))))))

  (def-test "dtls read does not double buffer capacity per iteration (a1c896672f)"
    :timeout 20
    :skip-cases [skip-no-memory-probe?]

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            rounds-done (ev/chan 1)]

        # Server fiber: one priming round, then one 100-byte payload per
        # loop round, so the client's measured loop always has exactly one
        # datagram in flight per read. The server side reads with a 1 KiB
        # request into a 1 KiB buffer, which needs no growth, so the
        # server contributes nothing to the measurement.
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (for i 0 loop-rounds
                  (def addr (:recv-from server 1024 (buffer/new 1024)))
                  (when addr (:send-to server addr payload)))
                (ev/give rounds-done true))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        # Force close - see the f1ba4f59a1 guard above.
        (defer (:close conn true)

          # Priming round. Completes the handshake on both sides so the
          # measured loop below contains no handshake allocations.
          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (assert (= "pong" (string r1))
                  "priming read should receive the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          # The measured loop (cfun_dtls_read, src/jdtls/api/io.c:38, on
          # every iteration). Each round delivers one 100-byte datagram
          # and requests 16 MiB into a FRESH user buffer, so the growth
          # call runs once per read iteration with the request as its
          # input. The buffers are retained across the loop on purpose:
          # each iteration's reservation has to stay live for the total to
          # be visible, and the allocator hands large regions straight
          # back to the OS on free, so released buffers would hide the
          # per-iteration total.
          (gccollect)
          (def vm1 (get-vmsize-kb))
          (def bufs @[])
          (var total-delivered 0)
          (for i 0 loop-rounds
            (:write conn payload)
            (def buf (buffer/new 0))
            (def result (:read conn request-bytes buf))
            (assert (buffer? result)
                    "dtls read should return a buffer")
            (assert (= 100 (length result))
                    (string/format "dtls read should deliver 100 bytes, got %d"
                                   (length result)))
            (assert (= payload (string result))
                    "dtls read data should match the payload sent by the server")
            (set total-delivered (+ total-delivered (length result)))
            (array/push bufs buf))
          (def vm2 (get-vmsize-kb))
          (def delta (if (and vm1 vm2) (- vm2 vm1) nil))

          (def rounds-val (ev/take rounds-done))
          (assert (= true rounds-val)
                  (string/format "server loop failed: %v" rounds-val))

          # Delivered data: the loop must return exactly the bytes the
          # server sent. The defect is in the allocation, not the data.
          (assert (= loop-rounds (length bufs))
                  (string/format "loop should retain %d buffers, got %d"
                                 loop-rounds (length bufs)))
          (assert (= (* loop-rounds 100) total-delivered)
                  (string/format
                    "loop should deliver %d bytes in total, got %d"
                    (* loop-rounds 100) total-delivered))

          # The allocation assertion: the TOTAL across the loop must be
          # bounded by the data delivered plus slack, not by the doubled
          # reservation each iteration makes against the 16 MiB request.
          # Under the defect four iterations reserve 4 x 2n (~131088 kB)
          # for 400 bytes of data and this fails with the predicted
          # symptom above; under fixed code each iteration is bounded to
          # JSEC_READ_CHUNK and the total stays under 1024 kB.
          (assert (and delta (< delta max-growth-kb))
                  (string/format
                    (string "dtls read loop doubled buffer capacity per "
                            "iteration: acquired %d kB virtual memory across "
                            "%d reads delivering %d bytes; expected under %d "
                            "kB (capacity must follow data delivered, not the "
                            "request)")
                    (or delta -1) loop-rounds total-delivered
                    max-growth-kb))))))

  # Third guard - non-truncation. Named for what it guards: a datagram
  # larger than 4096 bytes must be delivered intact, i.e. never truncated
  # to a JSEC_READ_CHUNK-sized slice, through both dtls read and
  # dtls/recv-from.
  (def-test "dtls read and recv-from deliver 8000-byte datagrams intact (non-truncation)"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            big-sent (ev/chan 1)
            start-recv-window (ev/chan 1)
            recv-result (ev/chan 1)]

        # Server fiber: three rounds.
        #   1. handshake + "Ping1" -> "pong" primes the session.
        #   2. "Ping2" -> the 8000-byte datagram for the client read.
        #   3. the recv-from of the client's own 8000-byte datagram.
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (def addr2 (:recv-from server 1024 (buffer/new 1024)))
                (when addr2 (:send-to server addr2 big-payload))
                (ev/give big-sent true)
                (ev/take start-recv-window)
                (def recv-buf (buffer/new 0))
                (def addr3 (:recv-from server request-bytes recv-buf))
                (ev/give recv-result
                         {:addr addr3
                          :data (string recv-buf)}))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        # Force close - see the f1ba4f59a1 guard above.
        (defer (:close conn true)

          # Priming round. Completes the handshake on both sides so the
          # measured exchanges below contain no handshake traffic.
          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (assert (= "pong" (string r1))
                  "priming read should receive the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          # The client read of the 8000-byte datagram: one datagram, a
          # 16 MiB request into a fresh buffer. A truncating fix shape
          # delivers 4096 bytes here; the non-truncating datagram-driven
          # sizing delivers the datagram whole.
          (:write conn "Ping2")
          (def sent-val (ev/take big-sent))
          (assert (= true sent-val)
                  (string/format "server payload round failed: %v" sent-val))
          (def read-buf (buffer/new 0))
          (def result (:read conn request-bytes read-buf))

          # The recv-from of the client's own 8000-byte datagram: same
          # intact-delivery requirement on the server path.
          (ev/give start-recv-window true)
          (ev/sleep 0.1)
          (:write conn big-payload)
          (def recv (ev/take recv-result))

          # Intact delivery: exactly 8000 bytes, byte-for-byte, on both
          # paths.
          (assert (buffer? result) "dtls read should return a buffer")
          (assert (= big-bytes (length result))
                  (string/format
                    (string "dtls read should deliver the %d-byte datagram "
                            "intact, got %d bytes")
                    big-bytes (length result)))
          (assert (= big-payload (string result))
                  (string "dtls read data should match the 8000-byte "
                          "payload sent by the server"))
          (assert (recv :addr)
                  "recv-from should return the peer address")
          (assert (= big-bytes (length (recv :data)))
                  (string/format
                    (string "recv-from should deliver the %d-byte datagram "
                            "intact, got %d bytes")
                    big-bytes (length (recv :data))))
          (assert (= big-payload (recv :data))
                  (string "recv-from data should match the 8000-byte "
                          "payload sent by the client"))))))
)

