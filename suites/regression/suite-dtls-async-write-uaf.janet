# DTLS write data pointer stale across suspension regression test
# Ticket 2b7d4de4650f816ef48860ca38fbb6557864d0d9
#
# "DTLS async write buffer UAF across suspension"
#
# Mechanism (this tree, ticket branch off 0.2.0):
#   - cfun_dtls_write captures the byte view once at entry:
#     JanetByteView data = janet_getbytes(argv, 1) (src/jdtls/api/io.c:165)
#     and hands that RAW view to dtls_client_start_async_write
#     (src/jdtls/api/io.c:189) when the first SSL_write does not
#     complete - the operation state caches it as state->write_data
#     (src/jdtls/api/async.c:360, field at src/jdtls/api/async.c:27,
#     struct DTLSClientAsyncState at src/jdtls/api/async.c:16-39).
#     For a buffer source that pointer is buffer->data.
#   - When the write suspends (WANT_WRITE / WANT_READ), the pointer
#     survives across the suspension; after resumption the
#     CLIENT_OP_WRITE arm of dtls_client_async_callback feeds it back
#     to OpenSSL - dtls_do_write(client->ssl, state->write_data.bytes,
#     state->write_data.len, &nwritten) at src/jdtls/api/async.c:209-211
#     (SSL_write inside dtls_do_write at src/jdtls/state_machine.c:99-109)
#     - and that is a read of memory the caller's buffer no longer owns.
#   - The JANET_ASYNC_EVENT_MARK arm (src/jdtls/api/async.c:103-110)
#     GC-marks only state->client and state->buffer; the write source
#     is a raw JanetByteView with nothing to mark, so an unrooted
#     source can also be collected while the write is parked.
#   - Janet core does not do this: ev_callback_write marks the write
#     source during JANET_ASYNC_EVENT_MARK (core/ev.c:2714-2721), and
#     the jtls layer fixed its write path the same way - TLSState holds
#     Janet write_src (src/jtls/internal.h:195), marks it while parked
#     (src/jtls/state_machine.c:858-864), and re-derives the bytes on
#     every attempt (src/jtls/state_machine.c:415-422), failing the
#     write cleanly if the source changed while suspended.
#
# This test demonstrates:
#   (a) a write from buffer B parks mid-flight (the loopback TCP
#       transport - dtls/upgrade over a connected stream socket -
#       absorbs a couple of MB before the write suspends; the probe on
#       this host parks at write 7945 of 256 bytes) and another fiber
#       then fill-clear-grows B: a 256-byte "X" fill overwrites the
#       whole original region in place and a second 256-byte "X" push
#       grows past the old capacity, so the buffer is reallocated while
#       the write is suspended,
#   (b) the write must then complete with exactly the original bytes or
#       raise - under the defect it delivers the mutated/stale pattern
#       through the stale cached pointer (the parked write's payload is
#       256 bytes that are not the original "A" bytes - freed-memory
#       garbage in the probe runs), or the process dies reading freed
#       memory (SIGSEGV) when the realloc moved and unmapped the old
#       region.
#
# Proof contract: the fill-clear-grow overwrites the source region
# BEFORE the realloc, so every malloc outcome is covered - an in-place
# or unmoved region reads the "X" fill, a moved region is freed and
# reads freed/reused memory or faults, and the already-delivered fill
# prefix cannot mask the mismatch because the parked write's payload is
# identified as the last 256-byte payload (payload-index in the RESULT
# line). It fails on purpose under the defect with exactly the
# predicted symptom and becomes the regression guard after the fix
# lands.

(use assay)
(import ../helpers :prefix "")

# Child program: DTLS over a loopback TCP transport, handshake
# completes, then a fiber writes a 256-byte buffer in a tight loop
# until the transport absorbs no more and the write parks. The main
# fiber fill-clear-grows the buffer to a 512-byte "X" fill while the
# write is parked, then drains the server side and compares the
# delivery against the original "A" pattern. Prints
# RESULT:delivered:ok, RESULT:delivered:mismatched:... or
# RESULT:raised:...; under a freed-memory read the process dies before
# any RESULT line.
(def- child-program
  ```
(import jsec/dtls-stream :as dtls)
(import jsec/cert :as cert)

(defn say [& xs]
  (print ;xs)
  (file/flush stdout))

(def PAY 256)
(def FILL 20000)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [_ port] (net/localname server))
(def done (ev/chan 2))
(ev/go
  (fn []
    (try
      (do
        (def conn (:accept server))
        (def srv (dtls/upgrade conn {:server true
                                     :cert (certs :cert) :key (certs :key)}))
        (ev/give done [:ok srv]))
      ([e] (ev/give done [:err (describe e)])))))
(var cli nil)
(try
  (do
    (def cli-conn (net/connect "127.0.0.1" (string port)))
    (set cli (dtls/upgrade cli-conn {:verify false})))
  ([e] (say "RESULT:setup-failed:" (describe e)) (os/exit 2)))
(def srv-res (ev/take done))
(unless (= :ok (srv-res 0))
  (say "RESULT:setup-failed:" (describe (srv-res 1)))
  (os/exit 2))
(def srv (srv-res 1))

(def buf (buffer/new PAY))
(buffer/push buf (string/repeat "A" PAY))

(var w-result :pending)
(var n-writes 0)
(ev/go
  (fn []
    (try
      (do
        (for i 0 FILL
          (:write cli buf)
          (++ n-writes))
        (set w-result :writes-done))
      ([e] (set w-result (string "raised:" e))))))

(var last-n -1)
(var stable 0)
(while (and (= :pending w-result) (< stable 3))
  (ev/sleep 0.3)
  (if (= n-writes last-n)
    (++ stable)
    (set stable 0))
  (set last-n n-writes))

(if (not= :pending w-result)
  (do
    (say "RESULT:never-parked:w-result=" (describe w-result)
         ":n-writes=" n-writes)
    (file/flush stdout)
    (os/exit 0))
  (do
    # fill-clear-grow: drop the original content, overwrite the whole
    # source region with "X", and grow past the old capacity so the
    # buffer is reallocated while the write is suspended.
    (buffer/clear buf)
    (buffer/push buf (string/repeat "X" PAY))
    (buffer/push buf (string/repeat "X" PAY))))

(def payloads @[])
(while (= :pending w-result)
  (def p @"")
  (try
    (do (:read srv 65536 p 5) (array/push payloads (string p)))
    ([_] (break))))
(while (< (length payloads) (+ FILL 4))
  (def p @"")
  (try
    (do (:read srv 65536 p 0.5) (array/push payloads (string p)))
    ([_] (break))))

(var idx -1)
(var off -1)
(var got 0)
(var n256 0)
(var n512 0)
(var nother 0)
(eachp [i p] payloads
  (case (length p)
    256 (++ n256)
    512 (++ n512)
    (++ nother))
  (when (and (= off -1) (= (length p) PAY))
    (for j 0 (length p)
      (when (and (= off -1) (not= (in p j) 65))
        (set idx i)
        (set off j)
        (set got (in p j))))))

(cond
  (and (= :pending w-result) (= off -1))
    (say "RESULT:incomplete:payloads=" (length payloads))
  (and (= off -1) (string? w-result))
    (say "RESULT:raised:" w-result)
  (= off -1)
    (say "RESULT:delivered:ok:payloads=" (length payloads))
    (say "RESULT:delivered:mismatched:payload-index=" idx ":first-off=" off
         ":got-byte=" got ":want-byte=65:payloads=" (length payloads)
         ":n256=" n256 ":n512=" n512 ":nother=" nother))
(file/flush stdout)
(os/exit 0)
```)

(defn- run-write-realloc-child
  "Spawn the stale-write scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  []
  (def proc (os/spawn ["janet" "-e" child-program] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(defn- safe-text
  "Render bytes as printable text so a binary leak into a failure
   message cannot break string/format (it rejects embedded NULs)."
  [s]
  (string/from-bytes ;(map |(if (or (= $ 10) (= $ 9) (and (>= $ 32) (not= $ 127))) $ 63) s)))

(defn- signal-death-note
  "Human-readable note when the child died by signal (POSIX shell exit
   semantics: status = signal + 128)."
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT)"
    139 " (died by signal 11 SIGSEGV: read of freed/unmapped memory)"
    ""))

(def-suite :name "DTLS Write Data Pointer Stale Regression"
  :description "Ticket 2b7d4de465: a dtls/write must not read a stale cached data pointer across suspension when the source buffer is reallocated"

  (def-test "dtls-write-from-buffer-reallocated-mid-write-delivers-original-bytes-or-raises"
    :timeout 120

    (def child (run-write-realloc-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The write, the parking, and the realloc must all have
    # happened without killing the process. Under the defect this can
    # fail with a SIGSEGV from the freed-memory read.
    (assert (= 0 exit)
            (string/format
              (string "the write read freed memory after the source "
                      "buffer was reallocated mid-write (the raw "
                      "JanetByteView cached at src/jdtls/api/async.c:360 "
                      "was fed back to dtls_do_write at "
                      "src/jdtls/api/async.c:209-211): child exit "
                      "status %d%s; child stdout: %s; child stderr: %s")
              exit (signal-death-note exit) (safe-text (string/trim out))
              (safe-text (string/trim err))))

    # (b) Delivery contract: the parked write completes with exactly
    # the original bytes, or it raises. It must never complete with the
    # mutated/stale pattern read through the stale cached pointer.
    (def ok (string/find "RESULT:delivered:ok" out))
    (def raised (string/find "RESULT:raised:" out))
    (assert (or ok raised)
            (string/format
              (string "a dtls/write from a buffer reallocated mid-write "
                      "must either complete with the original bytes or "
                      "raise - never read the stale cached pointer "
                      "(src/jdtls/api/async.c:360 into "
                      "src/jdtls/api/async.c:209-211); child "
                      "stdout: %s; child stderr: %s")
              (safe-text (string/trim out)) (safe-text (string/trim err))))))
