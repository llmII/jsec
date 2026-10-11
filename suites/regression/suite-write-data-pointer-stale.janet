# Write data pointer cached across suspension regression test
# Ticket d27f8af55f41e8aba8c2e5c06648e81a0a93ad68
#
# "Write data pointer cached across suspension"
#
# Mechanism (this tree, ticket branch off 0.2.0):
#   - cfun_write captures the byte view once at entry:
#     JanetByteView bytes = janet_getbytes(argv, 1) (src/jtls/api/io.c:196)
#     and caches the RAW data pointer in the embedded operation state -
#     state->write_data = bytes.bytes (src/jtls/api/io.c:204, field at
#     src/jtls/internal.h:195) with state->write_len = bytes.len at
#     :205. For a buffer source that pointer is buffer->data.
#   - When the socket blocks (WANT_WRITE), the operation suspends and
#     the pointer survives across the suspension; after resumption the
#     TLS_OP_WRITE case feeds it back to OpenSSL -
#     SSL_write(tls->ssl, state->write_data + state->write_offset,
#     remaining) at src/jtls/state_machine.c:378-381 - and that is a
#     read of memory the caller's buffer no longer owns.
#   - Janet core does not do this: janet_ev_write_generic stores the
#     JanetBuffer value itself (core/ev.c:2882-2884, the buffer-taking
#     wrappers at :2897-2916) and re-derives buffer->data and
#     buffer->count on EVERY write event (core/ev.c:2817-2825).
#
# This test demonstrates:
#   (a) a write from buffer B parks mid-flight (16 MB source, the
#       loopback peer not draining - the probe on this host shows the
#       socket pair absorbs about 3 MB before the write suspends) and
#       another fiber then fill-clear-grows B: clear plus a 32 MB
#       "X" fill, which overwrites the whole original region and
#       forces a realloc past the old capacity,
#   (b) the write must then complete with exactly the original bytes
#       or raise - under the defect it delivers the mutated pattern
#       through the stale cached pointer (first mismatch offset in the
#       RESULT line), or the process dies reading freed memory
#       (SIGSEGV) when the realloc moved and unmapped the old region.
#
# Proof contract: the fill-clear-grow overwrites the source region
# BEFORE the realloc, so every malloc outcome is covered - an in-place
# or unmoved region reads the "X" fill, a moved region is freed and
# reads freed/reused memory or faults, and the already-flushed prefix
# (about 3 MB) cannot mask the mismatch in a 16 MB delivery. It fails
# on purpose under the defect with exactly the predicted symptom and
# becomes the regression guard after the fix lands.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Child program: TLS loopback, handshake completes, then the client
# fiber writes a 16 MB buffer and parks (the server side does not read
# yet). The main fiber fill-clear-grows the buffer to a 32 MB "X"
# fill while the write is parked, then drains exactly 16 MB from the
# server side and compares the delivery against the original "A"
# pattern. Prints RESULT:delivered:ok, RESULT:delivered:mismatched:...
# or RESULT:raised:...; under a freed-memory read the process dies
# before any RESULT line.
(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def S (* 16 1024 1024))
(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))
(def addr {:host host :port (string port)})
(def ready (ev/chan 1))
(def wdone (ev/chan 1))

(def buf (buffer/new S))
(def blk (string/repeat "A" (* 1024 1024)))
(for i 0 16 (buffer/push buf blk))

(ev/go (fn []
         (try
           (with [conn (net/connect (addr :host) (addr :port))]
             (with [c (tls/wrap conn {:verify false})]
               (ev/give ready true)
               (try
                 (do (:write c buf) (ev/give wdone :ok))
                 ([err] (ev/give wdone (string "write error: " err))))
               (ev/sleep 30)))
           ([err] (ev/give ready (string "client error: " err))))))

(def conn (:accept server))
(def s (tls/wrap conn {:cert (certs :cert) :key (certs :key)}))
(def rv (ev/take ready))
(unless (= true rv)
  (print "SETUP-FAILED:" rv)
  (os/exit 2))

# Let the 16 MB write park: the socket pair absorbs only a few MB with
# the server side not reading.
(ev/sleep 0.8)

# fill-clear-grow: drop the original content, overwrite the whole
# source region with "X", and grow past the old capacity so the buffer
# is reallocated while the write is suspended.
(buffer/clear buf)
(def xblk (string/repeat "X" (* 1024 1024)))
(for i 0 32 (buffer/push buf xblk))

# Drain exactly S bytes from the server side, comparing nothing yet.
(def acc (buffer/new S))
(var read-err nil)
(try
  (while (< (length acc) S)
    (def chunk (:read s 65536 nil 15))
    (if (and chunk (> (length chunk) 0))
      (buffer/push acc chunk)
      (break)))
  ([err] (set read-err (string err))))

(def w (ev/take wdone))
(cond
  (string? w)
    (print "RESULT:raised:" w)
  (not= nil read-err)
    (print "RESULT:incomplete:read-error:" read-err)
  (< (length acc) S)
    (print "RESULT:incomplete:received=" (length acc) ":want=" S)
  (do
    (var off -1)
    (for i 0 S
      (when (and (= off -1) (not= (in acc i) 65))
        (set off i)))
    (if (= off -1)
      (print "RESULT:delivered:ok:total=" S)
      (print "RESULT:delivered:mismatched:first-off=" off
             ":got-byte=" (in acc off) ":want-byte=65:total=" S))))
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

(def-suite :name "Write Data Pointer Stale Regression"
  :description "Ticket d27f8af55f: a write must not read a stale cached data pointer across suspension when the source buffer is reallocated"

  (def-test "write-from-buffer-reallocated-mid-write-delivers-original-bytes-or-raises"
    :timeout 60

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
                      "pointer cached at src/jtls/api/io.c:204 was fed "
                      "back to SSL_write at "
                      "src/jtls/state_machine.c:378-381): child exit "
                      "status %d%s; child stdout: %s; child stderr: %s")
              exit (signal-death-note exit) (safe-text (string/trim out))
              (safe-text (string/trim err))))

    # (b) Delivery contract: the write completes with exactly the
    # original bytes, or it raises. It must never complete with the
    # mutated pattern read through the stale cached pointer.
    (def ok (string/find "RESULT:delivered:ok" out))
    (def raised (string/find "RESULT:raised:" out))
    (assert (or ok raised)
            (string/format
              (string "a write from a buffer reallocated mid-write must "
                      "either complete with the original bytes or "
                      "raise - never read the stale cached pointer "
                      "(src/jtls/api/io.c:204 into "
                      "src/jtls/state_machine.c:378-381); child "
                      "stdout: %s; child stderr: %s")
              (safe-text (string/trim out)) (safe-text (string/trim err))))))
