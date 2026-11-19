# jtls read drain redundant EAGAIN regression test
# Ticket fb5527b84819d05459bda264569123718b640639
#
# "jtls read and chunk state machine issues redundant EAGAIN socket read
# after draining buffered records"
#
# Mechanism (this tree, branch ticket-fb5527b84819d05459bda264569123718b640639
# off 0.2.0 at 2eef29afaf): TLS_OP_READ (src/jtls/state_machine.c:281-324)
# loops SSL_read until the caller's byte request is met. Each SSL_read
# pulls encrypted bytes through jtls_bio_read (src/jtls/bio.c:44-115),
# which serves tls->bio_ahead first and only issues a kernel read(fd)
# when the ahead buffer is empty (:65-98). When several TLS records
# arrive in one TCP segment, one read(fd) buffers them all and the loop
# decrypts every buffered record in user space. The loop's only exit
# check is the request size (:306-311): once the last buffered record is
# decrypted and both tls->bio_ahead (p == pe) and OpenSSL's internal
# buffer (SSL_has_pending) are empty, one more SSL_read runs, forcing
# jtls_bio_read to issue a second kernel read(fd) that fails with
# EAGAIN before handle_ssl_error (src/jtls/state_machine.c:166-207,
# has_data at :170-171) notices the user buffer already holds data and
# returns TLS_IO_COMPLETE. TLS_OP_CHUNK (:334-391) carries the same
# shape through its just_read_data retry (:374-383): after a successful
# read and a WANT_READ it continues the loop once more even with no
# buffered data left, so a second immediate read(fd) hits EAGAIN before
# the operation suspends.
#
# The extra read(fd) is invisible from Janet: the operation still
# returns the same decrypted bytes and no error. The proof therefore
# observes the syscall itself - the shape of
# suites/regression/suite-jtls-accept-bio-context-guards.janet - with a
# test-only LD_PRELOAD interposer compiled at run time that counts
# read() calls on sockets returning EAGAIN/EWOULDBLOCK after a trigger
# file arms the counting window.
#
# This test demonstrates: a (:read tls 65536) that drains two buffered
# TLS records into the user buffer returns exactly the four buffered
# plaintext bytes and, in the armed window, issues ZERO read() syscalls
# that fail with EAGAIN - with everything already buffered there is no
# kernel read left to make. Under the defect the same drain issues
# exactly one trailing EAGAIN read() per run (measured: 1 in three
# consecutive runs), the predicted symptom of the missing buffered-data
# check. Under fixed code the whole test passes.
#
# Scope note: the guard pins TLS_OP_READ (the ticket's (:read tls 65536)
# case). The TLS_OP_CHUNK retry and the jtls_attempt_io loop condition
# (src/jtls/state_machine.c:634-638) share the same missing
# jtls_has_buffered_data check and are fixed together, but a chunk that
# suspends for more data still performs one legitimate EAGAIN read()
# before parking, so its accounting is a count bound, not the zero
# count this guard asserts.

(use assay)
(import ../helpers :prefix "")

# ---------------------------------------------------------------------------
# Shared child plumbing
# ---------------------------------------------------------------------------

(defn- run-child
  "Spawn a child program under the janet interpreter on PATH. env-extra, when
   given, is merged over the current environment (os/spawn :pe form).
   Returns {:exit n :out stdout :err stderr}."
  [prog &opt env-extra]
  (def proc
    (if env-extra
      (os/spawn ["janet" "-e" prog] :pe
                (merge (os/environ) env-extra {:out :pipe :err :pipe}))
      (os/spawn ["janet" "-e" prog] :p {:out :pipe :err :pipe})))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(def- tmp-counter @[0])
(defn- tmp-base
  "Unique temp path stem per call (test artifacts live outside the tree)."
  []
  (def n (+ 1 (tmp-counter 0)))
  (put tmp-counter 0 n)
  (string "/tmp/jsec-suite-" (os/getpid) "-" n))

# ---------------------------------------------------------------------------
# fb5527b848 guard: no trailing EAGAIN read after draining buffered records
# ---------------------------------------------------------------------------

# The symptom is a syscall-level performance/behaviour detail - an extra
# read(fd) returning EAGAIN - not a user-visible failure, so the guard
# counts the syscall: the interposer appends one byte to a count file
# for every socket read() that returns EAGAIN/EWOULDBLOCK after the
# child arms the trigger file. The child arms the trigger only after
# both TLS records sit in the kernel buffer and immediately before the
# drain read, so handshake WANT_READ probes (which legitimately EAGAIN
# while parking) stay outside the window. errno is saved and restored
# around the probe calls so the interposer cannot change what
# jtls_bio_read observes.
(def- eagain-count-interposer-src
  ```
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t (*real_read)(int, void *, size_t);
static int counting;

static int trigger_armed(void) {
    if (counting) return 1;
    const char *p = getenv("JSEC_EAGAIN_COUNT_ARM");
    if (p && access(p, F_OK) == 0) counting = 1;
    return counting;
}

static void record_eagain(void) {
    const char *p = getenv("JSEC_EAGAIN_COUNT_FILE");
    if (!p) return;
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { ssize_t w = write(fd, "E", 1); (void)w; close(fd); }
}

static int is_socket(int fd) {
    int t;
    socklen_t l = sizeof t;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &l) == 0;
}

ssize_t read(int fd, void *buf, size_t n) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    ssize_t r = real_read(fd, buf, n);
    int e = errno;
    if (r < 0 && (e == EAGAIN || e == EWOULDBLOCK) && is_socket(fd) &&
        trigger_armed()) {
        record_eagain();
    }
    errno = e;
    return r;
}
```)

(defn- compile-eagain-interposer
  "Compile the syscall-counting interposer next to a temp name. Returns the
   shared object path."
  []
  (def base (tmp-base))
  (def c-path (string base ".c"))
  (def so-path (string base ".so"))
  (spit c-path eagain-count-interposer-src)
  (def code (os/execute ["cc" "-shared" "-fPIC" "-O2" "-o" so-path c-path
                         "-ldl"] :p))
  (assert (zero? code)
          (string "failed to compile the EAGAIN counting interposer (cc exit "
                  code ")"))
  so-path)

# Child: complete a TLS handshake over an in-process loopback, queue two
# separate application writes ("aa" + "aa" - two TLS records) from the
# client fiber, arm the counting trigger once both records are sitting
# in the kernel buffer, then issue one (:read s 65536). The read must
# drain both buffered records into the user buffer - four plaintext
# bytes - and every kernel read() in the armed window has data: a
# trailing read() returning EAGAIN is the defect's redundant syscall.
(def- drain-child
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :ec-p256 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [_ port] (net/localname server))
(def ready (ev/chan 1))

(ev/go
  (fn []
    (try
      (do
        (def conn (net/connect "127.0.0.1" (string port)))
        (def c (tls/wrap conn "127.0.0.1" {:verify false}))
        (:write c "aa")
        (:write c "aa")
        (ev/give ready true)
        (ev/sleep 3)
        (:close c true))
      ([e] (ev/give ready (string "client error: " e))))))

(def conn (:accept server))
(def s (tls/wrap conn {:cert (certs :cert) :key (certs :key)}))
(def rv (ev/take ready))
(unless (= true rv) (do (print "RESULT:setup-failed:" rv) (os/exit 1)))
(ev/sleep 0.2)
(spit (os/getenv "JSEC_EAGAIN_COUNT_ARM") "1")
(def r (:read s 65536))
(print "RESULT:ok:" (string r))
(os/exit 0)
```)

(def-suite :name "Redundant EAGAIN After Drain Regression"
  :description "Ticket fb5527b848: a read draining buffered TLS records must not issue a trailing EAGAIN socket read"

  (def-test "read-draining-buffered-records-must-not-issue-a-trailing-eagain-read"
    :timeout 60

    (def so-path (compile-eagain-interposer))
    (def arm (string (tmp-base) ".arm"))
    (def cnt (string (tmp-base) ".cnt"))
    (def child (run-child drain-child
                          {"LD_PRELOAD" so-path
                           "JSEC_EAGAIN_COUNT_ARM" arm
                           "JSEC_EAGAIN_COUNT_FILE" cnt}))
    (def out (child :out))
    (def err (child :err))

    # Environment check: the drain really happened - the child returned
    # all four buffered plaintext bytes in one read, so the counting
    # window below covered the drain read and nothing else.
    (assert (string/find "RESULT:ok:aaaa" out)
            (string/format
              (string "the drain read did not return the four buffered "
                      "plaintext bytes; child stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err)))

    # (a) With both TLS records already buffered in tls->bio_ahead there
    #     is no kernel read left to make: the drain must issue zero
    #     read() syscalls returning EAGAIN. Under the defect TLS_OP_READ
    #     (src/jtls/state_machine.c:281-324) loops one SSL_read past the
    #     drained records because its only exit check is the request
    #     size (:306-311), and that SSL_read reaches jtls_bio_read
    #     (src/jtls/bio.c:65-98) for a kernel read(fd) that fails with
    #     EAGAIN - the redundant syscall this guard counts.
    (def eagain-count (if (os/stat cnt) (length (slurp cnt)) 0))
    (assert (zero? eagain-count)
            (string/format
              (string "the (:read tls 65536) drain of two buffered TLS "
                      "records issued %d read() syscall(s) returning EAGAIN "
                      "in the armed window: TLS_OP_READ "
                      "(src/jtls/state_machine.c:281-324) does not check "
                      "whether buffered data remains once the last buffered "
                      "record is decrypted, so one more SSL_read forces "
                      "jtls_bio_read (src/jtls/bio.c:65-98) into a kernel "
                      "read(fd) that finds an empty socket - the trailing "
                      "redundant EAGAIN read of ticket fb5527b848; child "
                      "stdout: %s")
              eagain-count (string/trim out)))))
