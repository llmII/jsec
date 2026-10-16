# jtls accept/bio/context defect guards
#
# Tickets (combined ticket branch off 0.2.0 at ecef0d3bb2):
#   57794d2ee91da8548b13a1f93436d1ee3b3fbede (57794d2ee9)
#   7fc0fd6e603d52100988ee1d1e09569f14a9c619 (7fc0fd6e60)
#   98ecf6ce7c739838106e8f786b4bca8ea560e0e9 (98ecf6ce7c)
#   e33233e52179fcafc0be14de059b6afc9e5c3c6f (e33233e521)
#
# Each named def-test below is one member ticket's guard and carries its
# own predicted symptom, per docs/maintainer/jsec-conventions.org
# (one suite, one named def-test per listed member ticket).
#
# 7fc0fd6e60 mechanism (this tree): the Unix accept loop at
# src/jtls/api/server.c:205-214 breaks out of its accept4 drain loop on
# EAGAIN/EWOULDBLOCK (:208-210) but executes `continue` on every other
# accept error (:213). A persistent accept error (EMFILE/ENFILE/EBADF)
# therefore drives an infinite tight loop INSIDE the event callback: the
# callback never returns, the event loop serves nothing else, and the
# process burns a full core. Janet core breaks in the same situation
# (net.c:299-313). Predicted symptom: at 100 percent CPU the whole
# process stops serving - a heartbeat fiber starves while the callback
# spins.
#
# 57794d2ee9 mechanism (this tree): jtls_bio_read and jtls_bio_write at
# src/jtls/bio.c:88-93, :110-115 and :144-149 set a BIO retry flag only
# for EAGAIN/EWOULDBLOCK. A read/send returning -1 with EINTR gets no
# retry flag, so OpenSSL reports SSL_ERROR_SYSCALL and the operation is
# cancelled with "Read syscall error: Interrupted system call" (the
# message shape of src/jtls/state_machine.c:192-196). Janet core itself
# loops on EINTR. Predicted symptom: one interrupted transport read kills
# the connection instead of retrying.
#
# 98ecf6ce7c mechanism (this tree): cfun_accept at
# src/jtls/api/server.c:749-750 accepts an optional timeout argument but
# never reads argv[2], so the documented (accept listener opts &opt
# timeout) deadline does nothing. The accept state also up-refs or
# creates its own SSL_CTX (:761-774) and its JANET_ASYNC_EVENT_DEINIT
# case falls through `default: break` (:605), so on ev/with-deadline or
# ev/cancel the ctx is never freed. Predicted symptoms: the timeout is
# silently ignored, and every cancelled accept leaks one SSL_CTX until
# memory pressure.
#
# e33233e521 mechanism (this tree): jtls_create_server_ctx pins the
# session_id_context to the fixed string "jsec_server" at
# src/jtls/context/server.c:101-103, and the SNI callback at
# src/jtls/context/sni.c:26 switches SSL_CTX while keeping the original
# session_ctx of the SSL object, so all SNI vhosts of one accept context
# share one session identity. Predicted symptom: a session established
# for vhost a.example resumes for vhost b.example (session-reused? true
# across vhosts) whenever both vhosts sit behind one accept context.
#
# Shape: every scenario runs in a child janet process (os/spawn of the
# janet interpreter, the pattern of suites/regression/suite-timed-read-timeout-crash.janet).
# The parent asserts from the outside on exit status and RESULT lines.
# Under each defect the corresponding guard fails with exactly the
# predicted symptom - not a crash, not a hang, not an unrelated error;
# under the fixes all guards pass.

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

(defn- proc-cpu-ticks
  "utime + stime of pid from procfs, in clock ticks (HZ=100)."
  [pid]
  (def st (slurp (string "/proc/" pid "/stat")))
  (def parts (string/split " " (string/trim st)))
  (+ (scan-number (parts 13)) (scan-number (parts 14))))

# ---------------------------------------------------------------------------
# 7fc0fd6e60 guard: accept-loop spin under a persistent accept error
# ---------------------------------------------------------------------------

# Child: start a tls accept-loop, beat a heartbeat file every 100 ms,
# then exhaust the fd table so the next accept4 fails with EMFILE. The
# parent connects one client afterwards: the accept callback runs,
# accept4 fails EMFILE, and the defect's `continue` spins the loop. Live
# coordination goes through marker files (ready, meta, exhausted) and the
# heartbeat file because a starved process cannot report over its pipes.
(def- spin-child
  ```
(import jsec/tls :as tls)
(import jsec/tls-stream :as ts)
(import jsec/cert :as cert)

(def dir (os/getenv "SPIN_DIR"))
(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :ec-p256 :days-valid 1}))
(def ctx (tls/new-context {:cert (certs :cert) :key (certs :key)}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))
(def f (file/open (string dir "/meta") :w))
(file/write f (string port))
(file/close f)
(file/open (string dir "/ready") :w)

(ev/go (fn [] (ts/accept-loop server ctx (fn [s] nil))))

(def hb-file (file/open (string dir "/heartbeat") :a))
(ev/go
  (fn []
    (try
      (forever
        (ev/sleep 0.1)
        (file/write hb-file "H")
        (file/flush hb-file))
      ([e] nil))))

(ev/sleep 0.3)
(def fds @[])
(try
  (forever
    (array/push fds (os/open "/dev/null" :r)))
  ([e] nil))
# The fd table is full now - no new handle can be opened, so signal
# readiness on the heartbeat handle that is already open: one X marker.
(file/write hb-file "X")
(file/flush hb-file)

(ev/sleep 6)
(file/close hb-file)
(os/exit 0)
```)

# ---------------------------------------------------------------------------
# 57794d2ee9 guard: EINTR on the transport read must retry
# ---------------------------------------------------------------------------

# The defect is in the handling of the kernel-level -1/EINTR return of
# read on the transport socket. Under janet's os/sigaction every handler
# runs with SA_RESTART so a signal cannot produce that return, so the
# guard injects the exact syscall condition once via a preloaded
# interposer: the first socket read that would report EAGAIN after the
# child arms the trigger file returns -1 with errno EINTR instead. The
# interposer is test-only code compiled at run time and never touches the
# tree.
(def- eintr-interposer-src
  ```
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t (*real_read)(int, void *, size_t);
static int injected;

static int trigger_armed(void) {
    const char *p = getenv("JSEC_EINTR_TRIGGER");
    return p && access(p, F_OK) == 0;
}

static int is_socket(int fd) {
    int t;
    socklen_t l = sizeof t;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &l) == 0;
}

ssize_t read(int fd, void *buf, size_t n) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    ssize_t r = real_read(fd, buf, n);
    if (r < 0) {
        int e = errno;
        if (e == EAGAIN && !injected && is_socket(fd) && trigger_armed()) {
            injected = 1;
            errno = EINTR;
            return -1;
        }
        errno = e;
    }
    return r;
}
```)

(defn- compile-eintr-interposer
  "Compile the fault-injection interposer next to a temp name. Returns the
   shared object path."
  []
  (def base (tmp-base))
  (def c-path (string base ".c"))
  (def so-path (string base ".so"))
  (spit c-path eintr-interposer-src)
  (def code (os/execute ["cc" "-shared" "-fPIC" "-O2" "-o" so-path c-path
                         "-ldl"] :p))
  (assert (zero? code)
          (string "failed to compile the EINTR interposer (cc exit " code ")"))
  so-path)

# Child: complete a TLS handshake over an in-process loopback, arm the
# trigger file, then park on a TLS read with the peer silent and a 3 s
# deadline while the peer writes "hello" after 300 ms. The next transport
# read that would report EAGAIN is turned into -1/EINTR exactly once. A
# healthy BIO layer retries and the read returns "hello"; the defect
# fails the connection with the predicted syscall error text.
(def- eintr-child
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :ec-p256 :days-valid 1}))

(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))

(ev/go
  (fn []
    (try
      (do
        (def conn (:accept server))
        (def s (tls/wrap conn {:cert (certs :cert) :key (certs :key)}))
        (:read s 1)
        (ev/sleep 0.3)
        (:write s "hello"))
      ([e] (print "SRV-ERR:" e)))))

(def client-sock (net/connect host port))
(def c (tls/wrap client-sock {:verify false :hostname "127.0.0.1"}))
(:write c "x")

(file/open (os/getenv "JSEC_EINTR_TRIGGER") :w)
(try
  (do
    (def data (:read c 5 nil 3))
    (print "RESULT:ok:" data))
  ([e] (print "RESULT:error:" e)))
(os/exit 0)
```)

# ---------------------------------------------------------------------------
# 98ecf6ce7c guards: accept timeout expiry and cancelled-accept ctx leak
# ---------------------------------------------------------------------------

# Timeout half: accept with a 0.2 s deadline on a listener that sees no
# connection until a sentinel arrives at 1.2 s. The expiry contract is
# the ev/read shape (raise "timeout"): under the defect the deadline does
# nothing and accept returns a TLS stream only when the sentinel arrives.
(def- accept-timeout-child
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)
(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :ec-p256 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))
(ev/go
  (fn []
    (ev/sleep 1.2)
    (try (def c (net/connect host port)) ([e] nil))))
(def t0 (os/clock))
(try
  (do
    (def s (tls/accept server {:cert (certs :cert) :key (certs :key)} 0.2))
    (print "RESULT:accepted-after:"
           (math/round (* 1000 (- (os/clock) t0))) "ms"))
  ([e]
    (print "RESULT:error:" e " after:"
           (math/round (* 1000 (- (os/clock) t0))) "ms")))
(os/exit 0)
```)

# Leak half: 150 cancelled tls/accept calls, each with DISTINCT
# credentials so the one-slot server ctx cache cannot mask the leak (a
# cache hit reuses one SSL_CTX and hides it). Each accept up-refs or
# creates its own SSL_CTX; the defect's DEINIT path never frees it, so
# VmRSS grows by roughly one SSL_CTX per cancelled accept (~27 KB on this
# platform). The fix must keep the growth at baseline noise.
(def- accept-leak-child
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def server (net/listen "127.0.0.1" "0"))

(defn rss-kb []
  (def st (slurp "/proc/self/status"))
  (def line (find |(string/find "VmRSS:" $) (string/split "\n" st)))
  (scan-number (first (string/split " " (string/trim (last (string/split ":" line)))))))

(defn round [certs]
  (def f (ev/go (fn [] (try (tls/accept server {:cert (certs :cert) :key (certs :key)}) ([e] nil)))))
  (ev/sleep 0.005)
  (ev/cancel f "cancelled"))

(round (cert/generate-self-signed-cert
          {:common-name "127.0.0.1" :key-type :ec-p256 :days-valid 1}))
(gccollect) (ev/sleep 0.2) (gccollect)
(def r0 (rss-kb))
(def N 150)
(for i 0 N
  (round (cert/generate-self-signed-cert
           {:common-name (string "h" i) :key-type :ec-p256 :days-valid 1})))
(gccollect) (ev/sleep 0.3) (gccollect)
(def r1 (rss-kb))
(print "RESULT:rss-delta-kb:" (- r1 r0) " rounds:" N)
(os/exit 0)
```)

# ---------------------------------------------------------------------------
# e33233e521 guard: cross-vhost session resumption via fixed sid_ctx
# ---------------------------------------------------------------------------

# Child: one accept context with an SNI map of two vhosts backed by two
# different certificates, forced to TLS 1.2 for session-id resumption.
# (a) control: a session from vhost a.example must still resume on
#     a.example (scenario validity),
# (b) contract: the same session must NOT resume on vhost b.example -
#     under the fixed session_id_context shared by every vhost it does
#     (session-reused? true) and the guard fails with exactly that
#     symptom.
(def- sidctx-child
  ```
(import jsec/tls :as tls)
(import jsec/tls-stream :as ts)
(import jsec/cert :as cert)

(def sec @{:min-version "TLS1.2" :max-version "TLS1.2"})
(def certsA (cert/generate-self-signed-cert
              {:common-name "a.example" :key-type :ec-p256 :days-valid 1}))
(def certsB (cert/generate-self-signed-cert
              {:common-name "b.example" :key-type :ec-p256 :days-valid 1}))
(def ctx (tls/new-context
           {:cert (certsA :cert) :key (certsA :key) :security sec
            :sni {"a.example" {:cert (certsA :cert) :key (certsA :key)}
                  "b.example" {:cert (certsB :cert) :key (certsB :key)}}}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))

(ev/go
  (fn []
    (try
      (forever
        (def c (tls/accept server ctx))
        (ev/go
          (fn []
            (try
              (do (def b (:read c 1 nil 5)) (:write c "X") (:close c))
              ([e] (try (:close c) ([_] nil)))))))
      ([e] nil))))

(defn probe [label sni sess]
  (def opts @{:verify false :hostname sni :security sec})
  (try
    (do
      (def c (tls/connect host (string port) opts))
      (when sess (ts/set-session c sess))
      (:write c "h")
      (def r (:read c 1 nil 5))
      (def reused (ts/session-reused? c))
      (def s (ts/get-session c))
      (print "PROBE:" label " reused=" reused)
      (:close c)
      [reused s])
    ([e] (print "PROBE:" label " ERROR:" e) [nil nil])))

(def [r1 sess1] (probe "a-first" "a.example" nil))
(ev/sleep 0.3)
(def [r2 sess2] (probe "a-resume-a" "a.example" sess1))
(ev/sleep 0.3)
(def [r3 sess3] (probe "a-session-on-b" "b.example" sess1))
(print "SUMMARY a-first=" r1 " a-resume-a=" r2 " a-session-on-b=" r3)
(os/exit 0)
```)

(def-suite :name "JTLS Accept Bio Context Guards Regression"
  :description "Accept/bio/context behavioral guards: 7fc0fd6e60 accept-loop spin, 57794d2ee9 EINTR retry, 98ecf6ce7c accept timeout and ctx leak, e33233e521 session_id_context"

  (def-test "accept-loop-persistent-accept-error-must-not-spin-the-event-loop"
    :timeout 60

    # The child accept-loop beats a heartbeat file every 100 ms and then
    # exhausts its fd table; the parent connects one client so accept4
    # fails with EMFILE inside the loop callback. The window below is
    # measured from the outside with procfs cpu ticks and the heartbeat
    # file.
    (def dir (string (tmp-base) ".spin"))
    (os/mkdir dir)
    (def proc
      (os/spawn ["janet" "-e" spin-child] :pe
                (merge (os/environ) {"SPIN_DIR" dir} {:out :pipe :err :pipe})))
    (def out-buf @"")
    (def err-buf @"")
    (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
    (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))

    # Wait for the X marker the child writes on its heartbeat handle
    # after the fd table is exhausted (the child is ready for the
    # trigger).
    (defn- hb-ready? []
      (and (os/stat (string dir "/heartbeat"))
           (string/find "X" (string (slurp (string dir "/heartbeat"))))))
    (var waited 0)
    (while (and (not (hb-ready?)) (< waited 200))
      (ev/sleep 0.05)
      (++ waited))
    (assert (hb-ready?)
            (string "spin child never reached fd exhaustion; child stderr: "
                    (string/trim (string err-buf))))

    (def port (string/trim (string (slurp (string dir "/meta")))))
    (def client (net/connect "127.0.0.1" port))
    (ev/sleep 0.2)

    (def pid (proc :pid))
    (def cpu1 (proc-cpu-ticks pid))
    (def hb1 (length (slurp (string dir "/heartbeat"))))
    (ev/sleep 1.5)
    (def cpu2 (proc-cpu-ticks pid))
    (def hb2 (length (slurp (string dir "/heartbeat"))))
    (def cpu-delta (- cpu2 cpu1))
    (def hb-delta (- hb2 hb1))

    (os/proc-kill proc)
    (ev/sleep 0.2)
    (try (os/proc-wait proc) ([_] nil))
    (:close (proc :out))
    (:close (proc :err))

    # (a) The event loop must keep serving while accept() reports a
    #     persistent error: the callback has to return. Under the defect
    #     the accept4 drain loop spins inside the callback and the
    #     heartbeat freezes (denial of service).
    (assert (> hb-delta 0)
            (string/format
              (string "the accept loop spun inside the event callback on a "
                      "persistent accept() error (EMFILE) and denied service "
                      "to the whole process: heartbeat advanced %d beats in "
                      "1.5 s while the loop burned %d of 150 cpu ticks "
                      "(100 percent core) in an infinite tight loop "
                      "(src/jtls/api/server.c:213 continues instead of "
                      "breaking); child stderr: %s")
              hb-delta cpu-delta (string/trim (string err-buf))))

    # (b) The loop must not burn a full core on a persistent accept
    #     error: break or back off, never spin.
    (assert (< cpu-delta 120)
            (string/format
              (string "the accept loop burned %d of 150 cpu ticks over 1.5 s "
                      "on a persistent accept() error (EMFILE): the accept4 "
                      "drain loop at src/jtls/api/server.c:213 spins instead "
                      "of breaking or backing off")
              cpu-delta)))

  (def-test "eintr-on-transport-read-must-retry-instead-of-failing-the-connection"
    :timeout 60

    (def so-path (compile-eintr-interposer))
    (def trigger (string (tmp-base) ".trg"))
    (def child (run-child eintr-child
                          {"LD_PRELOAD" so-path
                           "JSEC_EINTR_TRIGGER" trigger}))
    (def out (child :out))
    (def err (child :err))

    # (a) The connection must survive exactly one EINTR at the transport
    #     read boundary: the parked TLS read retries and returns the
    #     peer's "hello". Under the defect the same read dies with the
    #     predicted symptom "Read syscall error: Interrupted system call".
    (assert (string/find "RESULT:ok:hello" out)
            (string/format
              (string "an EINTR on the transport read killed the TLS "
                      "connection instead of being retried: expected the "
                      "parked read to survive the interrupted read() and "
                      "return the peer's hello, the predicted symptom is "
                      "\"Read syscall error: Interrupted system call\"; "
                      "child stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err))))

  (def-test "accept-timeout-must-expire-and-cancelled-accept-must-free-its-context"
    :timeout 60

    # Both children first so one failing run carries both predicted
    # symptoms in its evidence.
    (def t-child (run-child accept-timeout-child))
    (def t-out (t-child :out))
    (def t-err (t-child :err))
    (def l-child (run-child accept-leak-child))
    (def l-out (l-child :out))
    (def l-err (l-child :err))

    # Half (a): the documented timeout must expire as a Janet error (the
    # ev/read expiry contract). Under the defect the deadline is ignored
    # and accept returns a stream when the sentinel connector arrives.
    (assert (string/find "RESULT:error:" t-out)
            (string/format
              (string "tls/accept ignored its documented 0.2 s timeout: with "
                      "no connection arriving it did not expire as a Janet "
                      "error, it returned a TLS stream when the sentinel "
                      "connector arrived after 1.2 s (the expiry contract is "
                      "the ev/read shape: raise \"timeout\"); timeout child "
                      "stdout: %s; timeout child stderr: %s; leak child "
                      "stdout: %s")
              (string/trim t-out) (string/trim t-err) (string/trim l-out)))

    # Half (b): 150 cancelled accepts with distinct credentials must not
    # accumulate ctx memory. Under the defect each cancelled accept leaks
    # its SSL_CTX (~27 KB each, ~4 MB per 150 rounds on this platform)
    # because the DEINIT case falls through default at
    # src/jtls/api/server.c:605 and never frees the ctx created or
    # up-ref'd at :761-774.
    (assert (string/find "RESULT:rss-delta-kb:" l-out)
            (string/format
              (string "leak child did not report a VmRSS delta; child "
                      "stdout: %s; child stderr: %s")
              (string/trim l-out) (string/trim l-err)))
    (def m (string/find "RESULT:rss-delta-kb:" l-out))
    (def delta-kb
      (scan-number (first (string/split " " (string/trim (string (slice l-out (+ m 20))))))))
    (assert (< delta-kb 1500)
            (string/format
              (string "cancelled tls/accept calls leak their SSL_CTX: "
                      "VmRSS grew %d KB across 150 cancelled accepts with "
                      "distinct credentials (about %d KB each): the "
                      "JANET_ASYNC_EVENT_DEINIT case of tls_accept_callback "
                      "falls through default at src/jtls/api/server.c:605 "
                      "and never frees the SSL_CTX created or up-ref'd at "
                      ":761-774; child stdout: %s; child stderr: %s")
              delta-kb (math/round (/ delta-kb 150))
              (string/trim l-out) (string/trim l-err))))

  (def-test "session-for-one-sni-vhost-must-not-resume-on-another-vhost"
    :timeout 60

    (def child (run-child sidctx-child))
    (def out (child :out))
    (def err (child :err))

    # (a) Scenario validity: a full first handshake, and same-vhost
    #     resumption still works (the fix narrows resumption across
    #     vhosts, it does not break resumption).
    (assert (string/find "SUMMARY a-first=false a-resume-a=true" out)
            (string/format
              (string "resumption scenario is not valid on this build: a "
                      "first handshake must be full and a session must "
                      "still resume on its own SNI vhost; child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))

    # (b) A session established for vhost a.example must not resume for
    #     vhost b.example. Under the fixed session_id_context every vhost
    #     of one accept context shares one session identity
    #     (src/jtls/context/server.c:101-103) and the SNI path keeps the
    #     original session_ctx (src/jtls/context/sni.c:26), so the
    #     session for a.example resumes on b.example with session-reused?
    #     true - the predicted symptom.
    (assert (string/find "a-session-on-b=false" out)
            (string/format
              (string "a TLS session established for SNI vhost a.example "
                      "resumed for SNI vhost b.example (session-reused? is "
                      "true across vhosts): every vhost shares the fixed "
                      "session_id_context jsec_server "
                      "(src/jtls/context/server.c:101-103) and the SNI "
                      "callback keeps the original session_ctx "
                      "(src/jtls/context/sni.c:26), so a session for one "
                      "vhost resumes for another; child stdout: %s; child "
                      "stderr: %s")
              (string/trim out) (string/trim err))))

)
