# test/test-toolchain.janet — Hermetic in-tree toolchain acceptance test for jsec
#
# Verifies the toolchain built by scripts/bootstrap-toolchain.sh is HERMETIC and
# SELF-CONSISTENT. This is the acceptance test for the in-tree toolchain feature
# (ticket 94ac1d35486fb6d4a6ef825bde81711ee119f892). It must be run with the
# in-tree toolchain interpreter, e.g.:
#
#   .work/toolchain/bin/janet test/test-toolchain.janet
#
# It is a STANDALONE script (not an assay suite) because it asserts properties of
# the toolchain itself — properties that only hold when the running interpreter
# IS the in-tree janet. Folding it into suites/ would make the normal test matrix
# (run under whatever janet is on PATH) fail spuriously, and it drives build-time
# bootstrap work (compiling a native module) outside assay's matrix model. It is
# modelled on jpq's test/test-toolchain.janet.
#
# Properties asserted:
#   1. (dyn :syspath) is isolated — no ~/.local and no /usr/local leakage.
#   2. The running janet's version equals the version baked into the resolved
#      headerpath's janet.h (the JANET_VERSION_* macros) — the property whose
#      violation is the `config mismatch` defect.
#   3. A trivial native module BUILT with the in-tree jpm LOADS under the in-tree
#      janet without `config mismatch`.
#   4. jpm's resolved :headerpath points inside the toolchain (not a host dir).

(import jpm/default-config :as jpm-config)

# --- Locate the in-tree toolchain from the running interpreter -----------------
# (dyn :executable) is the in-tree janet; its parent is <prefix>/bin and its
# grandparent is the toolchain prefix. Derive everything from that, so the test
# works regardless of where the toolchain is checked out.
(defn path-dirname [p]
  (def parts (string/split "/" p))
  (array/pop parts)
  (string/join parts "/"))

(def exec-path (dyn :executable))
(assert (string? exec-path) "could not determine running janet executable path")
(def exec-real (os/realpath exec-path))
(def bin-dir (path-dirname exec-real))                # <prefix>/bin
(def toolchain-dir (path-dirname bin-dir))            # <prefix>
(def janet-bin (string bin-dir "/janet"))
(def jpm-bin (string bin-dir "/jpm"))

(print "==> jsec hermetic toolchain acceptance test")
(print "    janet executable : " exec-real)
(print "    toolchain prefix : " (os/realpath toolchain-dir))

# --- 1. Syspath isolation -----------------------------------------------------
(def syspath (dyn :syspath))
(print "    syspath          : " syspath)
(assert (string? syspath) "syspath is not set")
(assert (not (string/find "/usr/local" syspath))
        (string "ambient /usr/local leakage detected in syspath: " syspath))
(assert (not (string/find ".local" syspath))
        (string "ambient .local leakage detected in syspath: " syspath))
(print "  [ok] syspath is hermetic (no ~/.local, no /usr/local)")

# --- 2. Version match: running janet vs resolved headerpath janet.h ----------
(def cfg jpm-config/config)
(def headerpath (get cfg :headerpath))
(print "    jpm :headerpath  : " headerpath)
(assert (string? headerpath) "jpm config has no :headerpath")
(assert (not (string/find "/usr/local" headerpath))
        (string "headerpath points at /usr/local: " headerpath))
(assert (not (string/find ".local" headerpath))
        (string "headerpath points at a .local dir: " headerpath))
# The resolved headerpath must live inside this toolchain (the core property:
# a baked headerpath pointing at a foreign Janet reproduces the defect).
(def tc-real (os/realpath toolchain-dir))
(def hp-real (os/realpath headerpath))
(assert (string/has-prefix? tc-real hp-real)
        (string "headerpath " hp-real " is not inside toolchain " tc-real))

(def header-file (string headerpath "/janet.h"))
(assert (os/stat header-file) (string "janet.h not found at " header-file))
(def header-text (slurp header-file))

(defn header-macro-num [name]
  (def p (peg/compile ~(thru (* "#define JANET_VERSION_" ,name (any (if-not :d 1)) (<- (some :d))))))
  (def m (peg/match p header-text))
  (assert m (string "JANET_VERSION_" name " not found in " header-file))
  (scan-number (first m)))

(def h-maj (header-macro-num "MAJOR"))
(def h-min (header-macro-num "MINOR"))
(def h-pat (header-macro-num "PATCH"))
(def header-ver (string h-maj "." h-min "." h-pat))
(print "    header janet.h   : " header-ver " (from JANET_VERSION_* macros)")

(def running-ver janet/version)
(print "    running janet    : " running-ver)

# Normalize a trailing suffix on the running version (e.g. "1.40.1-dev") so only
# major.minor.patch is compared. Falls back to the raw string when unparsable.
(def running-base
  (if-let [m (peg/match '(* (<- (some :d)) "." (<- (some :d)) "." (<- (some :d)) (any 1)) running-ver)]
    (string/join m ".")
    running-ver))

(assert (= running-base header-ver)
        (string "config mismatch - host " running-ver " vs module " header-ver
                " (running janet " running-ver " != headerpath " header-file
                " version " header-ver ")"))
(print "  [ok] running janet version matches headerpath janet.h version")

# --- Helpers to run subprocesses and capture output --------------------------
(defn run-proc [args]
  (def p (os/spawn args :p {:out :pipe :err :pipe}))
  (def out (ev/read (p :out) :all))
  (def err (ev/read (p :err) :all))
  (def code (os/proc-wait p))
  {:code code :output (string (or out "") (or err ""))})

# --- 3. Build a trivial native module with in-tree jpm, load with in-tree janet
# The module is compiled against the toolchain's janet.h, so it embeds that
# version. Loading it under the in-tree janet must succeed WITHOUT a
# `config mismatch` — proving the toolchain is self-consistent end to end.
(def root (os/cwd))
(def mod-src-dir (string root "/.work/scratch/toolchain-modtest"))

(defn rm-recursive [path]
  (when (os/stat path)
    (each entry (os/dir path)
      (def full (string path "/" entry))
      (if (= ((os/stat full) :mode) :directory)
        (rm-recursive full)
        (os/rm full)))
    (os/rmdir path)))

(when (os/stat mod-src-dir) (rm-recursive mod-src-dir))
(os/mkdir mod-src-dir)
(def mod-src-dir-real (os/realpath mod-src-dir))

(spit (string mod-src-dir "/project.janet")
      ``(declare-project
          :name "tcmod"
          :description "toolchain acceptance probe"
          :version "0.0.1")
        (declare-native
          :name "tcmod/mod"
          :source ["mod.c"])
        ``)

(spit (string mod-src-dir "/mod.c")
      ```
#include <janet.h>
static Janet cfun_ping(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    return janet_wrap_keyword("pong");
}
static const JanetReg cfuns[] = {
    {"ping", cfun_ping, "(tcmod/ping)\n\nToolchain acceptance ping."},
    {NULL, NULL, NULL}
};
JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "tcmod", cfuns);
}
```)

(def buildpath (string mod-src-dir-real "/build"))
(print "    building probe module with " jpm-bin)
(def build-res
  (do
    (os/cd mod-src-dir-real)
    (def r (run-proc [jpm-bin
                      (string "--modpath=" (os/realpath (string toolchain-dir "/lib/janet")))
                      (string "--buildpath=" buildpath)
                      "build"]))
    (os/cd root)
    r))

(when (not (zero? (build-res :code)))
  (print "  jpm build output:\n" (build-res :output)))
(assert (zero? (build-res :code))
        (string "in-tree jpm build failed (exit " (build-res :code) ")"))

(def mod-artifact (string buildpath "/tcmod/mod"))
(assert (os/stat (string mod-artifact ".so"))
        (string "built module not found at " mod-artifact ".so"))
(print "  [ok] probe module built with in-tree jpm")

# Load the freshly built module under the in-tree janet. A `config mismatch`
# error here is exactly the defect this feature removes.
(def mod-so (string mod-artifact ".so"))
(def load-res
  (run-proc [janet-bin "-e"
             (string "(native \"" mod-so "\") (print \"MODULE_LOADED\")")]))
(print "    load output      : " (string/trim (load-res :output)))
(assert (not (string/find "config mismatch" (load-res :output)))
        (string "config mismatch loading built module: " (load-res :output)))
(assert (zero? (load-res :code))
        (string "in-tree janet failed to load module (exit " (load-res :code) "): " (load-res :output)))
(assert (string/find "MODULE_LOADED" (load-res :output))
        (string "module did not load cleanly: " (load-res :output)))
(print "  [ok] probe module loads under in-tree janet with no config mismatch")

# Cleanup the probe artifacts (kept under .work/, but leave no residue).
(when (os/stat mod-src-dir) (rm-recursive mod-src-dir))

(print "==> Hermetic toolchain acceptance test passed cleanly.")
