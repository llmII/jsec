(declare-project
  :name "jsec"
  :description "TLS/SSL support for Janet using OpenSSL"
  :author "llmII <dev@amlegion.org>"
  :license "ISC"
  :url "https://github.com/llmII/jsec"
  :repo "git+https://github.com/llmII/jsec.git"
  :dependencies [{:url "https://github.com/janet-lang/spork.git"
                  :tag "master"}
                 {:url "https://github.com/llmII/janet-assay.git"
                  :tag "main"}]
  :version "0.1.0")

# ============================================================================
# Janet Version Floor
# ============================================================================
# jsec needs Janet 1.41.1 or newer (janet PR 1683, merge d3f5b541): that
# release fixes a unix-socket connect hang on edge-triggered kqueue where
# connect() completing synchronously still scheduled an async writability
# wait that never fires, so older Janets hang rather than fail. Hard floor -
# no override.

(def jsec-min-janet-version "1.41.1")

# janet/version is a string on 1.41.1+, and may be a callable on older
# Janets; handle both shapes. Call it through a parameter - a direct
# (janet/version) is a compile error when the value is the 1.41.1+ string,
# even in the untaken branch.
(def- jsec-janet-version
  (string (if (string? janet/version)
            janet/version
            ((fn [f] (f)) janet/version))))

# [major minor patch] of a dotted version, -/+ suffixes dropped and missing
# components read as 0; nil when the string does not conform.
(defn- jsec-version-tuple [v]
  (def parts
    (string/split "." (first (string/split "+" (first (string/split "-" v))))))
  (when (and (<= 1 (length parts) 3)
             (all |(and (not (empty? $)) (string/check-set "0123456789" $))
                  parts))
    (take 3 [;(map scan-number parts) 0 0])))

(defn- jsec-version-at-least? [v floor]
  (def a (jsec-version-tuple v))
  (def b (jsec-version-tuple floor))
  (and a b (>= (compare a b) 0)))

(unless (jsec-version-at-least? jsec-janet-version jsec-min-janet-version)
  (errorf (string "jsec requires Janet %s or newer, refusing to run against "
                  "Janet %s. Janet 1.41.1 fixes a unix-socket connect hang on "
                  "edge-triggered kqueue (janet PR 1683, merge d3f5b541): "
                  "connect() completing synchronously still scheduled an "
                  "async writability wait that never fires, so older Janets "
                  "hang rather than fail. Upgrade Janet, or build through the "
                  "hermetic in-tree toolchain (docs/DEVELOPERS.org); there is "
                  "no override.")
          jsec-min-janet-version jsec-janet-version))

# ============================================================================
# Platform Detection
# ============================================================================

(def- windows? (= (os/which) :windows))
(def- macos? (= (os/which) :macos))
(def- dragonfly? (= (os/which) :dragonfly))
(def- illumos? (= (os/which) :illumos))

# ============================================================================
# Build Configuration (from environment or active toolchain stamp)
# ============================================================================

(defn- detect-toolchain-sanitizer []
  (when-let [syspath (dyn :syspath)
             stamp-path (string syspath "/../../TOOLCHAIN")
             _ (os/stat stamp-path)
             content (slurp stamp-path)]
    (var found nil)
    (each line (string/split "\n" content)
      (when (string/has-prefix? "sanitizer:" line)
        (def v (string/trim (string/slice line (length "sanitizer:"))))
        (when (and (not (empty? v)) (not= v "none"))
          (set found v))))
    found))

(def- toolchain-san (detect-toolchain-sanitizer))
(def- san-env (or (os/getenv "JSEC_SANITIZER")
                  (when (os/getenv "JSEC_SAN") "san")
                  toolchain-san))

(def- debug? (os/getenv "JSEC_DEBUG"))
(def- asan? (or (os/getenv "JSEC_ASAN") (= san-env "asan") (= san-env "san")))
(def- lsan? (or (os/getenv "JSEC_LSAN") (= san-env "lsan")))
(def- ubsan? (or (os/getenv "JSEC_UBSAN") (= san-env "ubsan") (= san-env "san")))
(def- verbose? (os/getenv "JSEC_DEBUG_VERBOSE"))

# ============================================================================
# File System Helpers
# ============================================================================

(defn- find-files-by-suffixes [dir suffixes]
  "Recursively find files matching any suffix in suffixes list.
   Returns array of paths relative to current directory."
  (def results @[])
  (defn scan [path]
    (when (os/stat path)
      (each entry (os/dir path)
        (def full (string path "/" entry))
        (def stat (os/stat full))
        (when stat
          (case (stat :mode)
            :directory (scan full)
            :file (when (some |(string/has-suffix? $ entry) suffixes)
                    (array/push results full)))))))
  (scan dir)
  (sort results))

(defn- rmdir-recursive [path]
  "Recursively remove a directory and its contents"
  (when (os/stat path)
    (each entry (os/dir path)
      (def full-path (string path "/" entry))
      (def stat (os/stat full-path))
      (if (= (stat :mode) :directory)
        (rmdir-recursive full-path)
        (os/rm full-path)))
    (os/rmdir path)))

(defn- rm-if-exists [path]
  "Remove a file if it exists"
  (when (os/stat path)
    (os/rm path)))

# ============================================================================
# OpenSSL Path Detection
# ============================================================================

(def- openssl-prefix
  (cond
    macos?
    (or (os/getenv "OPENSSL_PREFIX")
        (if (os/stat "/opt/homebrew/opt/openssl@3")
          "/opt/homebrew/opt/openssl@3" # ARM Mac
          "/usr/local/opt/openssl@3")) # Intel Mac
    dragonfly? "/usr/local"
    illumos? (or (os/getenv "OPENSSL_PREFIX") "/usr/openssl/3")
    windows?
    (when-let [vcpkg-root (os/getenv "VCPKG_ROOT")]
      (string (string/trim vcpkg-root) "/installed/x64-windows"))
    nil))

# ============================================================================
# Compiler Flags
# ============================================================================

# Standard flags - comprehensive warnings for defensive builds
# These catch issues that may only manifest on stricter platforms
# (e.g., ARM Mac). Note: Some flags omitted because janet.h macros
# trigger unavoidable warnings.
(def- standard-cflags
  (if windows?
    ["/O2" "/W4" "/MD" "/wd4152" "/wd4702"]
    ["-std=c99" "-O2"
     # Basic warnings
     "-Wall" "-Wextra" "-Wshadow" "-fno-common"
     "-Wuninitialized" "-Wpointer-arith" "-Wstrict-prototypes"
     "-Wfloat-equal" "-Wformat=2" "-Wimplicit-fallthrough"
     # Integer/pointer conversion warnings (critical for cross-platform)
     "-Wint-conversion" "-Wpointer-to-int-cast" "-Wint-to-pointer-cast"
     # Null pointer and type safety
     "-Wnull-dereference" "-Wcast-align"
     # Sign conversion (can catch subtle bugs)
     "-Wsign-compare"]))

# Sanitizer flags (Unix only) - decoupled from JSEC_DEBUG so sanitizer
# toolchains (.work/{asan,lsan,ubsan,san}) and JSEC_{ASAN,LSAN,UBSAN,SAN}=1
# apply sanitizer compile/link flags directly.
(defn- build-sanitizer-list []
  (if windows?
    @[]
    (let [sanitizers @[]]
      (when asan? (array/push sanitizers "address"))
      (when (and lsan? (not asan?)) (array/push sanitizers "leak"))
      (when ubsan? (array/push sanitizers "undefined"))
      sanitizers)))

(defn- build-sanitizer-recover-list []
  (if windows?
    @[]
    (let [recover @[]]
      (when asan? (array/push recover "address"))
      (when ubsan? (array/push recover "undefined"))
      recover)))

(def- sanitizer-cflags
  (let [sanitizers (build-sanitizer-list)
        recover (build-sanitizer-recover-list)]
    (if (empty? sanitizers)
      @[]
      (let [flags @["-O1" "-g3" "-fno-omit-frame-pointer"
                    "-fno-optimize-sibling-calls"
                    (string "-fsanitize=" (string/join sanitizers ","))]]
        (unless (empty? recover)
          (array/push flags
                      (string "-fsanitize-recover="
                              (string/join recover ","))))
        flags))))

(def- sanitizer-lflags
  (let [sanitizers (build-sanitizer-list)]
    (if (empty? sanitizers)
      @[]
      @[(string "-fsanitize=" (string/join sanitizers ","))])))

(def- debug-cflags
  (if windows?
    @["/Zi" "/Od" "/DJSEC_DEBUG"]
    (let [base @["-g3" "-Og" "-fno-omit-frame-pointer"
                 "-fstack-protector-strong" "-DJSEC_DEBUG"]]
      (when verbose?
        (array/push base "-DJSEC_DEBUG_VERBOSE"))
      base)))

(def- debug-lflags
  (if windows?
    @["/DEBUG"]
    @[]))

(def- platform-cflags
  (cond
    windows?
    (if openssl-prefix
      [(string "/I" openssl-prefix "/include")]
      [])
    illumos?
    [(string "-I" openssl-prefix "/include") "-D__EXTENSIONS__"]
    openssl-prefix
    [(string "-I" openssl-prefix "/include")]
    []))

(def- platform-lflags
  (cond
    windows?
    (if openssl-prefix
      [(string "/LIBPATH:" openssl-prefix "/lib")
       "libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"]
      ["libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"])
    illumos?
    (let [libdir (string openssl-prefix "/lib/amd64")]
      [(string "-L" libdir) (string "-Wl,-R," libdir)
       "-lssl" "-lcrypto" "-lsocket" "-lnsl"])
    openssl-prefix
    [(string "-L" openssl-prefix "/lib") "-lssl" "-lcrypto"]
    ["-lssl" "-lcrypto"]))

(def- build-cflags
  [;standard-cflags
   ;(if debug? debug-cflags [])
   ;sanitizer-cflags
   ;platform-cflags])

(def- build-lflags
  [;platform-lflags
   ;(if debug? debug-lflags [])
   ;sanitizer-lflags])

# Windows DLL handling
(when windows?
  (setdyn :dynamic-cflags @["/LD" "/DJANET_DLL_IMPORT"]))

# ============================================================================
# Source File Scanning
# ============================================================================

# jutils shared sources - used by all modules (without module.c entry point)
(def- jutils-shared-sources
  (filter |(not (string/has-suffix? "module.c" $))
          (find-files-by-suffixes "src/jutils" [".c"])))
(def- jutils-headers (find-files-by-suffixes "src/jutils" [".h"]))
# jutils full sources - for jsec/utils module only
(def- jutils-all-sources (find-files-by-suffixes "src/jutils" [".c"]))

# ============================================================================
# Module Declarations
# ============================================================================

(declare-native
  :name "jsec/utils"
  :source jutils-all-sources
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/tls-stream"
  :source [;(find-files-by-suffixes "src/jtls" [".c"]) ;jutils-shared-sources]
  :headers [;(find-files-by-suffixes "src/jtls" [".h"]) ;jutils-headers]
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/dtls-stream"
  :source [;(find-files-by-suffixes "src/jdtls" [".c"]) ;jutils-shared-sources]
  :headers [;(find-files-by-suffixes "src/jdtls" [".h"]) ;jutils-headers]
  :cflags build-cflags
  :lflags build-lflags)

(declare-source
  :source ["jsec/tls.janet"]
  :prefix "jsec")

(declare-native
  :name "jsec/cert"
  :source [;(find-files-by-suffixes "src/jcert" [".c"]) ;jutils-shared-sources]
  :headers jutils-headers
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/bio"
  :source ["src/jbio.c" ;jutils-shared-sources]
  :headers jutils-headers
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/crypto"
  :source [;(find-files-by-suffixes "src/jcrypto" [".c"])
           ;jutils-shared-sources]
  :headers [;(find-files-by-suffixes "src/jcrypto" [".h"]) ;jutils-headers]
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/ca"
  :source [;(find-files-by-suffixes "src/jca" [".c"]) ;jutils-shared-sources]
  :headers [;(find-files-by-suffixes "src/jca" [".h"]) ;jutils-headers]
  :cflags build-cflags
  :lflags build-lflags)

(declare-bin
  :main "bin/perf9-analyze.janet"
  :name "perf9-analyze")

# ============================================================================
# Phony Targets
# ============================================================================

(phony "clean" []
       (print "Cleaning build artifacts...")
       (rmdir-recursive (dyn :buildpath "build"))
       (rmdir-recursive "jpm_tree")
       # Remove generated markdown files
       (each f (find-files-by-suffixes "." [".md"])
         (when (not (string/find "jpm_tree" f))
           (rm-if-exists f)))
       (rm-if-exists "valgrind-output.txt")
       (rm-if-exists "debug.log")
       (print "Clean complete."))

# Format C code with clang-format
(phony "format/c" []
       (print "Formatting C source files...")
       (def files (find-files-by-suffixes "src" [".c" ".h"]))
       (when (not (empty? files))
         (os/execute ["clang-format" "-i" ;files] :p)))

# Format Janet code with janet-format
(phony "format/janet" []
       (print "Formatting Janet source files...")
       (def all-janet @[])
       (each dir ["." "jsec" "bin" "test" "examples"]
         (when (os/stat dir)
           (array/concat all-janet (find-files-by-suffixes dir [".janet"]))))
       # Exclude jpm_tree and build
       (def files (filter |(not (or (string/find "jpm_tree" $)
                                    (string/find "build" $))) all-janet))
       (when (not (empty? files))
         (os/execute ["janet-format" "-f" ;files] :p)))

# Format org files - align tables (emacs requires per-file)
(phony "format/org" []
       (print "Aligning tables in org files...")
       (def files (find-files-by-suffixes "." [".org"]))
       (def filtered (filter |(not (or (string/find "jpm_tree" $)
                                       (string/find "/." $))) files))
       (each f filtered
         (os/execute ["emacs" "--batch" f
                      "--eval" "(org-table-map-tables #'org-table-align t)"
                      "-f" "save-buffer"] :p)))

# Format all code
(phony "format/all" ["format/c" "format/janet" "format/org"]
       (print "All code formatted."))

# Convenient aliases matching CONTRIBUTING.org
(phony "format" ["format/all"])
(phony "format-c" ["format/c"])
(phony "format-janet" ["format/janet"])

# Check C code formatting with clang-format
(phony "check-format-c" []
       (print "Checking C formatting...")
       (def files (find-files-by-suffixes "src" [".c" ".h"]))
       (when (not (empty? files))
         (os/execute ["clang-format" "--dry-run" "-Werror" ;files] :p)))

# Clang-tidy static analysis
(phony "tidy" []
       (print "Running clang-tidy static analysis...")
       (def janet-inc
         (cond
           (os/stat "/usr/local/include/janet/janet.h")
           "/usr/local/include/janet"
           (os/stat
             (string (os/getenv "HOME") "/.local/include/janet/janet.h"))
           (string (os/getenv "HOME") "/.local/include/janet")
           (os/stat "/usr/include/janet/janet.h")
           "/usr/include/janet"
           "/usr/include"))
       (def include-args
         [(string "-I" janet-inc) "-I/usr/include/openssl" "-Isrc"])
       (def files (find-files-by-suffixes "src" [".c"]))
       (var failed false)
       (each src files
         (def proc
           (os/spawn ["clang-tidy" "--quiet" src "--" "-std=c99" ;include-args]
                     :p {:out :pipe :err :pipe}))
         (def stdout-content (ev/read (proc :out) :all))
         (def stderr-content (ev/read (proc :err) :all))
         (os/proc-wait proc)
         (def combined (string (or stdout-content "") (or stderr-content "")))
         # Filter noise and check for real issues
         (when (or (string/find "warning:" combined)
                   (string/find "error:" combined))
           (def lines (string/split "\n" combined))
           (def filtered
             (filter |(not (string/find "warnings generated" $)) lines))
           (print (string/join filtered "\n"))
           (set failed true)))
       (if failed
         (do
           (print "\nclang-tidy found issues.")
           (os/exit 1))
         (print "\nclang-tidy: All checks passed!")))

# Release task - generate markdown from org files
(phony "release" ["clean" "format/all"]
       (print "Generating markdown documentation from org files...")
       (def files (find-files-by-suffixes "." [".org"]))
       (def filtered (filter |(not (or (string/find "jpm_tree" $)
                                       (string/find "/." $))) files))
       (each f filtered
         (os/execute ["emacs" "--batch"
                      "--eval" "(require 'ox-md)"
                      f "-f" "org-md-export-to-markdown"] :p))
       (print "Release preparation complete."))

# Leak check with valgrind - placeholder
(phony "test/valgrind" []
       (print "Note: Valgrind leak checking requires a debug build.")
       (print
         (string "Run manually: valgrind --leak-check=full "
                 "janet test/runner.janet"))
       (print "This target is a no-op for now."))
(phony "leak-check" ["test/valgrind"])

# ============================================================================
# Hermetic In-Tree Toolchain (see docs/DEVELOPERS.org)
# ============================================================================
# These run bootstrap and tests through .work/bin/{janet,jpm}, never the host
# janet/jpm. First invocation may use `jpm run` as a dispatcher; the actual
# build/test steps invoke the in-tree tools by path.

(defn- run-or-fail [args &opt extra-env]
  (def code
    (if extra-env
      (os/execute args :pe (merge (os/environ) extra-env))
      (os/execute args :p)))
  (unless (zero? code)
    (print "command failed (exit " code "): " (string/join args " "))
    (os/exit code)))

(def- toolchain-janet ".work/bin/janet")
(def- toolchain-jpm ".work/bin/jpm")

# Poll-backend toolchain: Janet built with JANET_EV_NO_EPOLL + JANET_EV_NO_KQUEUE
# so the poll(2) fallback is active. Lives beside the default .work/ toolchain
# so both can coexist at the same Janet rev (see docs/DEVELOPERS.org).
(def- poll-toolchain-janet ".work/poll/bin/janet")
(def- poll-toolchain-jpm ".work/poll/bin/jpm")

# A toolchain's installed module tree (the janet binary's baked syspath).
(def- toolchain-modpath ".work/lib/janet")
(def- poll-toolchain-modpath ".work/poll/lib/janet")

(defn- san-build-env [sanitizer]
  (when sanitizer
    {"JSEC_SANITIZER" sanitizer
     "ASAN_OPTIONS" "detect_leaks=0:halt_on_error=0"
     "LSAN_OPTIONS" "detect_leaks=0"
     "UBSAN_OPTIONS" "halt_on_error=0"}))

(defn- san-test-env [sanitizer log-prefix]
  (def cwd (os/cwd))
  (def halt (if (os/getenv "JSEC_SAN_HALT") "1" "0"))
  (def detect-leaks
    (if (or (= sanitizer "asan") (= sanitizer "ubsan")) "0" "1"))
  (def asan-supp (string cwd "/sanitizers/asan.supp"))
  (def lsan-supp (string cwd "/sanitizers/lsan.supp"))
  (def ubsan-supp (string cwd "/sanitizers/ubsan.supp"))
  {"JSEC_SANITIZER" sanitizer
   "ASAN_OPTIONS" (string "detect_leaks=" detect-leaks
                          ":halt_on_error=" halt
                          ":print_stacktrace=1:fast_unwind_on_malloc=0"
                          ":exitcode=23"
                          ":suppressions=" asan-supp
                          ":log_path=" log-prefix)
   "LSAN_OPTIONS" (string "exitcode=23:print_suppressions=0"
                          ":suppressions=" lsan-supp
                          ":log_path=" log-prefix)
   "UBSAN_OPTIONS" (string "halt_on_error=" halt
                           ":print_stacktrace=1:exitcode=23"
                           ":suppressions=" ubsan-supp
                           ":log_path=" log-prefix)})

(defn- collect-san-logs [log-dir]
  (def logs @[])
  (when (os/stat log-dir)
    (each entry (sort (os/dir log-dir))
      (when (string/has-prefix? "san.log." entry)
        (def full (string log-dir "/" entry))
        (def st (os/stat full))
        (when (and st (> (st :size) 0))
          (array/push logs full)))))
  logs)

# Ensure a toolchain's module tree holds the test dependencies (assay, spork).
# jpm build/install do NOT install dependencies, and without them
# test/runner.janet cannot import assay and its workers cannot run - so the run
# would be meaningless. Install only when missing so a populated tree is left
# alone (idempotent, no network/clone on re-runs).
(defn- ensure-test-deps [jpm-bin modpath &opt build-env]
  (def missing (filter |(not (os/stat (string modpath "/" $)))
                       ["assay" "spork"]))
  (unless (empty? missing)
    (print "Installing test dependencies ("
           (string/join missing ", ") ")...")
    (flush)
    (run-or-fail [jpm-bin "deps"] build-env)))

# Build jsec and run the unit/regression/coverage suite (perf excluded) under a
# toolchain's janet/jpm with the project's default concurrency and suite
# selection (builds and tests itself). Shared by self-test (epoll),
# self-test-poll (poll), and self-test-{asan,lsan,ubsan,san} so all profiles
# stay directly comparable: same flags, same output shape, same exit semantics.
(defn- run-self-test-suite [janet-bin jpm-bin modpath &opt sanitizer prefix]
  (def build-env (san-build-env sanitizer))
  (ensure-test-deps jpm-bin modpath build-env)
  (print "Building jsec under the in-tree toolchain...")
  (flush)
  (run-or-fail [jpm-bin "build"] build-env)
  (print "Installing jsec under the in-tree toolchain...")
  (flush)
  (run-or-fail [jpm-bin "install"] build-env)
  (print "Running unit/regression/coverage under the in-tree toolchain...")
  (flush)
  (def runner-args [janet-bin "test/runner.janet"
                    "-f" "{unit,regression,coverage}"
                    "-j" "fiber:16,thread:6,subprocess:6"])
  (if (nil? sanitizer)
    (run-or-fail runner-args)
    (let [tc-prefix (or prefix (string ".work/" sanitizer))
          log-dir (string (os/cwd) "/" tc-prefix "/scratch/san-logs")
          log-prefix (string log-dir "/san.log")]
      (rmdir-recursive log-dir)
      (os/mkdir (string (os/cwd) "/" tc-prefix "/scratch"))
      (os/mkdir log-dir)
      (def code (os/execute runner-args :pe
                            (merge (os/environ)
                                   (san-test-env sanitizer log-prefix))))
      (ev/sleep 0.2)
      (def logs (collect-san-logs log-dir))
      (unless (empty? logs)
        (print "\n=== Sanitizer findings (" (length logs)
               " process log(s) in " log-dir ") ===")
        (each f logs
          (print "\n--- " f " ---")
          (prin (slurp f)))
        (flush)
        (os/exit (if (zero? code) 23 code)))
      (unless (zero? code)
        (print "command failed (exit " code "): "
               (string/join runner-args " "))
        (os/exit code)))))

(defn- run-sanitized-profile [sanitizer]
  (def prefix (string ".work/" sanitizer))
  (run-self-test-suite (string prefix "/bin/janet")
                       (string prefix "/bin/jpm")
                       (string prefix "/lib/janet")
                       sanitizer
                       prefix))

# Build the hermetic toolchain into .work/ (idempotent).
(phony "toolchain" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"]))

# Build the poll-backend hermetic toolchain into .work/poll/ (idempotent).
(phony "toolchain-poll" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"
                     "--ev-backend" "poll" "--toolchain" ".work/poll"]))

# Build sanitizer-instrumented hermetic toolchains into .work/<profile>/.
(phony "toolchain-asan" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"
                     "--sanitizer" "asan" "--toolchain" ".work/asan"]))

(phony "toolchain-lsan" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"
                     "--sanitizer" "lsan" "--toolchain" ".work/lsan"]))

(phony "toolchain-ubsan" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"
                     "--sanitizer" "ubsan" "--toolchain" ".work/ubsan"]))

(phony "toolchain-san" []
       (run-or-fail ["sh" "scripts/bootstrap-toolchain.sh"
                     "--sanitizer" "san" "--toolchain" ".work/san"]))

# Build jsec and run the suite under the default (epoll) in-tree toolchain.
(phony "self-test" ["toolchain"]
       (run-self-test-suite toolchain-janet toolchain-jpm toolchain-modpath))

# Explicit epoll alias for symmetry with self-test-poll (self-test already
# builds the default epoll toolchain).
(phony "self-test-epoll" ["self-test"])

# Build jsec and run the suite under the poll-backend in-tree toolchain.
(phony "self-test-poll" ["toolchain-poll"]
       (run-self-test-suite poll-toolchain-janet poll-toolchain-jpm
                            poll-toolchain-modpath))

# Build jsec and run the suite under sanitizer-instrumented toolchains.
(phony "self-test-asan" ["toolchain-asan"]
       (run-sanitized-profile "asan"))

(phony "self-test-lsan" ["toolchain-lsan"]
       (run-sanitized-profile "lsan"))

(phony "self-test-ubsan" ["toolchain-ubsan"]
       (run-sanitized-profile "ubsan"))

(phony "self-test-san" ["toolchain-san"]
       (run-sanitized-profile "san"))

# Wire test/sanitized and test-sanitized to the combined hermetic *SAN profile.
(phony "test/sanitized" ["self-test-san"])
(phony "test-sanitized" ["test/sanitized"])
