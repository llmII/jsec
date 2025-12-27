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

# Standard compiler flags for quality - comprehensive warnings
# Note: Several flags omitted because janet.h macros (janet_stringv,
# janet_malloc, janet_string) trigger unavoidable warnings when expanded in
# our code:
#   -Wcast-qual: janet_string macro casts away const
#   -Wconversion/-Wsign-conversion: janet macros have size/sign conversions
#   -Wmissing-prototypes: JANET_MODULE_ENTRY generates functions without
#                         prototypes
#
# Production builds use -O2 for optimization. Debug builds use -Og instead.
(def- is-windows (= (os/which) :windows))

(def standard-cflags
  (if is-windows
    # /wd4152 - function/data pointer conversion (inherent to Janet cfun registration)
    # /wd4702 - unreachable code after janet_panic (MSVC doesn't know it's noreturn)
    ["/O2" "/W4" "/MD" "/wd4152" "/wd4702"]
    ["-std=c99" "-O2"
     "-Wall" "-Wextra" "-Wshadow" "-fno-common"
     "-Wuninitialized" "-Wpointer-arith" "-Wstrict-prototypes"
     "-Wfloat-equal" "-Wformat=2" "-Wimplicit-fallthrough"]))

# Debug build flags - sanitizers and debug symbols
# 
# Environment variables for build control:
#   JSEC_DEBUG           - Enable debug build (debug symbols, -Og)
#   JSEC_DEBUG_VERBOSE   - Enable verbose debug print statements
#   JSEC_ASAN            - Enable AddressSanitizer
#   JSEC_UBSAN           - Enable UndefinedBehaviorSanitizer  
#   JSEC_LSAN            - Enable LeakSanitizer
#                          (bundled with ASAN, use at runtime)
#
# Example build commands:
#   JSEC_DEBUG=1 jpm build                    # Debug symbols only
#   JSEC_DEBUG=1 JSEC_ASAN=1 jpm build       # Debug with ASan
#   JSEC_DEBUG=1 JSEC_UBSAN=1 jpm build      # Debug with UBSan
#   JSEC_DEBUG=1 JSEC_ASAN=1 JSEC_UBSAN=1 jpm build  # Both sanitizers
#
# At runtime, use the scripts in sanitizers/:
#   ./sanitizers/run-with-asan.sh janet script.janet   # Run with ASan
#   ./sanitizers/run-with-ubsan.sh janet script.janet  # Run with UBSan
#   ./sanitizers/run-with-lsan.sh janet script.janet   # Run with LSan 
#   ./sanitizers/run-with-asan.sh test                 # Test suite with ASan
#   ./sanitizers/run-with-ubsan.sh test                # Test suite with UBSan
#   ./sanitizers/run-with-lsan.sh test                 # Test suite with LSan
#
# Note: These scripts support both GCC and Clang compilers automatically.

(def- debug? (os/getenv "JSEC_DEBUG"))
(def- asan? (os/getenv "JSEC_ASAN"))
(def- ubsan? (os/getenv "JSEC_UBSAN"))
(def- verbose? (os/getenv "JSEC_DEBUG_VERBOSE"))

# Build sanitizer flags based on which are enabled (Unix only - MSVC doesn't support)
(defn- build-sanitizer-flags []
  (if is-windows
    @[]
    (let [sanitizers @[]]
      (when asan? (array/push sanitizers "address"))
      (when ubsan? (array/push sanitizers "undefined"))
      (if (empty? sanitizers)
        @[]
        @[(string "-fsanitize=" (string/join sanitizers ","))]))))

(def debug-extra-cflags
  (if is-windows
    @["/Zi" "/Od" "/DJSEC_DEBUG"]
    (let [base @["-g3" "-Og" "-fno-omit-frame-pointer"
                 "-fstack-protector-strong" "-DJSEC_DEBUG"]
          san-flags (build-sanitizer-flags)]
      (when (not (empty? san-flags))
        (array/push base ;san-flags)
        (array/push base "-fsanitize-recover=all"))
      (when verbose?
        (array/push base "-DJSEC_DEBUG_VERBOSE"))
      base)))

(def debug-lflags
  (if is-windows
    @["/DEBUG"]
    (build-sanitizer-flags)))

# macOS: Use Homebrew OpenSSL instead of outdated system LibreSSL 3.3.6
# Set OPENSSL_PREFIX env var to override the default Homebrew location
# DragonflyBSD: LibreSSL headers in /usr/local/include
# Windows: Use vcpkg OpenSSL (requires VCPKG_ROOT environment variable)
(def- macos? (= (os/which) :macos))
(def- dragonfly? (= (os/which) :dragonfly))
(def- openssl-prefix
  (cond
    macos?
    (or (os/getenv "OPENSSL_PREFIX")
        (if (os/stat "/opt/homebrew/opt/openssl@3")
          "/opt/homebrew/opt/openssl@3" # ARM Mac (M1/M2/M3)
          "/usr/local/opt/openssl@3")) # Intel Mac (x86_64)
    dragonfly? "/usr/local"
    is-windows
    (when-let [vcpkg-root (os/getenv "VCPKG_ROOT")]
      (string vcpkg-root "/installed/x64-windows"))
    nil))

(def platform-cflags
  (cond
    is-windows
    (if openssl-prefix
      [(string "/I" openssl-prefix "/include")]
      [])
    openssl-prefix
    [(string "-I" openssl-prefix "/include")]
    []))

(def platform-lflags
  (cond
    is-windows
    (if openssl-prefix
      [(string "/LIBPATH:" openssl-prefix "/lib") "libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"]
      ["libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"])
    openssl-prefix
    [(string "-L" openssl-prefix "/lib") "-lssl" "-lcrypto"]
    ["-lssl" "-lcrypto"]))

# Debug build support: set JSEC_DEBUG env var to enable
(def build-cflags
  (if debug?
    [;standard-cflags ;debug-extra-cflags ;platform-cflags]
    [;standard-cflags ;platform-cflags]))

(def build-lflags
  (if debug?
    [;platform-lflags ;debug-lflags]
    platform-lflags))

# Windows: Set jpm dynamic-cflags for proper DLL import handling
# JANET_DLL_IMPORT makes janet.h use dllimport for Janet symbols
(when is-windows
  (setdyn :dynamic-cflags @["/LD" "/DJANET_DLL_IMPORT"]))

# jsec/utils - Shared utilities and types (must be loaded first)
(declare-native
  :name "jsec/utils"
  :source ["src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"
           "src/jutils/module.c"]
  :cflags build-cflags
  :lflags build-lflags)

# jsec/tls-stream - TLS over TCP/Unix sockets
(declare-native
  :name "jsec/tls-stream"
  :source ["src/jtls/types.c"
           "src/jtls/bio.c"
           "src/jtls/state_machine.c"
           "src/jtls/context/alpn.c"
           "src/jtls/context/sni.c"
           "src/jtls/context/ocsp.c"
           "src/jtls/context/client.c"
           "src/jtls/context/server.c"
           "src/jtls/stream.c"
           "src/jtls/api/connect.c"
           "src/jtls/api/server.c"
           "src/jtls/api/io.c"
           "src/jtls/api/session.c"
           "src/jtls/api/context.c"
           "src/jtls/api/info.c"
           "src/jtls/module.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jtls/internal.h"
            "src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

# jsec/dtls-stream - DTLS over UDP sockets
(declare-native
  :name "jsec/dtls-stream"
  :source ["src/jdtls/address.c"
           "src/jdtls/session.c"
           "src/jdtls/state_machine.c"
           "src/jdtls/context.c"
           "src/jdtls/api/types.c"
           "src/jdtls/api/async.c"
           "src/jdtls/api/connect.c"
           "src/jdtls/api/upgrade.c"
           "src/jdtls/api/io.c"
           "src/jdtls/api/close.c"
           "src/jdtls/api/info.c"
           "src/jdtls/api/module.c"
           "src/jdtls/server.c"
           "src/jdtls/module.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jdtls/internal.h"
            "src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

# jsec/tls.janet - Unified API dispatching to tls-stream/dtls-stream
(declare-source
  :source ["jsec/tls.janet"]
  :prefix "jsec")

(declare-native
  :name "jsec/cert"
  :source ["src/jcert/jcert.c"
           "src/jcert/verify.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/bio"
  :source ["src/jbio.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

(declare-native
  :name "jsec/crypto"
  :source ["src/jcrypto/module.c"
           "src/jcrypto/digest.c"
           "src/jcrypto/keys.c"
           "src/jcrypto/sign.c"
           "src/jcrypto/hmac.c"
           "src/jcrypto/random.c"
           "src/jcrypto/base64.c"
           "src/jcrypto/kdf.c"
           "src/jcrypto/csr.c"
           "src/jcrypto/cms.c"
           "src/jcrypto/cipher.c"
           "src/jcrypto/rsa.c"
           "src/jcrypto/convert.c"
           "src/jcrypto/pkcs12.c"
           "src/jcrypto/ec.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jcrypto/internal.h"
            "src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

# jsec/ca - Certificate Authority operations
(declare-native
  :name "jsec/ca"
  :source ["src/jca/types.c"
           "src/jca/sign.c"
           "src/jca/crl.c"
           "src/jca/ocsp.c"
           "src/jca/module.c"
           "src/jutils/error.c"
           "src/jutils/janet_types.c"
           "src/jutils/cert_loading.c"
           "src/jutils/security.c"
           "src/jutils/context.c"]
  :headers ["src/jca/internal.h"
            "src/jutils.h"]
  :cflags build-cflags
  :lflags build-lflags)

# perf9-analyze - Performance test results analyzer
(declare-bin
  :main "bin/perf9-analyze.janet"
  :name "perf9-analyze")

# Cross-platform helper to recursively remove a directory
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

# Cross-platform helper to remove a file if it exists
(defn- rm-if-exists [path]
  "Remove a file if it exists"
  (when (os/stat path)
    (os/rm path)))

# Clean task
(phony "clean" []
       (print "Cleaning build artifacts...")
       (rmdir-recursive "build")
       (rmdir-recursive "jpm_tree")
       (rm-if-exists "README.md")
       (rm-if-exists "CHANGELOG.md")
       (rm-if-exists "valgrind-output.txt")
       (rm-if-exists "debug.log")
       (print "Clean complete."))

# Format C code with clang-format
(phony "format-c" []
       (print "Formatting C source files with clang-format...")
       (os/shell "find src -name '*.c' -o -name '*.h' | xargs clang-format -i"))

# Check C code formatting
(phony "check-format-c" []
       (print "Checking C code formatting...")
       (os/shell "find src -name '*.c' -o -name '*.h' | xargs clang-format --dry-run --Werror"))

# Format Janet code with janet-format
(phony "format-janet" []
       (print "Formatting Janet source files with janet-format...")
       (os/shell (string "find . -name '*.janet' "
                         "-not -path './jpm_tree/*' "
                         "-not -path './build/*' "
                         "| xargs janet-format -f")))

# Format org files - align tables
(phony "format-org" []
       (print "Aligning tables in org files...")
       (os/shell "find . -type f -name '*.org' -not -path '*/.*' -not -path './jpm_tree/*' -exec emacs --batch {} --eval \"(org-table-map-tables #'org-table-align t)\" -f save-buffer \\;"))

# Format all code
(phony "format" ["format-c" "format-janet" "format-org"]
       (print "All code formatted"))

# Release task - generate markdown from org files
(phony "release" ["clean" "format"]
       (print "Cleaning build artifacts...")
       (print "Formatting code...")
       (print "Generating markdown documentation from org files...")
       (os/shell "find . -type f -name '*.org' -not -path '*/.*' -not -path './jpm_tree/*' -exec emacs --batch --eval \"(require 'ox-md)\" {} -f org-md-export-to-markdown \\;"))

# Leak check with valgrind
(phony "leak-check" []
       (print "Running tests under valgrind for leak detection...")
       (print "Note: This may take significantly longer than normal test runs")
       (os/shell "JSEC_LEAK_CHECK=1 jpm test 2>&1 | tee valgrind-output.txt")
       (print "\nLeak check complete. Full output in valgrind-output.txt"))

# All source files for tidy checking
(def all-c-sources
  ["src/jutils/error.c"
   "src/jutils/janet_types.c"
   "src/jutils/cert_loading.c"
   "src/jutils/security.c"
   "src/jutils/context.c"
   "src/jutils/module.c"
   "src/jtls/types.c"
   "src/jtls/bio.c"
   "src/jtls/state_machine.c"
   "src/jtls/context/alpn.c"
   "src/jtls/context/sni.c"
   "src/jtls/context/ocsp.c"
   "src/jtls/context/client.c"
   "src/jtls/context/server.c"
   "src/jtls/stream.c"
   "src/jtls/api/connect.c"
   "src/jtls/api/server.c"
   "src/jtls/api/io.c"
   "src/jtls/api/session.c"
   "src/jtls/api/context.c"
   "src/jtls/api/info.c"
   "src/jtls/module.c"
   "src/jdtls/address.c"
   "src/jdtls/session.c"
   "src/jdtls/state_machine.c"
   "src/jdtls/context.c"
   "src/jdtls/api/types.c"
   "src/jdtls/api/async.c"
   "src/jdtls/api/connect.c"
   "src/jdtls/api/upgrade.c"
   "src/jdtls/api/io.c"
   "src/jdtls/api/close.c"
   "src/jdtls/api/info.c"
   "src/jdtls/api/module.c"
   "src/jdtls/server.c"
   "src/jdtls/module.c"
   "src/jcert/jcert.c"
   "src/jbio.c"
   "src/jcrypto/module.c"
   "src/jcrypto/digest.c"
   "src/jcrypto/keys.c"
   "src/jcrypto/sign.c"
   "src/jcrypto/hmac.c"
   "src/jcrypto/random.c"
   "src/jcrypto/base64.c"
   "src/jcrypto/kdf.c"
   "src/jcrypto/csr.c"
   "src/jcrypto/cms.c"
   "src/jcrypto/cipher.c"
   "src/jca/types.c"
   "src/jca/sign.c"
   "src/jca/crl.c"
   "src/jca/ocsp.c"
   "src/jca/module.c"])

# Helper to filter clang-tidy output noise
(defn- filter-tidy-output [output]
  "Filter out 'N warnings generated' noise from clang-tidy output"
  (when output
    (def lines (string/split "\n" output))
    (def filtered (filter |(not (string/find "warnings generated" $)) lines))
    (string/join filtered "\n")))

# Helper to check if output contains real issues
(defn- has-tidy-issues [output]
  "Check if clang-tidy output contains warnings or errors"
  (and output
       (not= output "")
       (or (string/find "warning:" output)
           (string/find "error:" output))))

# Clang-tidy check - static analysis and code quality
# --quiet suppresses warnings about suppressed diagnostics in non-user code
(phony "tidy" []
       (print "Running clang-tidy static analysis...")
       (print "This checks for bugs, security issues, and code quality.")
       (print "")
       (def include-args ["-I/usr/local/include/janet" "-I/usr/include/openssl" "-Isrc"])
       (var failed false)
       (each src all-c-sources
         (def proc (os/spawn ["clang-tidy" "--quiet" src "--" "-std=c99" ;include-args]
                             :p {:out :pipe :err :pipe}))
         (def stdout-content (ev/read (proc :out) :all))
         (def stderr-content (ev/read (proc :err) :all))
         (os/proc-wait proc)
         # Combine and filter output
         (def combined (string (or stdout-content "") (or stderr-content "")))
         (def filtered (filter-tidy-output combined))
         (when (has-tidy-issues filtered)
           (print filtered)
           (set failed true)))
       (if failed
         (do
           (print "\nclang-tidy found issues. Please fix them before committing.")
           (os/exit 1))
         (print "\nclang-tidy: All checks passed!")))

# Tidy with fixes applied automatically
(phony "tidy-fix" []
       (print "Running clang-tidy with automatic fixes...")
       (def include-args ["-I/usr/local/include/janet" "-I/usr/include/openssl" "-Isrc"])
       (each src all-c-sources
         (def proc (os/spawn ["clang-tidy" "--quiet" "-fix" src "--" "-std=c99" ;include-args]
                             :p {:out :pipe :err :pipe}))
         (ev/read (proc :out) :all)
         (ev/read (proc :err) :all)
         (os/proc-wait proc))
       (print "\nclang-tidy fixes applied. Review changes before committing."))

# Run tests with sanitizers enabled
# Requires a debug build: JSEC_DEBUG=1 jpm build && jpm install
(phony "test-sanitized" []
       (print "Running tests with AddressSanitizer and UndefinedBehaviorSanitizer...")
       (print "Make sure you have built with JSEC_DEBUG=1")
       (def project-dir (os/cwd))
       (def san-dir (string project-dir "/sanitizers"))
       (os/setenv "ASAN_OPTIONS"
                  (string "suppressions=" san-dir "/asan.supp"
                          ":detect_leaks=1:halt_on_error=0:print_stacktrace=1"))
       (os/setenv "UBSAN_OPTIONS"
                  (string "suppressions=" san-dir "/ubsan.supp"
                          ":halt_on_error=0:print_stacktrace=1"))
       (os/setenv "LSAN_OPTIONS"
                  (string "suppressions=" san-dir "/lsan.supp"))
       (os/execute ["janet" "test/runner.janet"] :p))
