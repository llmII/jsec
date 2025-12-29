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
# Platform Detection
# ============================================================================

(def- windows? (= (os/which) :windows))
(def- macos? (= (os/which) :macos))
(def- dragonfly? (= (os/which) :dragonfly))

# ============================================================================
# Build Configuration (from environment)
# ============================================================================

(def- debug? (os/getenv "JSEC_DEBUG"))
(def- asan? (os/getenv "JSEC_ASAN"))
(def- ubsan? (os/getenv "JSEC_UBSAN"))
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
    windows?
    (when-let [vcpkg-root (os/getenv "VCPKG_ROOT")]
      (string vcpkg-root "/installed/x64-windows"))
    nil))

# ============================================================================
# Compiler Flags
# ============================================================================

# Standard flags - comprehensive warnings
# Note: Some flags omitted because janet.h macros trigger unavoidable warnings
(def- standard-cflags
  (if windows?
    ["/O2" "/W4" "/MD" "/wd4152" "/wd4702"]
    ["-std=c99" "-O2"
     "-Wall" "-Wextra" "-Wshadow" "-fno-common"
     "-Wuninitialized" "-Wpointer-arith" "-Wstrict-prototypes"
     "-Wfloat-equal" "-Wformat=2" "-Wimplicit-fallthrough"]))

# Sanitizer flags (Unix only)
(defn- build-sanitizer-flags []
  (if windows?
    @[]
    (let [sanitizers @[]]
      (when asan? (array/push sanitizers "address"))
      (when ubsan? (array/push sanitizers "undefined"))
      (if (empty? sanitizers)
        @[]
        @[(string "-fsanitize=" (string/join sanitizers ","))]))))

(def- debug-cflags
  (if windows?
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

(def- debug-lflags
  (if windows?
    @["/DEBUG"]
    (build-sanitizer-flags)))

(def- platform-cflags
  (cond
    windows?
    (if openssl-prefix
      [(string "/I" openssl-prefix "/include")]
      [])
    openssl-prefix
    [(string "-I" openssl-prefix "/include")]
    []))

(def- platform-lflags
  (cond
    windows?
    (if openssl-prefix
      [(string "/LIBPATH:" openssl-prefix "/lib") "libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"]
      ["libssl.lib" "libcrypto.lib" "ws2_32.lib" "mswsock.lib"])
    openssl-prefix
    [(string "-L" openssl-prefix "/lib") "-lssl" "-lcrypto"]
    ["-lssl" "-lcrypto"]))

(def- build-cflags
  (if debug?
    [;standard-cflags ;debug-cflags ;platform-cflags]
    [;standard-cflags ;platform-cflags]))

(def- build-lflags
  (if debug?
    [;platform-lflags ;debug-lflags]
    platform-lflags))

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
  :source [;(find-files-by-suffixes "src/jcrypto" [".c"]) ;jutils-shared-sources]
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
       (rmdir-recursive "build")
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

# Clang-tidy static analysis
(phony "tidy" []
       (print "Running clang-tidy static analysis...")
       (def include-args ["-I/usr/local/include/janet" "-I/usr/include/openssl" "-Isrc"])
       (def files (find-files-by-suffixes "src" [".c"]))
       (var failed false)
       (each src files
         (def proc (os/spawn ["clang-tidy" "--quiet" src "--" "-std=c99" ;include-args]
                             :p {:out :pipe :err :pipe}))
         (def stdout-content (ev/read (proc :out) :all))
         (def stderr-content (ev/read (proc :err) :all))
         (os/proc-wait proc)
         (def combined (string (or stdout-content "") (or stderr-content "")))
         # Filter noise and check for real issues
         (when (or (string/find "warning:" combined)
                   (string/find "error:" combined))
           (def lines (string/split "\n" combined))
           (def filtered (filter |(not (string/find "warnings generated" $)) lines))
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

# Test with sanitizers - placeholder (requires debug build)
(phony "test/sanitized" []
       (print "Note: Sanitizer testing requires JSEC_DEBUG=1 JSEC_ASAN=1 jpm build first.")
       (print "Then run: janet test/runner.janet")
       (print "This target is a no-op for now."))

# Leak check with valgrind - placeholder
(phony "test/valgrind" []
       (print "Note: Valgrind leak checking requires a debug build.")
       (print "Run manually: valgrind --leak-check=full janet test/runner.janet")
       (print "This target is a no-op for now."))
