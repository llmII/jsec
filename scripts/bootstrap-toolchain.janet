# ==============================================================================
# JSEC Hermetic In-Tree Toolchain Manager
# ==============================================================================
# Invoked by the minimal seed wrappers (scripts/bootstrap-toolchain.sh on POSIX
# and scripts/bootstrap-toolchain.bat on Windows) once a seed Janet binary is
# available in .work/seed/.
#
# Manages argument parsing, prerequisite & OpenSSL probes, git source resolution
# for Janet and jpm, building & installing Janet into the target toolchain
# prefix, bootstrapping jpm, installing launchers, extending default-config,
# and recording the TOOLCHAIN provenance stamp.
# ==============================================================================

(def default-janet-rev "8b6d56edae8c1eb5ae19b024087a065b6918b9ef")
(def default-jpm-rev "2430dec269f485473502bcdc2049ee332bc63908")

(def windows? (= (os/which) :windows))
(def sep (if windows? "\\" "/"))

(defn- log [fmt & args]
  (printf (string "==> " fmt) ;args)
  (flush))

(defn- info [fmt & args]
  (printf (string "    " fmt) ;args)
  (flush))

(defn- die [fmt & args]
  (eprintf (string "ERROR: " fmt) ;args)
  (eflush)
  (os/exit 1))

(defn- to-posix [p]
  (string/replace-all "\\" "/" p))

(defn- to-native [p]
  (if windows?
    (string/replace-all "/" "\\" p)
    (string/replace-all "\\" "/" p)))

(defn- join-path [& parts]
  (string/join (map to-native parts) sep))

(defn- dirname [p]
  (def norm (to-posix p))
  (var last-slash nil)
  (for i 0 (length norm)
    (when (= (get norm i) (chr "/"))
      (set last-slash i)))
  (if last-slash
    (to-native (if (zero? last-slash) "/" (string/slice norm 0 last-slash)))
    "."))

(defn- dir-exists? [p]
  (when-let [st (os/stat p)]
    (= (st :mode) :directory)))

(defn- file-exists? [p]
  (when-let [st (os/stat p)]
    (= (st :mode) :file)))

(defn- read-trimmed [p]
  (when (file-exists? p)
    (string/trim (slurp p))))

(defn- mkdir-p [p]
  (def norm (to-posix p))
  (def parts (string/split "/" norm))
  (var cur (if (string/has-prefix? "/" norm) "" nil))
  (each part parts
    (when (not (empty? part))
      (set cur (if cur (string cur "/" part) part))
      (when (not (and (= (length cur) 2) (= (get cur 1) (chr ":"))))
        (os/mkdir (to-native cur))))))

(defn- rm-rf [p]
  (when-let [st (os/stat p)]
    (if (= (st :mode) :directory)
      (do
        (each entry (os/dir p)
          (rm-rf (join-path p entry)))
        (try (os/rmdir p) ([_] nil)))
      (try (os/rm p) ([_] nil)))))

(defn- copy-file [src dst]
  (spit dst (slurp src)))

(defn- run-out [args &opt env]
  (def proc
    (if env
      (os/spawn args :pe (merge env {:out :pipe :err :pipe}))
      (os/spawn args :p {:out :pipe :err :pipe})))
  (def out @"")
  (def err @"")
  (ev/gather
    (when-let [b (:read (proc :out) :all)] (buffer/push out b))
    (when-let [b (:read (proc :err) :all)] (buffer/push err b)))
  (def code (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit code :out (string out) :err (string err)})

(defn- run-logged [log-path args &opt env]
  (def res (run-out args env))
  (spit log-path (string (res :out) (res :err)))
  (unless (zero? (res :exit))
    (eprint "--- output ---")
    (eprint (string/trimr (string (res :out) (res :err))))
    (eprint "--- end output ---")
    (eflush)
    (break false))
  true)

(defn- cmd-exists? [cmd]
  (if windows?
    (zero? ((run-out ["where" cmd]) :exit))
    (zero? ((run-out ["sh" "-c" (string "command -v " cmd " >/dev/null 2>&1")]) :exit))))

(defn- require-cmd [cmd desc]
  (unless (cmd-exists? cmd)
    (die "missing required command '%s' (%s). Install base build tools and retry." cmd desc)))

(defn- detect-native-ev-backend []
  (case (os/which)
    :windows "iocp"
    :linux "epoll"
    :freebsd "kqueue"
    :openbsd "kqueue"
    :netbsd "kqueue"
    :dragonfly "kqueue"
    :macos "kqueue"
    :illumos "evport"
    "native"))

(defn- is-sha? [s]
  (and (>= (length s) 7)
       (all |(or (and (>= $ (chr "0")) (<= $ (chr "9")))
                 (and (>= $ (chr "a")) (<= $ (chr "f")))
                 (and (>= $ (chr "A")) (<= $ (chr "F"))))
            s)))

(defn- ncpu []
  (if windows?
    (or (scan-number (or (os/getenv "NUMBER_OF_PROCESSORS") "1")) 1)
    (let [r (run-out ["sh" "-c" "nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1"])]
      (or (scan-number (string/trim (r :out))) 1))))

(defn- usage [janet-url jpm-url]
  (def script-name
    (if windows? "scripts\\bootstrap-toolchain.bat" "scripts/bootstrap-toolchain.sh"))
  (printf
    ``Usage: %s [OPTIONS]

Build a hermetic in-tree Janet toolchain into a .work/ prefix for jsec.
Idempotent and re-runnable. The host janet/jpm are NOT used for jsec builds.

Options:
  -h, --help                 Show this help and exit
  -f, --force                Rebuild the toolchain even if it already exists
  -c, --clean                Remove bin/, build/, include/, lib/, libexec/,
                             share/ under the prefix first, then rebuild
      --local                Offline only: require local source mirrors
      --janet-rev REV        Janet revision (default: %s)
      --janet-src DIR        Opt-in local Janet source mirror (or JANET_SRC)
      --jpm-rev REV          jpm revision (default: %s)
      --jpm-src DIR          Opt-in local jpm source mirror (or JPM_SRC)
      --toolchain DIR        Output prefix (default: .work)
      --ev-backend BACK      Event-loop backend (native/epoll/kqueue/evport/poll/iocp)
      --sanitizer MODE       Sanitizer profile on POSIX: none, asan, lsan, ubsan, san
      --openssl-prefix DIR   OpenSSL install prefix (or VCPKG_ROOT on Windows)

Environment:
  JANET_SRC   Opt-in local Janet source mirror
  JPM_SRC     Opt-in local jpm source mirror
  JANET_URL   Janet git URL (default: %s)
  JPM_URL     jpm git URL   (default: %s)
``
    script-name default-janet-rev default-jpm-rev janet-url jpm-url))

(defn- abspath [root p]
  (def norm (to-posix p))
  (if (or (string/has-prefix? "/" norm)
          (and (>= (length norm) 2) (= (get norm 1) (chr ":"))))
    (to-native norm)
    (join-path root p)))

(defn- resolve-repo [name url rev mirror-dir dest-dir marker-file local-only actions]
  (def rev-file (join-path dest-dir ".jsec-rev"))
  (when (and (file-exists? (join-path dest-dir marker-file))
             (= (read-trimmed rev-file) rev))
    (array/push actions (string/format "reused %s source at %s (rev %s)" name dest-dir rev))
    (break dest-dir))

  (rm-rf dest-dir)
  (mkdir-p dest-dir)

  (when (and mirror-dir (not (empty? mirror-dir)))
    (unless (dir-exists? mirror-dir)
      (die "%s mirror %s does not exist." name mirror-dir))
    (def cat-res (run-out ["git" "-C" mirror-dir "cat-file" "-e" (string rev "^{commit}")]))
    (if (zero? (cat-res :exit))
      (do
        (log "Extracting %s rev %s from local mirror %s..." name rev mirror-dir)
        (def cmd
          (if windows?
            ["cmd" "/c" (string "git -C \"" mirror-dir "\" archive \"" rev "\" | tar -xf - -C \"" dest-dir "\"")]
            ["sh" "-c" (string "git -C \"" mirror-dir "\" archive \"" rev "\" | ( cd \"" dest-dir "\" && tar xf - )")]))
        (def r (run-out cmd))
        (unless (zero? (r :exit))
          (die "failed to extract %s rev %s from %s: %s" name rev mirror-dir (r :err)))
        (spit rev-file (string rev "\n"))
        (array/push actions (string/format "checked out %s rev %s from %s" name rev mirror-dir))
        (break dest-dir))
      (when (and (not (os/stat (join-path mirror-dir ".git")))
                 (file-exists? (join-path mirror-dir marker-file)))
        (log "Copying local %s tree from %s..." name mirror-dir)
        (def cmd
          (if windows?
            ["robocopy" mirror-dir dest-dir "/E" "/XD" ".git" "build"]
            ["sh" "-c" (string "( cd \"" mirror-dir "\" && tar cf - --exclude=./.git --exclude=./build . ) | ( cd \"" dest-dir "\" && tar xf - )")]))
        (def r (run-out cmd))
        (when (if windows? (>= (r :exit) 8) (not (zero? (r :exit))))
          (die "failed to copy local %s tree from %s" name mirror-dir))
        (spit rev-file (string rev "\n"))
        (array/push actions (string/format "copied %s rev %s (as asserted) from %s" name rev mirror-dir))
        (break dest-dir)))
    (when local-only
      (die "--local requested but %s rev %s not found in mirror %s." name rev mirror-dir)))

  (when local-only
    (die "--local requested but no %s mirror given." name))

  (log "Cloning %s rev %s from %s..." name rev url)
  (if (is-sha? rev)
    (do
      (def r1 (run-out ["git" "clone" url dest-dir]))
      (unless (zero? (r1 :exit))
        (die "clone of %s failed: %s" url (r1 :err)))
      (def r2 (run-out ["git" "-C" dest-dir "checkout" "--quiet" rev]))
      (unless (zero? (r2 :exit))
        (die "%s rev %s not found in %s." name rev url)))
    (do
      (def r1 (run-out ["git" "clone" "--depth" "1" "--branch" rev url dest-dir]))
      (unless (zero? (r1 :exit))
        (die "clone of %s tag/branch %s failed." name rev))))
  (spit rev-file (string rev "\n"))
  (array/push actions (string/format "cloned %s rev %s from %s" name rev url))
  dest-dir)

(defn- query-reg-vcpkg-root []
  (def rq (run-out ["reg" "query" "HKCU\\Environment" "/v" "VCPKG_ROOT"]))
  (var res nil)
  (when (zero? (rq :exit))
    (each line (string/split "\n" (rq :out))
      (when-let [idx (string/find "REG_" line)]
        (def tail (string/slice line idx))
        (when-let [sp (string/find " " tail)]
          (set res (string/trim (string/slice tail sp)))))))
  res)

(defn- check-windows-ssl-dev [scratch-dir explicit-prefix]
  (def c-file (join-path scratch-dir ".ssl-probe.c"))
  (def o-file (join-path scratch-dir ".ssl-probe.obj"))
  (def e-file (join-path scratch-dir ".ssl-probe.exe"))
  (defer (do (rm-rf c-file) (rm-rf o-file) (rm-rf e-file))
    (spit c-file "#include <openssl/ssl.h>\nint main(void){ SSL_library_init(); return 0; }\n")
    (def prefixes @[])
    (when (and explicit-prefix (not (empty? explicit-prefix)))
      (array/push prefixes explicit-prefix))
    (when-let [env-p (os/getenv "OPENSSL_PREFIX")]
      (when (not (empty? env-p)) (array/push prefixes env-p)))
    (when-let [reg-v (query-reg-vcpkg-root)]
      (when (not (empty? reg-v))
        (array/push prefixes (join-path reg-v "installed" "x64-windows"))))
    (when-let [vcpkg (os/getenv "VCPKG_ROOT")]
      (when (not (empty? vcpkg))
        (array/push prefixes (join-path (string/trim vcpkg) "installed" "x64-windows"))))
    (when-let [up (os/getenv "USERPROFILE")]
      (array/push prefixes (join-path up "vcpkg" "installed" "x64-windows")))
    (array/push prefixes "C:\\vcpkg\\installed\\x64-windows")
    (var detected nil)
    (each p prefixes
      (when (and (nil? detected)
                 (file-exists? (join-path p "include" "openssl" "ssl.h")))
        (def r1 (run-out ["cl" "/nologo" "/c" (string "/I" (join-path p "include"))
                          (string "/Fo" o-file) c-file]))
        (when (zero? (r1 :exit))
          (def r2 (run-out ["link" "/nologo" (string "/OUT:" e-file) o-file
                            (string "/LIBPATH:" (join-path p "lib"))
                            "libssl.lib" "libcrypto.lib"]))
          (when (zero? (r2 :exit))
            (set detected p)))))
    (when detected (break detected))
    (def r1 (run-out ["cl" "/nologo" "/c" (string "/Fo" o-file) c-file]))
    (when (zero? (r1 :exit))
      (def r2 (run-out ["link" "/nologo" (string "/OUT:" e-file) o-file
                        "libssl.lib" "libcrypto.lib"]))
      (when (zero? (r2 :exit))
        (set detected "ambient INCLUDE/LIB")))
    detected))

(defn- check-posix-ssl-dev [cc scratch-dir explicit-prefix]
  (def c-file (join-path scratch-dir ".ssl-probe.c"))
  (def o-file (join-path scratch-dir ".ssl-probe"))
  (defer (do (rm-rf c-file) (rm-rf o-file))
    (def prefixes @[])
    (when (and explicit-prefix (not (empty? explicit-prefix)))
      (array/push prefixes explicit-prefix))
    (when-let [env-p (os/getenv "OPENSSL_PREFIX")]
      (when (not (empty? env-p)) (array/push prefixes env-p)))
    (array/push prefixes
                "/usr/local"
                "/opt/homebrew/opt/openssl@3"
                "/usr/local/opt/openssl@3"
                "/usr/openssl/3")
    (spit c-file "#include <openssl/ssl.h>\nint main(void){ SSL_library_init(); return 0; }\n")
    (when (zero? ((run-out [cc c-file "-o" o-file "-lssl" "-lcrypto"]) :exit))
      (break true))
    (var ok false)
    (each p prefixes
      (when (and (not ok) (dir-exists? (join-path p "include")))
        (each libsub ["lib" "lib/amd64"]
          (def ldir (join-path p libsub))
          (when (and (not ok) (dir-exists? ldir))
            (when (zero? ((run-out [cc (string "-I" (join-path p "include"))
                                    (string "-L" ldir) c-file "-o" o-file
                                    "-lssl" "-lcrypto"]) :exit))
              (set ok true))))))
    (when ok (break true))
    (spit c-file "#include <tls.h>\nint main(void){ return 0; }\n")
    (when (zero? ((run-out [cc c-file "-o" o-file "-ltls"]) :exit))
      (break true))
    (each p prefixes
      (when (and (not ok)
                 (dir-exists? (join-path p "include"))
                 (dir-exists? (join-path p "lib")))
        (when (zero? ((run-out [cc (string "-I" (join-path p "include"))
                                (string "-L" (join-path p "lib"))
                                c-file "-o" o-file "-ltls"]) :exit))
          (set ok true))))
    ok))

(defn- check-posix-sanitizer-dev [cc san-cflags scratch-dir]
  (if (empty? san-cflags)
    true
    (let [c-file (join-path scratch-dir ".san-probe.c")
          o-file (join-path scratch-dir ".san-probe")]
      (defer (do (rm-rf c-file) (rm-rf o-file))
        (spit c-file "int main(void){ return 0; }\n")
        (def args @[cc ;(string/split " " san-cflags) c-file "-o" o-file])
        (zero? ((run-out args) :exit))))))

(defn- update-jpm-config-file [cfg-path updates]
  (def env (dofile cfg-path))
  (def cfg (get-in env ['config :value]))
  (unless (table? cfg)
    (die "%s does not define a config table" cfg-path))
  (eachp [k v] updates
    (when (not (nil? v))
      (put cfg k v)))
  (spit cfg-path
        (string/format
          "# Autogenerated by generate-config in jpm/make-config.janet\n(def config %.99m)\n"
          cfg)))

(defn- parse-stamp [stamp-file]
  (def res @{})
  (when (file-exists? stamp-file)
    (each line (string/split "\n" (slurp stamp-file))
      (when-let [idx (string/find ":" line)]
        (def k (string/trim (string/slice line 0 idx)))
        (def v (string/trim (string/slice line (+ idx 1))))
        (put res k v))))
  res)

(defn- clean-posix-env [toolchain-bin sanitizer &opt extra]
  (def base
    @{"PATH" (string toolchain-bin ":" (or (os/getenv "PATH") "/usr/bin:/bin"))
      "HOME" (or (os/getenv "HOME") "/")})
  (when (not= sanitizer "none")
    (put base "ASAN_OPTIONS" "detect_leaks=0:halt_on_error=0")
    (put base "LSAN_OPTIONS" "detect_leaks=0")
    (put base "UBSAN_OPTIONS" "halt_on_error=0"))
  (when extra
    (merge-into base extra))
  base)

(defn- clean-windows-env [toolchain-bin &opt extra]
  (def base (table/clone (os/environ)))
  (each k ["JANET_PATH" "JANET_TREE" "JANET_WINDOWS_PREFIX"
           "JANET_JPM_CONFIG" "JPM_BOOTSTRAP_CONFIG"
           "JANET_HEADERPATH" "JANET_LIBPATH" "JANET_BINPATH"
           "JANET_MODPATH" "JANET_MANPATH" "PREFIX" "JANET_PREFIX"]
    (put base k nil))
  (def path-key (if (has-key? base "Path") "Path" "PATH"))
  (put base path-key (string toolchain-bin ";" (or (get base path-key) "")))
  (when extra
    (merge-into base extra))
  base)

(defn- format-utc-timestamp []
  (def d (os/date (os/time)))
  (string/format "%04d-%02d-%02dT%02d:%02d:%02dZ"
                 (d :year) (+ 1 (d :month)) (+ 1 (d :month-day))
                 (d :hours) (d :minutes) (d :seconds)))

(defn- build-janet-windows [jsrc toolchain-dir bin-dir lib-dir inc-dir mod-dir janet-exe log-path actions]
  (def prefix-file (join-path jsrc ".jsec-prefix"))
  (when (not= (read-trimmed prefix-file) toolchain-dir)
    (rm-rf (join-path jsrc "build")))
  (spit prefix-file (string toolchain-dir "\n"))
  (mkdir-p (join-path jsrc "build" "boot"))
  (mkdir-p (join-path jsrc "build" "c"))
  (mkdir-p bin-dir)
  (mkdir-p lib-dir)
  (mkdir-p mod-dir)
  (mkdir-p inc-dir)

  (def modpath-posix (to-posix mod-dir))
  (def bat-path (join-path jsrc "build" "jsec_build_win.bat"))
  (spit bat-path
        (string/format
          ``@echo off
setlocal EnableExtensions
cd /d "%s" || exit /b 1
set "J_CFLAGS=/nologo /Isrc\include /Isrc\conf /c /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /MD"
for %%%%F in (src\core\*.c) do (
    cl %%J_CFLAGS%% /DJANET_BOOTSTRAP /Fobuild\boot\%%%%~nF.obj "%%%%F" || exit /b 1
)
for %%%%F in (src\boot\*.c) do (
    cl %%J_CFLAGS%% /DJANET_BOOTSTRAP /Fobuild\boot\%%%%~nF.obj "%%%%F" || exit /b 1
)
link /nologo /OUT:build\janet_boot.exe build\boot\*.obj || exit /b 1
build\janet_boot.exe . JANET_PATH "%s" > build\c\janet.c || exit /b 1
cl %%J_CFLAGS%% /Fobuild\janet.obj build\c\janet.c || exit /b 1
cl %%J_CFLAGS%% /Fobuild\shell.obj src\mainclient\shell.c || exit /b 1
rc /nologo /fobuild\janet_win.res janet_win.rc || exit /b 1
link /nologo /OUT:"%s" /IMPLIB:"%s\janet.lib" build\janet.obj build\shell.obj build\janet_win.res || exit /b 1
lib /nologo /OUT:"%s\libjanet.lib" build\janet.obj || exit /b 1
"%s" tools\patch-header.janet src\include\janet.h src\conf\janetconf.h "%s\janet.h" || exit /b 1
copy /Y "%s\janet.h" "%s\include\janet.h" >nul || exit /b 1
copy /Y "%s\janet.lib" "%s\janet.lib" >nul || exit /b 1
exit /b 0
``
          jsrc modpath-posix janet-exe lib-dir lib-dir janet-exe inc-dir
          inc-dir toolchain-dir lib-dir inc-dir))
  (unless (run-logged log-path ["cmd" "/c" bat-path])
    (die "Janet Windows build failed (see output above)."))
  (array/push actions (string/format "built Janet -> %s" janet-exe)))

(defn- build-janet-posix [jsrc toolchain-dir mod-dir libexec-dir janet-real make-cmd cc ev-backend ev-defines sanitizer san-cflags log-path actions]
  (def ev-file (join-path jsrc ".jsec-ev"))
  (def san-file (join-path jsrc ".jsec-san"))
  (def pfx-file (join-path jsrc ".jsec-prefix"))
  (def last-ev (or (read-trimmed ev-file) ""))
  (def last-san (or (read-trimmed san-file) "none"))
  (def last-pfx (or (read-trimmed pfx-file) ""))
  (when (and (or (not= last-ev ev-backend)
                 (not= last-san sanitizer)
                 (not= last-pfx toolchain-dir))
             (dir-exists? (join-path jsrc "build")))
    (rm-rf (join-path jsrc "build"))
    (array/push actions
                (string/format "cleared in-tree Janet build output (was %s/%s, now %s/%s)"
                               (if (empty? last-ev) "unset" last-ev) last-san ev-backend sanitizer)))
  (spit ev-file (string ev-backend "\n"))
  (spit san-file (string sanitizer "\n"))
  (spit pfx-file (string toolchain-dir "\n"))

  (def make-base @[make-cmd "-C" jsrc (string "CC=" cc)
                   (string "PREFIX=" toolchain-dir)
                   (string "JANET_PATH=" mod-dir)])
  (when (or (not (empty? san-cflags)) (not (empty? ev-defines)))
    (def base-cf (or (os/getenv "CFLAGS") (if (empty? san-cflags) "-O2 -g" "")))
    (def parts (filter |(not (empty? $)) [base-cf san-cflags ev-defines]))
    (array/push make-base (string "CFLAGS=" (string/join parts " "))))

  (def build-env
    (if (not (empty? san-cflags))
      (merge (os/environ)
             {"ASAN_OPTIONS" "detect_leaks=0:halt_on_error=0"
              "LSAN_OPTIONS" "detect_leaks=0"
              "UBSAN_OPTIONS" "halt_on_error=0"})
      nil))

  (def jobs-arg (string "-j" (ncpu)))
  (unless (run-logged log-path [;make-base jobs-arg] build-env)
    (die "Janet build failed (see output above)."))
  (unless (run-logged log-path [;make-base "install" "LDCONFIG=true"] build-env)
    (die "Janet install into %s failed." toolchain-dir))

  (def installed-bin (join-path toolchain-dir "bin" "janet"))
  (def built-bin (join-path jsrc "build" "janet"))
  (when (and (not= sanitizer "none") (file-exists? built-bin))
    (copy-file built-bin installed-bin)
    (run-out ["chmod" "+x" installed-bin])
    (array/push actions (string/format "preserved unstripped debug symbols in Janet binary (%s)" sanitizer)))

  (unless (file-exists? installed-bin)
    (die "Janet binary missing after install: %s" installed-bin))

  (log "Relocating the real Janet binary to libexec/...")
  (mkdir-p libexec-dir)
  (os/rename installed-bin janet-real)
  (run-out ["chmod" "+x" janet-real])
  (array/push actions (string/format "relocated janet binary -> %s" janet-real)))

(defn main [& args]
  (def script-file (abspath (os/cwd) (or (dyn :current-file) (get args 0))))
  (def script-dir (dirname script-file))
  (def root-dir (dirname script-dir))
  (def work-dir (join-path root-dir ".work"))
  (def src-dir (join-path work-dir "src"))
  (def scratch-dir (join-path work-dir "scratch"))

  (def janet-url (or (os/getenv "JANET_URL") "https://github.com/janet-lang/janet.git"))
  (def jpm-url (or (os/getenv "JPM_URL") "https://github.com/janet-lang/jpm.git"))
  (def native-ev (detect-native-ev-backend))

  (var janet-rev default-janet-rev)
  (var jpm-rev default-jpm-rev)
  (var janet-src (or (os/getenv "JANET_SRC") ""))
  (var jpm-src (or (os/getenv "JPM_SRC") ""))
  (var toolchain-dir work-dir)
  (var ev-backend native-ev)
  (var sanitizer "none")
  (var openssl-prefix (or (os/getenv "OPENSSL_PREFIX") ""))
  (var force false)
  (var clean false)
  (var local-only false)

  (def cli-args (tuple/slice args 1))
  (var i 0)
  (defn next-val [opt]
    (++ i)
    (when (>= i (length cli-args))
      (die "%s needs a value" opt))
    (get cli-args i))

  (while (< i (length cli-args))
    (def a (get cli-args i))
    (cond
      (or (= a "-h") (= a "--help"))
      (do (usage janet-url jpm-url) (os/exit 0))

      (or (= a "-f") (= a "--force"))
      (set force true)

      (or (= a "-c") (= a "--clean"))
      (set clean true)

      (= a "--local")
      (set local-only true)

      (= a "--janet-rev") (set janet-rev (next-val a))
      (string/has-prefix? "--janet-rev=" a) (set janet-rev (string/slice a 12))

      (= a "--janet-src") (set janet-src (next-val a))
      (string/has-prefix? "--janet-src=" a) (set janet-src (string/slice a 12))

      (= a "--jpm-rev") (set jpm-rev (next-val a))
      (string/has-prefix? "--jpm-rev=" a) (set jpm-rev (string/slice a 10))

      (= a "--jpm-src") (set jpm-src (next-val a))
      (string/has-prefix? "--jpm-src=" a) (set jpm-src (string/slice a 10))

      (= a "--toolchain") (set toolchain-dir (next-val a))
      (string/has-prefix? "--toolchain=" a) (set toolchain-dir (string/slice a 12))

      (= a "--ev-backend") (set ev-backend (next-val a))
      (string/has-prefix? "--ev-backend=" a) (set ev-backend (string/slice a 13))

      (= a "--sanitizer") (set sanitizer (next-val a))
      (string/has-prefix? "--sanitizer=" a) (set sanitizer (string/slice a 12))

      (= a "--openssl-prefix") (set openssl-prefix (next-val a))
      (string/has-prefix? "--openssl-prefix=" a) (set openssl-prefix (string/slice a 17))

      (die "unknown option: %s (try --help)" a))
    (++ i))

  (var ev-defines "")
  (if windows?
    (set ev-backend "iocp")
    (case ev-backend
      "native" (set ev-backend native-ev)
      "epoll" (set ev-backend native-ev)
      "kqueue" (set ev-backend native-ev)
      "evport" (set ev-backend native-ev)
      "poll" (set ev-defines "-DJANET_EV_NO_EPOLL -DJANET_EV_NO_KQUEUE")
      (die "--ev-backend must be poll, native, epoll, kqueue, or evport (got: %s)" ev-backend)))

  (def san-base "-O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  (var san-cflags "")
  (case sanitizer
    "none" (set san-cflags "")
    "asan" (set san-cflags (string san-base " -fsanitize=address -fsanitize-recover=address"))
    "lsan" (set san-cflags (string san-base " -fsanitize=leak"))
    "ubsan" (set san-cflags (string san-base " -fsanitize=undefined -fsanitize-recover=undefined"))
    "san" (set san-cflags (string san-base " -fsanitize=address,undefined -fsanitize-recover=address,undefined"))
    "asan+ubsan"
    (do
      (set sanitizer "san")
      (set san-cflags (string san-base " -fsanitize=address,undefined -fsanitize-recover=address,undefined")))
    (die "--sanitizer must be none, asan, lsan, ubsan, or san (got: %s)" sanitizer))

  (set toolchain-dir (abspath root-dir toolchain-dir))
  (def bin-dir (join-path toolchain-dir "bin"))
  (def lib-dir (join-path toolchain-dir "lib"))
  (def libexec-dir (join-path toolchain-dir "libexec"))
  (def mod-dir (join-path lib-dir "janet"))
  (def inc-dir (join-path toolchain-dir "include" "janet"))
  (def build-dir (join-path toolchain-dir "build"))
  (def stamp-file (join-path toolchain-dir "TOOLCHAIN"))

  (def janet-bin (join-path bin-dir (if windows? "janet.bat" "janet")))
  (def jpm-bin (join-path bin-dir (if windows? "jpm.bat" "jpm")))
  (def janet-real (if windows? (join-path bin-dir "janet.exe") (join-path libexec-dir "janet")))
  (def jpm-real (join-path libexec-dir "jpm"))
  (def launcher-janet (join-path script-dir (if windows? "toolchain-launcher-janet.bat" "toolchain-launcher-janet.sh")))
  (def launcher-jpm (join-path script-dir (if windows? "toolchain-launcher-jpm.bat" "toolchain-launcher-jpm.sh")))

  (log "Checking host prerequisites...")
  (mkdir-p scratch-dir)

  (var cc (or (os/getenv "CC") ""))
  (var make-cmd (or (os/getenv "MAKE") ""))

  (if windows?
    (do
      (when (nil? (os/getenv "VCPKG_ROOT"))
        (def rq (run-out ["reg" "query" "HKCU\\Environment" "/v" "VCPKG_ROOT"]))
        (when (zero? (rq :exit))
          (each line (string/split "\n" (rq :out))
            (when-let [idx (string/find "REG_" line)]
              (def tail (string/slice line idx))
              (when-let [sp (string/find " " tail)]
                (os/setenv "VCPKG_ROOT" (string/trim (string/slice tail sp))))))))
      (each c ["cl.exe" "link.exe" "lib.exe" "rc.exe" "git.exe" "tar.exe"]
        (require-cmd c "MSVC / Git build prerequisite"))
      (def detected-ossl (check-windows-ssl-dev scratch-dir openssl-prefix))
      (unless detected-ossl
        (die "OpenSSL headers and import libs (openssl/ssl.h, libssl.lib, libcrypto.lib) not found. Set VCPKG_ROOT or OPENSSL_PREFIX."))
      (info "C compiler: cl.exe")
      (info "OpenSSL:    ok (%s)" detected-ossl))
    (do
      (when (empty? cc)
        (set cc (cond (cmd-exists? "cc") "cc"
                  (cmd-exists? "gcc") "gcc"
                  (cmd-exists? "clang") "clang"
                  "cc")))
      (when (empty? make-cmd)
        (set make-cmd (if (cmd-exists? "gmake") "gmake" "make")))
      (require-cmd cc "C compiler")
      (require-cmd "ar" "static archiver")
      (require-cmd make-cmd "GNU Make build driver for Janet")
      (require-cmd "git" "source checkout")
      (unless (check-posix-ssl-dev cc scratch-dir openssl-prefix)
        (die "OpenSSL/LibreSSL dev headers and libs not found. Install openssl (or libretls) development packages and retry."))
      (unless (check-posix-sanitizer-dev cc san-cflags scratch-dir)
        (die "C compiler (%s) cannot compile/link with --sanitizer %s (%s)." cc sanitizer san-cflags))
      (info "C compiler: %s" cc)
      (info "Make driver: %s" make-cmd)
      (info "SSL dev:    ok (openssl/libretls)")))

  (info "Janet rev:  %s" janet-rev)
  (info "jpm rev:    %s" jpm-rev)
  (info "ev backend: %s" ev-backend)
  (info "sanitizer:  %s" sanitizer)

  (when clean
    (log "Cleaning %s..." toolchain-dir)
    (each sub ["bin" "build" "include" "lib" "libexec" "share"]
      (rm-rf (join-path toolchain-dir sub)))
    (rm-rf stamp-file))

  (each d [src-dir toolchain-dir scratch-dir build-dir]
    (mkdir-p d))

  (defn have-toolchain? []
    (and (file-exists? janet-real)
         (file-exists? jpm-real)
         (file-exists? janet-bin)
         (file-exists? jpm-bin)
         (file-exists? (join-path inc-dir "janet.h"))
         (file-exists? (join-path mod-dir "jpm" "default-config.janet"))))

  (def actions @[])

  (defn print-summary []
    (log "Hermetic toolchain ready at %s" toolchain-dir)
    (def env (if windows? (clean-windows-env bin-dir) (clean-posix-env bin-dir sanitizer)))
    (def v-res (run-out [janet-real "-e" "(printf \"%s|%s\" janet/version (or (dyn :syspath) \"\"))"] env))
    (def parts (string/split "|" (string/trim (v-res :out))))
    (def jver (or (get parts 0) "unknown"))
    (def jsys (or (get parts 1) ""))
    (info "janet:      %s  (syspath: %s)" jver jsys)
    (info "jpm:        %s" jpm-bin)
    (info "ev-backend: %s" ev-backend)
    (info "sanitizer:  %s" sanitizer)
    (info "libexec:    %s , %s" janet-real jpm-real)
    (info "headerpath: %s" inc-dir)
    (info "modpath:    %s" mod-dir)
    (info "buildpath:  %s" build-dir)
    (unless (empty? actions)
      (log "Actions taken:")
      (each a actions (info "- %s" a)))
    (log "Build/test with %s and %s (never the host janet/jpm)." janet-bin jpm-bin))

  (when (and (not force) (have-toolchain?))
    (def st (parse-stamp stamp-file))
    (def st-rev (get st "janet-rev"))
    (def st-jpm (or (get st "jpm-rev") jpm-rev))
    (def st-ev (or (get st "ev-backend") native-ev))
    (def st-san (or (get st "sanitizer") "none"))
    (if (and (= st-rev janet-rev)
             (= st-jpm jpm-rev)
             (= st-ev ev-backend)
             (= st-san sanitizer))
      (do
        (log "Toolchain already present (Janet rev %s, jpm rev %s, ev-backend %s, sanitizer %s) at %s; nothing to do."
             janet-rev jpm-rev ev-backend sanitizer toolchain-dir)
        (info "Use --force to rebuild or --clean to start over.")
        (print-summary)
        (os/exit 0))
      (log "Toolchain present for rev %s / ev-backend %s / sanitizer %s; requested %s / %s / %s; rebuilding."
           (or st-rev "unknown") st-ev st-san janet-rev ev-backend sanitizer)))

  (rm-rf stamp-file)

  (def jsrc
    (resolve-repo "Janet" janet-url janet-rev janet-src
                  (join-path src-dir "janet")
                  (if windows? "build_win.bat" "Makefile")
                  local-only actions))

  (def build-log (join-path scratch-dir ".last-janet-build.log"))
  (log "Building Janet rev %s (ev-backend: %s, sanitizer: %s) into %s..."
       janet-rev ev-backend sanitizer toolchain-dir)
  (if windows?
    (build-janet-windows jsrc toolchain-dir bin-dir lib-dir inc-dir mod-dir janet-real build-log actions)
    (build-janet-posix jsrc toolchain-dir mod-dir libexec-dir janet-real make-cmd cc ev-backend ev-defines sanitizer san-cflags build-log actions))

  (log "Installing the janet launcher into bin/...")
  (unless (file-exists? launcher-janet)
    (die "launcher source missing: %s" launcher-janet))
  (mkdir-p bin-dir)
  (copy-file launcher-janet janet-bin)
  (unless windows?
    (run-out ["chmod" "+x" janet-bin]))
  (array/push actions (string/format "installed launcher -> %s" janet-bin))

  (def psrc
    (resolve-repo "jpm" jpm-url jpm-rev jpm-src
                  (join-path src-dir "jpm")
                  "bootstrap.janet"
                  local-only actions))

  (log "Bootstrapping jpm rev %s against in-tree Janet..." jpm-rev)
  (def jpm-log (join-path scratch-dir ".last-jpm-build.log"))
  (if windows?
    (do
      (def bcfg-path (to-posix (join-path scratch-dir ".bootstrap-config.janet")))
      (def gen-code
        (string/format
          "(import ./jpm/make-config) (spit %q (make-config/generate-config \"\"))"
          bcfg-path))
      (def old-cwd (os/cwd))
      (os/cd psrc)
      (def wenv
        (clean-windows-env bin-dir
                           {"PREFIX" (to-posix toolchain-dir)
                            "JANET_PREFIX" (to-posix toolchain-dir)
                            "JANET_BINPATH" (to-posix bin-dir)
                            "JANET_LIBPATH" (to-posix lib-dir)
                            "JANET_HEADERPATH" (to-posix inc-dir)
                            "JANET_MODPATH" (to-posix mod-dir)
                            "JANET_MANPATH" (string (to-posix toolchain-dir) "/share/man/man1")
                            "JANET_STRICT_MODPATH" "true"}))
      (unless (run-logged jpm-log [janet-real "-e" gen-code] wenv)
        (os/cd old-cwd)
        (die "jpm make-config failed (see output above)."))
      (update-jpm-config-file
        (to-native bcfg-path)
        {:auto-shebang false
         :janet (to-posix janet-real)
         :buildpath (to-posix build-dir)
         :headerpath (to-posix inc-dir)
         :libpath (to-posix lib-dir)
         :modpath (to-posix mod-dir)
         :binpath (to-posix bin-dir)
         :janet-importlib (string (to-posix lib-dir) "/janet.lib")})
      (unless (run-logged jpm-log [janet-real "bootstrap.janet" bcfg-path] wenv)
        (os/cd old-cwd)
        (die "jpm bootstrap failed (see output above)."))
      (os/cd old-cwd))
    (do
      (def old-cwd (os/cwd))
      (os/cd psrc)
      (def penv
        (clean-posix-env bin-dir sanitizer
                         {"PREFIX" toolchain-dir
                          "JANET_STRICT_MODPATH" "true"}))
      (unless (run-logged jpm-log [janet-real "bootstrap.janet"] penv)
        (os/cd old-cwd)
        (die "jpm bootstrap failed (see output above)."))
      (os/cd old-cwd)))

  (def generated-jpm (join-path bin-dir "jpm"))
  (unless (file-exists? generated-jpm)
    (die "jpm script missing after bootstrap: %s" generated-jpm))
  (def def-cfg-path (join-path mod-dir "jpm" "default-config.janet"))
  (unless (file-exists? def-cfg-path)
    (die "jpm default-config.janet missing under %s" def-cfg-path))
  (array/push actions (string/format "bootstrapped jpm -> %s" jpm-real))

  (log "Relocating jpm's generated script to libexec/...")
  (mkdir-p libexec-dir)
  (rm-rf jpm-real)
  (os/rename generated-jpm jpm-real)
  (unless windows?
    (run-out ["chmod" "-x" jpm-real]))
  (array/push actions (string/format "relocated jpm script -> %s" jpm-real))

  (log "Installing the jpm launcher into bin/...")
  (unless (file-exists? launcher-jpm)
    (die "launcher source missing: %s" launcher-jpm))
  (copy-file launcher-jpm jpm-bin)
  (unless windows?
    (run-out ["chmod" "+x" jpm-bin]))
  (array/push actions (string/format "installed launcher -> %s" jpm-bin))

  (if windows?
    (update-jpm-config-file
      def-cfg-path
      {:auto-shebang false
       :janet (to-posix janet-real)
       :buildpath (to-posix build-dir)
       :headerpath (to-posix inc-dir)
       :libpath (to-posix lib-dir)
       :modpath (to-posix mod-dir)
       :binpath (to-posix bin-dir)
       :janet-importlib (string (to-posix lib-dir) "/janet.lib")})
    (update-jpm-config-file
      def-cfg-path
      {:janet janet-bin
       :buildpath build-dir
       :cc (when (and (not (empty? cc)) (not= cc "cc")) cc)
       :cc-link (when (and (not (empty? cc)) (not= cc "cc")) cc)}))
  (array/push actions "extended jpm default-config.janet with :janet and :buildpath")

  (def env (if windows? (clean-windows-env bin-dir) (clean-posix-env bin-dir sanitizer)))
  (def v-res (run-out [janet-real "-e" "(print janet/version)"] env))
  (def built-ver (if (zero? (v-res :exit)) (string/trim (v-res :out)) "unknown"))
  (spit stamp-file
        (string/format
          "janet-rev: %s\njanet-version: %s\njpm-rev: %s\nev-backend: %s\nsanitizer: %s\ntoolchain-prefix: %s\nbuilt-at: %s\n"
          janet-rev built-ver jpm-rev ev-backend sanitizer
          (if windows? (to-posix toolchain-dir) toolchain-dir)
          (format-utc-timestamp)))

  (print-summary))
