#!/bin/sh
# Portable POSIX sh (no bash-isms: BSD/Solaris /bin/sh safe).
set -eu

# ==============================================================================
# JSEC Hermetic In-Tree Toolchain Bootstrap
# ==============================================================================
# Builds a self-contained Janet toolchain into a .work/ prefix so jsec can build
# and test itself against a chosen Janet revision, with no reliance on the host
# janet/jpm. This removes the defect class where a host jpm's baked headerpath
# points at a Janet different from the host interpreter, producing
# `config mismatch - host A vs module B` at module load time.
#
# Hermeticity is established by the entry-point launchers and inherited by the
# whole process tree. The committed launchers
# (scripts/toolchain-launcher-{janet,jpm}.sh) self-locate via $0, unset every
# JANET_* path override, prepend <prefix>/bin to PATH, and exec the matching
# real binary under <prefix>/libexec/. Nothing else needs to know where
# anything lives: janet is self-describing (its baked (dyn :syspath) is
# <prefix>/lib/janet) and jpm's default-config.janet holds absolute paths.
#
# The Janet revision is a parameter (tag, branch, or githash) so one script can
# drive a per-version matrix. Each rev can build into its own toolchain prefix
# via --toolchain, so multiple Janets coexist under .work/.
#
# Layout produced (default prefix, .work/):
#   bin/janet        our self-locating POSIX-sh launcher (entry point)
#   bin/jpm          our self-locating POSIX-sh launcher (entry point)
#   libexec/janet    the real built janet binary (private)
#   libexec/jpm      jpm's own generated script (private, non-executable)
#   include/janet/janet.h
#   lib/libjanet.a  (and shared lib)
#   lib/janet/      (installed modules, incl. jpm/)
#   build/          jpm :buildpath (project build output; lives under the
#                   --toolchain prefix, so each Janet version is isolated)
#
# The in-tree jpm is bootstrapped AGAINST the in-tree janet with PREFIX and
# JANET_STRICT_MODPATH pointing it into <prefix>, so its baked
# default-config.janet resolves :headerpath/:modpath/:binpath/:libpath inside
# the toolchain. That generated config is then extended (structurally, never
# string-patched) with the two keys jpm's generator cannot express, :janet and
# :buildpath.
#
# Windows is a special case handled separately (see build-windows.bat / MSVC +
# vcpkg, or MSYS2 MinGW); this script targets POSIX hosts (Linux, the BSDs,
# macOS, Solaris/Illumos, Chimera).
# ==============================================================================

# --- Default pinned revisions -------------------------------------------------
# This increment pins one Janet. The rev is a githash so it is exact and
# reproducible; pass --janet-rev <tag|branch|githash> to build a different Janet
# (e.g. --janet-rev 8b6d56ed or --janet-rev 7810724e) for the version matrix.
DEFAULT_JANET_REV="8b6d56edae8c1eb5ae19b024087a065b6918b9ef"  # janet 1.41.1
DEFAULT_JPM_REV="2430dec269f485473502bcdc2049ee332bc63908"    # jpm 1.2.1

JANET_URL="${JANET_URL:-https://github.com/janet-lang/janet.git}"
JPM_URL="${JPM_URL:-https://github.com/janet-lang/jpm.git}"

# Local source mirrors are OPT-IN ONLY (--janet-src/--jpm-src or JANET_SRC/
# JPM_SRC); there are no built-in mirror paths and none are probed by default.
# With no opt-in, both sources are fetched at --janet-rev/--jpm-rev from
# JANET_URL/JPM_URL into .work/src/, so the bootstrap never consults jpm/janet
# trees or binaries on the host system.
JANET_SRC="${JANET_SRC:-}"
JPM_SRC="${JPM_SRC:-}"

# --- Locations (SCRIPT_DIR via $0; POSIX-safe) --------------------------------
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(dirname -- "$SCRIPT_DIR")
WORK_DIR="$ROOT_DIR/.work"
SRC_DIR="$WORK_DIR/src"
TOOLCHAIN_DIR="$WORK_DIR"               # overridable via --toolchain
SCRATCH_DIR="$WORK_DIR/scratch"

LAUNCHER_JANET="$SCRIPT_DIR/toolchain-launcher-janet.sh"
LAUNCHER_JPM="$SCRIPT_DIR/toolchain-launcher-jpm.sh"

JANET_REV="$DEFAULT_JANET_REV"
JPM_REV="$DEFAULT_JPM_REV"
FORCE=0
CLEAN=0
LOCAL_ONLY=0
ACTIONS=""
RESOLVED_SRC=""

# --- Helpers -------------------------------------------------------------------
log()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { ACTIONS="$ACTIONS    - $*
"; }

usage() {
    cat <<EOF
Usage: scripts/bootstrap-toolchain.sh [OPTIONS]

Build a hermetic in-tree Janet toolchain into a .work/ prefix for jsec.
Idempotent and re-runnable. The host janet/jpm are NOT used for jsec builds.

Hermeticity is established by the entry-point launchers copied into
<prefix>/bin/: they self-locate, clear the JANET_* path overrides, put their
own bin/ first on PATH, and exec the real binaries under <prefix>/libexec/.

The Janet revision is selectable (tag, branch, or githash) so one script can
drive a per-version test matrix. Pair --janet-rev with --toolchain to keep
multiple Janet toolchains side by side under .work/.

Options:
  -h, --help             Show this help and exit
  -f, --force            Rebuild the toolchain even if it already exists
  -c, --clean            Remove the toolchain under the prefix first (bin/,
                         build/, include/, lib/, libexec/, share/), then
                         rebuild. Keeps src/ and scratch/
      --local            Offline only: never clone; the opted-in local mirrors
                         must supply the requested revs (error otherwise)
      --janet-rev REV    Janet revision to build (tag/branch/githash).
                         Default: ${DEFAULT_JANET_REV} (janet 1.41.1)
      --janet-src DIR    Opt-in local Janet source mirror (or set JANET_SRC).
                         Off by default; with no mirror the rev is self-fetched
                         from JANET_URL into .work/src/janet/
      --jpm-rev REV      jpm revision to build (tag/branch/githash).
                         Default: ${DEFAULT_JPM_REV} (jpm 1.2.1)
      --jpm-src DIR      Opt-in local jpm source mirror (or set JPM_SRC).
                         Off by default; with no mirror the rev is self-fetched
                         from JPM_URL into .work/src/jpm/
      --toolchain DIR    Output prefix. Default: .work, so the toolchain
                         lives directly in .work/{bin,build,include,lib,
                         libexec,share} (e.g. .work/1.41.1 for a matrix)

Environment:
  JANET_SRC   Opt-in local Janet source mirror (default: empty, never probed;
              see --janet-src)
  JPM_SRC     Opt-in local jpm source mirror (default: empty, never probed;
              see --jpm-src)
  JANET_URL   Janet git URL for self-fetch   (default: ${JANET_URL})
  JPM_URL     jpm git URL for self-fetch     (default: ${JPM_URL})
  CC          C compiler (default: cc)

Output under --toolchain:
  bin/janet, bin/jpm       self-locating POSIX-sh launchers (entry points)
  libexec/janet            the real built janet binary (private)
  libexec/jpm              jpm's own generated script (private; only run as a
                           script argument to libexec/janet, never executed)
  include/janet/janet.h
  lib/libjanet.a
  lib/janet/               (installed modules)
  build/                   jpm :buildpath (project build output)

Provenance is recorded in <prefix>/TOOLCHAIN (revisions + built Janet version).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)      usage; exit 0 ;;
        -f|--force)     FORCE=1; shift ;;
        -c|--clean)     CLEAN=1; shift ;;
        --local)        LOCAL_ONLY=1; shift ;;
        --janet-rev)    [ $# -ge 2 ] || die "--janet-rev needs a value"; JANET_REV=$2; shift 2 ;;
        --janet-rev=*)  JANET_REV=${1#*=}; shift ;;
        --janet-src)    [ $# -ge 2 ] || die "--janet-src needs a value"; JANET_SRC=$2; shift 2 ;;
        --janet-src=*)  JANET_SRC=${1#*=}; shift ;;
        --jpm-rev)      [ $# -ge 2 ] || die "--jpm-rev needs a value"; JPM_REV=$2; shift 2 ;;
        --jpm-rev=*)    JPM_REV=${1#*=}; shift ;;
        --jpm-src)      [ $# -ge 2 ] || die "--jpm-src needs a value"; JPM_SRC=$2; shift 2 ;;
        --jpm-src=*)    JPM_SRC=${1#*=}; shift ;;
        --toolchain)    [ $# -ge 2 ] || die "--toolchain needs a value"; TOOLCHAIN_DIR=$2; shift 2 ;;
        --toolchain=*)  TOOLCHAIN_DIR=${1#*=}; shift ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

# Make toolchain path absolute and derive dependents.
case "$TOOLCHAIN_DIR" in
    /*) ;;
    *) TOOLCHAIN_DIR="$ROOT_DIR/$TOOLCHAIN_DIR" ;;
esac
LIBEXEC_DIR="$TOOLCHAIN_DIR/libexec"
JANET_BIN="$TOOLCHAIN_DIR/bin/janet"    # our launcher (public entry point)
JPM_BIN="$TOOLCHAIN_DIR/bin/jpm"        # our launcher (public entry point)
JANET_REAL="$LIBEXEC_DIR/janet"         # the real built janet binary (private)
JPM_REAL="$LIBEXEC_DIR/jpm"             # jpm's own generated script (private)
JANET_MODPATH="$TOOLCHAIN_DIR/lib/janet"
JANET_INCLUDEDIR="$TOOLCHAIN_DIR/include/janet"
BUILD_DIR="$TOOLCHAIN_DIR/build"        # jpm :buildpath (project build output)
STAMP_FILE="$TOOLCHAIN_DIR/TOOLCHAIN"

# --- Portable helpers ---------------------------------------------------------
ncpu() { nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command '$1' ($2). Install base build tools and retry."
}

is_sha() {
    case "$1" in
        [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*) return 0 ;;
        *) return 1 ;;
    esac
}

check_ssl_dev() {
    # jsec needs OpenSSL/LibreSSL (or libretls) dev headers + libs (ticket names
    # these). Compile+link a trivial probe so any layout is detected accurately.
    _c="$SCRATCH_DIR/.ssl-probe.c"; _o="$SCRATCH_DIR/.ssl-probe"
    mkdir -p "$SCRATCH_DIR"
    printf '#include <openssl/ssl.h>\nint main(void){ SSL_library_init(); return 0; }\n' > "$_c"
    if "$CC" "$_c" -o "$_o" -lssl -lcrypto >/dev/null 2>&1; then rm -f "$_c" "$_o"; return 0; fi
    printf '#include <tls.h>\nint main(void){ return 0; }\n' > "$_c"
    if "$CC" "$_c" -o "$_o" -ltls >/dev/null 2>&1; then rm -f "$_c" "$_o"; return 0; fi
    rm -f "$_c" "$_o"; return 1
}

# Copy a source mirror excluding .git and any build/ tree.
copy_src() {
    mkdir -p "$2"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude '.git/' --exclude 'build/' "$1/" "$2/"
    else
        ( cd "$1" && tar cf - --exclude=./.git --exclude=./build . ) | ( cd "$2" && tar xf - )
    fi
}

# Resolve Janet source at JANET_REV into $SRC_DIR/janet. Default is a
# self-fetch: clone that exact rev from JANET_URL into .work/src/janet/. A
# local mirror is consulted only when opted in (--janet-src / JANET_SRC);
# with --local the mirror is mandatory and the network is never touched.
resolve_janet_src() {
    dest="$SRC_DIR/janet"
    if [ -f "$dest/Makefile" ] && [ "$(cat "$dest/.jsec-rev" 2>/dev/null || echo)" = "$JANET_REV" ]; then
        note "reused Janet source at $dest (rev $JANET_REV)"
        RESOLVED_SRC="$dest"; return 0
    fi
    rm -rf "$dest"; mkdir -p "$dest"

    if [ -n "${JANET_SRC:-}" ]; then
        [ -d "$JANET_SRC" ] || die "Janet mirror $JANET_SRC does not exist."
        if git -C "$JANET_SRC" cat-file -e "$JANET_REV^{commit}" 2>/dev/null; then
            log "Extracting Janet rev $JANET_REV from local mirror $JANET_SRC..."
            git -C "$JANET_SRC" archive "$JANET_REV" | ( cd "$dest" && tar xf - )
            echo "$JANET_REV" > "$dest/.jsec-rev"
            note "checked out Janet rev $JANET_REV from $JANET_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        if [ ! -e "$JANET_SRC/.git" ] && [ -f "$JANET_SRC/Makefile" ]; then
            # Plain tree without git metadata: the caller asserts it holds
            # JANET_REV. This is the offline case --local exists for.
            log "Copying local Janet tree from $JANET_SRC..."
            copy_src "$JANET_SRC" "$dest"
            echo "$JANET_REV" > "$dest/.jsec-rev"
            note "copied Janet rev $JANET_REV (as asserted) from $JANET_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but Janet rev $JANET_REV not found in mirror $JANET_SRC."
    fi

    [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but no Janet mirror given (--janet-src or JANET_SRC)."
    log "Cloning Janet rev $JANET_REV from $JANET_URL..."
    if is_sha "$JANET_REV"; then
        git clone "$JANET_URL" "$dest" >/dev/null 2>&1 || die "clone of $JANET_URL failed."
        git -C "$dest" checkout --quiet "$JANET_REV" || die "Janet rev $JANET_REV not found in $JANET_URL."
    else
        git clone --depth 1 --branch "$JANET_REV" "$JANET_URL" "$dest" >/dev/null 2>&1 || die "clone of Janet tag/branch $JANET_REV failed."
    fi
    echo "$JANET_REV" > "$dest/.jsec-rev"
    note "cloned Janet rev $JANET_REV from $JANET_URL"
    RESOLVED_SRC="$dest"
}

# Resolve jpm source at JPM_REV into $SRC_DIR/jpm. Default is a self-fetch:
# clone that exact rev from JPM_URL into .work/src/jpm/. A local mirror is
# consulted only when opted in (--jpm-src / JPM_SRC); with --local the mirror
# is mandatory and the network is never touched.
resolve_jpm_src() {
    dest="$SRC_DIR/jpm"
    if [ -f "$dest/bootstrap.janet" ] && [ "$(cat "$dest/.jsec-rev" 2>/dev/null || echo)" = "$JPM_REV" ]; then
        note "reused jpm source at $dest (rev $JPM_REV)"
        RESOLVED_SRC="$dest"; return 0
    fi
    rm -rf "$dest"; mkdir -p "$dest"

    if [ -n "${JPM_SRC:-}" ]; then
        [ -d "$JPM_SRC" ] || die "jpm mirror $JPM_SRC does not exist."
        if git -C "$JPM_SRC" cat-file -e "$JPM_REV^{commit}" 2>/dev/null; then
            log "Extracting jpm rev $JPM_REV from local mirror $JPM_SRC..."
            git -C "$JPM_SRC" archive "$JPM_REV" | ( cd "$dest" && tar xf - )
            echo "$JPM_REV" > "$dest/.jsec-rev"
            note "checked out jpm rev $JPM_REV from $JPM_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        if [ ! -e "$JPM_SRC/.git" ] && [ -f "$JPM_SRC/bootstrap.janet" ]; then
            # Plain tree without git metadata: the caller asserts it holds
            # JPM_REV. This is the offline case --local exists for.
            log "Copying local jpm tree from $JPM_SRC..."
            copy_src "$JPM_SRC" "$dest"
            echo "$JPM_REV" > "$dest/.jsec-rev"
            note "copied jpm rev $JPM_REV (as asserted) from $JPM_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but jpm rev $JPM_REV not found in mirror $JPM_SRC."
    fi

    [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but no jpm mirror given (--jpm-src or JPM_SRC)."
    log "Cloning jpm rev $JPM_REV from $JPM_URL..."
    if is_sha "$JPM_REV"; then
        git clone "$JPM_URL" "$dest" >/dev/null 2>&1 || die "clone of jpm rev $JPM_REV failed."
        git -C "$dest" checkout --quiet "$JPM_REV" || die "jpm rev $JPM_REV not found in $JPM_URL."
    else
        git clone --depth 1 --branch "$JPM_REV" "$JPM_URL" "$dest" >/dev/null 2>&1 || die "clone of jpm tag/branch $JPM_REV failed."
    fi
    echo "$JPM_REV" > "$dest/.jsec-rev"
    note "cloned jpm rev $JPM_REV from $JPM_URL"
    RESOLVED_SRC="$dest"
}

# Run a command under a clean environment (env -i): only PATH and HOME are
# carried over, so a stale or hostile JANET_*/PREFIX export in the calling
# shell cannot leak into the toolchain being generated. PATH leads with the
# toolchain's own bin/ so `which janet` resolves to the launcher; the host
# tool locations that follow are still needed for cc, make, ar and git.
clean_env() {
    env -i PATH="$TOOLCHAIN_DIR/bin:$PATH" HOME="$HOME" "$@"
}

# jpm's generate-config cannot express :janet (it emits the bare name "janet")
# or :buildpath. Extend the generated default-config.janet structurally
# (dofile -> put -> spit) with those two keys: :janet names our launcher so
# jpm-spawned children re-enter the env-establishing entry point, and
# :buildpath pins the project build output. Nothing in the generated file is
# string-matched or patched.
extend_default_config() {
    _pp="$SCRATCH_DIR/.extend-config.janet"
    cat > "$_pp" <<'EOF'
(def cfg-path (os/getenv "PP_CONFIG"))
(def janet-abs (os/getenv "PP_JANET"))
(def build-abs (os/getenv "PP_BUILD"))

(def env (dofile cfg-path))
(def cfg (get-in env ['config :value]))
(unless (table? cfg) (error "default-config.janet does not define config"))
(put cfg :janet janet-abs)
(put cfg :buildpath build-abs)
(spit cfg-path
      (string/format
        "# Autogenerated by generate-config in jpm/make-config.janet\n(def config %.99m)"
        cfg))
EOF
    if ! clean_env \
           PP_CONFIG="$JANET_MODPATH/jpm/default-config.janet" \
           PP_JANET="$JANET_BIN" \
           PP_BUILD="$BUILD_DIR" \
           "$JANET_REAL" "$_pp"; then
        return 1
    fi
    note "extended jpm default-config.janet with :janet and :buildpath"
}

# Run a command, quiet on success; dump captured output and fail on error.
run_logged() {
    _log="$SCRATCH_DIR/.last-make.log"
    if "$@" >"$_log" 2>&1; then return 0; fi
    printf '--- output ---\n' >&2
    cat "$_log" >&2
    printf '--- end output ---\n' >&2
    return 1
}

build_janet() {
    log "Building Janet rev $JANET_REV into $TOOLCHAIN_DIR..."
    # PREFIX/JANET_PATH must be set for the BUILD step too: the default syspath is
    # baked into the amalgam at generation time. An ambient PREFIX (or JANET_PATH)
    # in the environment would otherwise leak a foreign path into (dyn :syspath),
    # breaking hermeticity. Command-line make vars override any ambient value.
    run_logged make -C "$1" PREFIX="$TOOLCHAIN_DIR" JANET_PATH="$JANET_MODPATH" -j"$(ncpu)" \
        || die "Janet build failed (see output above)."
    run_logged make -C "$1" PREFIX="$TOOLCHAIN_DIR" JANET_PATH="$JANET_MODPATH" install \
        || die "Janet install into $TOOLCHAIN_DIR failed."
    [ -x "$TOOLCHAIN_DIR/bin/janet" ] || die "Janet binary missing after install: $TOOLCHAIN_DIR/bin/janet"
    note "built Janet $(clean_env "$TOOLCHAIN_DIR/bin/janet" -e '(print janet/version)') -> $JANET_REAL"
}

# bin/ holds only our launchers; the real janet binary is private under libexec/.
relocate_janet() {
    log "Relocating the real Janet binary to libexec/..."
    mkdir -p "$LIBEXEC_DIR"
    mv "$TOOLCHAIN_DIR/bin/janet" "$JANET_REAL"
    note "relocated janet binary -> $JANET_REAL"
}

bootstrap_jpm() {
    log "Bootstrapping jpm rev $JPM_REV against in-tree Janet..."
    # jpm's generate-config derives binpath/headerpath/libpath/manpath/modpath
    # from PREFIX (JANET_STRICT_MODPATH pins modpath to lib/janet), so the
    # generated default-config.janet points INTO the toolchain - the baked
    # headerpath must resolve to <prefix>/include/janet, never a host include
    # dir. clean_env applies here: hostile exports must not be baked into the
    # generated config.
    _log="$SCRATCH_DIR/.last-make.log"
    if ! ( cd "$1" && \
           clean_env \
           PREFIX="$TOOLCHAIN_DIR" \
           JANET_STRICT_MODPATH=true \
           "$JANET_REAL" bootstrap.janet ) >"$_log" 2>&1; then
        printf '%s\n' "--- output ---" >&2; cat "$_log" >&2; printf '%s\n' "--- end output ---" >&2
        die "jpm bootstrap failed (see output above)."
    fi
    [ -x "$TOOLCHAIN_DIR/bin/jpm" ] || die "jpm script missing after bootstrap: $TOOLCHAIN_DIR/bin/jpm"
    [ -f "$JANET_MODPATH/jpm/default-config.janet" ] || die "jpm default-config.janet missing under $JANET_MODPATH/jpm/"
    note "bootstrapped jpm -> $JPM_REAL"
}

# bin/ holds only our launchers; jpm's own generated script is private too.
# bin/jpm passes it to libexec/janet as a script argument, so its execute bit
# is dropped: direct execution is not an entry point.
relocate_jpm() {
    log "Relocating jpm's generated script to libexec/..."
    mkdir -p "$LIBEXEC_DIR"
    mv "$TOOLCHAIN_DIR/bin/jpm" "$JPM_REAL"
    chmod -x "$JPM_REAL"
    note "relocated jpm script -> $JPM_REAL"
}

# Our committed launchers are relocatable repo source: copied, never generated.
# The janet launcher goes in BEFORE jpm's bootstrap: jpm's auto-shebang picks
# <binpath>/janet when that exists, so the generated libexec/jpm script then
# names the launcher and every execution path re-enters it.
install_janet_launcher() {
    log "Installing the janet launcher into bin/..."
    [ -f "$LAUNCHER_JANET" ] || die "launcher source missing: $LAUNCHER_JANET"
    mkdir -p "$TOOLCHAIN_DIR/bin"
    cp "$LAUNCHER_JANET" "$JANET_BIN"
    chmod +x "$JANET_BIN"
    note "installed launcher -> $JANET_BIN"
}

install_jpm_launcher() {
    log "Installing the jpm launcher into bin/..."
    [ -f "$LAUNCHER_JPM" ] || die "launcher source missing: $LAUNCHER_JPM"
    mkdir -p "$TOOLCHAIN_DIR/bin"
    cp "$LAUNCHER_JPM" "$JPM_BIN"
    chmod +x "$JPM_BIN"
    note "installed launcher -> $JPM_BIN"
}

write_stamp() {
    mkdir -p "$(dirname "$STAMP_FILE")"
    {
        echo "janet-rev: $JANET_REV"
        echo "janet-version: $("$JANET_BIN" -e '(print janet/version)' 2>/dev/null || echo unknown)"
        echo "jpm-rev: $JPM_REV"
        echo "toolchain-prefix: $TOOLCHAIN_DIR"
        echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$STAMP_FILE"
}

print_summary() {
    log "Hermetic toolchain ready at $TOOLCHAIN_DIR"
    info "janet:      $("$JANET_BIN" -e '(print janet/version)' 2>/dev/null)  (syspath: $("$JANET_BIN" -e '(print (dyn :syspath))' 2>/dev/null))"
    info "jpm:        $JPM_BIN"
    info "libexec:    $JANET_REAL , $JPM_REAL"
    info "headerpath: $JANET_INCLUDEDIR"
    info "modpath:    $JANET_MODPATH"
    info "buildpath:  $BUILD_DIR"
    if [ -n "$ACTIONS" ]; then
        log "Actions taken:"
        printf '%s' "$ACTIONS"
    fi
    log "Build/test with $JANET_BIN and $JPM_BIN (never the host janet/jpm)."
}

have_toolchain() {
    # Complete toolchain = the relocated real binaries + our launchers +
    # headers + jpm's generated config. The stamp (written only after a fully
    # successful run) is checked separately. libexec/jpm is checked with -f:
    # it is non-executable by design (a script argument to libexec/janet).
    [ -x "$JANET_REAL" ] && [ -f "$JPM_REAL" ] && \
        [ -x "$JANET_BIN" ] && [ -x "$JPM_BIN" ] && \
        [ -f "$JANET_INCLUDEDIR/janet.h" ] && \
        [ -f "$JANET_MODPATH/jpm/default-config.janet" ]
}

# --- Main ---------------------------------------------------------------------
log "Checking host prerequisites..."
CC="${CC:-cc}"
require_cmd "$CC" "C compiler"
require_cmd ar "static archiver"
require_cmd make "build driver for Janet"
require_cmd git "source checkout"
mkdir -p "$SCRATCH_DIR"
check_ssl_dev || die "OpenSSL/LibreSSL dev headers and libs not found (need openssl/ssl.h + -lssl/-lcrypto, or libretls tls.h + -ltls). Install openssl (or libretls) development packages and retry."
info "C compiler: $(command -v "$CC") ($("$CC" --version 2>/dev/null | head -1))"
info "SSL dev: ok (openssl/libretls)"
info "Janet rev: $JANET_REV"
info "jpm rev:   $JPM_REV"

if [ "$CLEAN" -eq 1 ]; then
    log "Cleaning $TOOLCHAIN_DIR..."
    # The default prefix is .work/ itself, which also holds the project's own
    # src/ and scratch/: keep those. build/ is the toolchain's disposable
    # build output and goes too - stale objects from a different Janet are
    # what the per-toolchain buildpath exists to exclude.
    rm -rf "$TOOLCHAIN_DIR/bin" "$TOOLCHAIN_DIR/build" "$TOOLCHAIN_DIR/include" \
           "$TOOLCHAIN_DIR/lib" "$TOOLCHAIN_DIR/libexec" "$TOOLCHAIN_DIR/share"
    rm -f "$STAMP_FILE"
fi

mkdir -p "$SRC_DIR" "$TOOLCHAIN_DIR" "$SCRATCH_DIR" "$BUILD_DIR"

if [ "$FORCE" -eq 0 ] && have_toolchain; then
    cur=$("$JANET_BIN" -e '(print janet/version)' 2>/dev/null || echo unknown)
    stamped=$(grep '^janet-rev:' "$STAMP_FILE" 2>/dev/null | awk '{print $2}' || echo)
    if [ "$stamped" = "$JANET_REV" ]; then
        log "Toolchain already present (Janet $cur, rev $JANET_REV) at $TOOLCHAIN_DIR; nothing to do."
        info "Use --force to rebuild or --clean to start over."
        print_summary
        exit 0
    fi
    log "Toolchain present for a different Janet rev (${stamped:-unknown} -> $JANET_REV); rebuilding."
fi

# Rebuilding now: drop the stamp first so an interrupted rebuild cannot look
# complete on the next run (the stamp is written only after full success).
rm -f "$STAMP_FILE"

resolve_janet_src
build_janet "$RESOLVED_SRC"
relocate_janet
install_janet_launcher
resolve_jpm_src
bootstrap_jpm "$RESOLVED_SRC"
relocate_jpm
install_jpm_launcher
extend_default_config
write_stamp
print_summary
