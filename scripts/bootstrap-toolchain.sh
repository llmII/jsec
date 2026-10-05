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
# The Janet revision is a parameter (tag, branch, or githash) so one script can
# drive a per-version matrix. Each rev can build into its own toolchain prefix
# via --toolchain, so multiple Janets coexist under .work/.
#
# Layout produced (mirrors the reference toolchain convention):
#   <prefix>/bin/janet
#   <prefix>/bin/jpm
#   <prefix>/include/janet/janet.h
#   <prefix>/lib/libjanet.a  (and shared lib)
#   <prefix>/lib/janet/      (installed modules, incl. jpm/)
#
# The in-tree jpm is bootstrapped AGAINST the in-tree janet with PREFIX and
# JANET_*PATH pointing into <prefix>, so its baked default-config.janet resolves
# :headerpath/:modpath/:binpath/:libpath inside the toolchain.
#
# Windows is a special case handled separately (see build-windows.bat / MSVC +
# vcpkg, or MSYS2 MinGW); this script targets POSIX hosts (Linux, the BSDs,
# macOS, Solaris/Illumos, Chimera).
# ==============================================================================

# --- Default pinned revisions -------------------------------------------------
# This increment pins one Janet. The rev is a githash so it is exact and
# reproducible; pass --janet-rev <tag|branch|githash> to build a different Janet
# (e.g. --janet-rev 7d672f43 or --janet-rev 7810724e) for the version matrix.
DEFAULT_JANET_REV="7d672f43fcd572965c8b63c61dd835d6e680ac1d"  # janet 1.40.1
DEFAULT_JPM_REV="2430dec269f485473502bcdc2049ee332bc63908"    # jpm 1.2.1

JANET_URL="${JANET_URL:-https://github.com/janet-lang/janet.git}"
JPM_URL="${JPM_URL:-https://github.com/janet-lang/jpm.git}"

# Offline source mirrors (override via env). Used to avoid network when they
# contain the requested rev; otherwise the rev is cloned from the URL above.
JANET_SRC="${JANET_SRC:-/home/llmII/workspace/personal/dev/janet/code/contributing/janet}"
JPM_SRC="${JPM_SRC:-/data/services/agentic/usr/projects/agentic-ng/.work/src/jpm}"

# --- Locations (SCRIPT_DIR via $0; POSIX-safe) --------------------------------
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(dirname -- "$SCRIPT_DIR")
WORK_DIR="$ROOT_DIR/.work"
SRC_DIR="$WORK_DIR/src"
TOOLCHAIN_DIR="$WORK_DIR/toolchain"     # overridable via --toolchain
SCRATCH_DIR="$WORK_DIR/scratch"
STAMP_FILE="$WORK_DIR/TOOLCHAIN"

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

The Janet revision is selectable (tag, branch, or githash) so one script can
drive a per-version test matrix. Pair --janet-rev with --toolchain to keep
multiple Janet toolchains side by side under .work/.

Options:
  -h, --help             Show this help and exit
  -f, --force            Rebuild the toolchain even if it already exists
  -c, --clean            Remove the toolchain prefix first, then rebuild
      --local            Offline only: use local mirrors, never clone (error if
                         the requested rev is not in a local mirror)
      --janet-rev REV    Janet revision to build (tag/branch/githash).
                         Default: ${DEFAULT_JANET_REV} (janet 1.40.1)
      --jpm-rev REV      jpm revision to build (tag/branch/githash).
                         Default: ${DEFAULT_JPM_REV} (jpm 1.2.1)
      --toolchain DIR    Output prefix. Default: .work/toolchain
                         (e.g. .work/toolchain/1.40.1 for a matrix)

Environment:
  JANET_SRC   Local Janet source mirror  (default: ${JANET_SRC})
  JPM_SRC     Local jpm source mirror    (default: ${JPM_SRC})
  JANET_URL   Janet git URL for cloning  (default: ${JANET_URL})
  JPM_URL     jpm git URL for cloning    (default: ${JPM_URL})
  CC          C compiler (default: cc)

Output under --toolchain:
  bin/{janet,jpm}
  include/janet/janet.h
  lib/libjanet.a
  lib/janet/                 (installed modules)

Provenance is recorded in .work/TOOLCHAIN (revisions + built Janet version).
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
        --jpm-rev)      [ $# -ge 2 ] || die "--jpm-rev needs a value"; JPM_REV=$2; shift 2 ;;
        --jpm-rev=*)    JPM_REV=${1#*=}; shift ;;
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
JANET_BIN="$TOOLCHAIN_DIR/bin/janet"
JPM_BIN="$TOOLCHAIN_DIR/bin/jpm"
JANET_MODPATH="$TOOLCHAIN_DIR/lib/janet"
JANET_HEADERPATH="$TOOLCHAIN_DIR/include/janet"

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

# Resolve Janet source at JANET_REV into $SRC_DIR/janet. Honors the offline
# mirror when it contains the requested rev; otherwise clones that exact rev.
resolve_janet_src() {
    dest="$SRC_DIR/janet"
    if [ -f "$dest/Makefile" ] && [ "$(cat "$dest/.jsec-rev" 2>/dev/null || echo)" = "$JANET_REV" ]; then
        note "reused Janet source at $dest (rev $JANET_REV)"
        RESOLVED_SRC="$dest"; return 0
    fi
    rm -rf "$dest"; mkdir -p "$dest"

    if [ -n "${JANET_SRC:-}" ] && [ -d "$JANET_SRC" ] && [ -f "$JANET_SRC/Makefile" ]; then
        if [ "$LOCAL_ONLY" -eq 1 ] || [ "$JANET_REV" = "$DEFAULT_JANET_REV" ]; then
            log "Copying local Janet source from $JANET_SRC..."
            copy_src "$JANET_SRC" "$dest"
            echo "$JANET_REV" > "$dest/.jsec-rev"
            note "copied Janet rev $JANET_REV from $JANET_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        if git -C "$JANET_SRC" cat-file -e "$JANET_REV^{commit}" 2>/dev/null; then
            log "Copying local Janet mirror and checking out rev $JANET_REV..."
            copy_src "$JANET_SRC" "$dest"
            git -C "$JANET_SRC" archive "$JANET_REV" | ( cd "$dest" && tar xf - )
            echo "$JANET_REV" > "$dest/.jsec-rev"
            note "checked out Janet rev $JANET_REV from $JANET_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
    fi

    [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but Janet rev $JANET_REV not found in local mirror ${JANET_SRC:-unset}."
    log "Cloning Janet rev $JANET_REV from $JANET_URL..."
    if is_sha "$JANET_REV"; then
        git clone "$JANET_URL" "$dest" >/dev/null 2>&1 || die "clone of $JANET_URL failed."
        git -C "$dest" checkout --quiet "$JANET_REV" || die "Janet rev $JANET_REV not found in $JANET_URL."
    else
        git clone --depth 1 --branch "$JANET_REV" "$JANET_URL" "$dest" >/dev/null 2>&1 || die "clone of Janet tag/branch $JANET_REV failed."
    fi
    echo "$JANET_REV" > "$dest/.jsec-rev"
    note "cloned Janet rev $JANET_REV from $JANET_URL"
    printf '%s' "$dest"
}

resolve_jpm_src() {
    dest="$SRC_DIR/jpm"
    if [ -f "$dest/bootstrap.janet" ] && [ "$(cat "$dest/.jsec-rev" 2>/dev/null || echo)" = "$JPM_REV" ]; then
        note "reused jpm source at $dest (rev $JPM_REV)"
        RESOLVED_SRC="$dest"; return 0
    fi
    rm -rf "$dest"; mkdir -p "$dest"

    if [ -n "${JPM_SRC:-}" ] && [ -d "$JPM_SRC" ] && [ -f "$JPM_SRC/bootstrap.janet" ]; then
        if [ "$LOCAL_ONLY" -eq 1 ] || [ "$JPM_REV" = "$DEFAULT_JPM_REV" ]; then
            log "Copying local jpm source from $JPM_SRC..."
            copy_src "$JPM_SRC" "$dest"
            echo "$JPM_REV" > "$dest/.jsec-rev"
            note "copied jpm rev $JPM_REV from $JPM_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
        if git -C "$JPM_SRC" cat-file -e "$JPM_REV^{commit}" 2>/dev/null; then
            log "Copying local jpm mirror and checking out rev $JPM_REV..."
            copy_src "$JPM_SRC" "$dest"
            git -C "$JPM_SRC" archive "$JPM_REV" | ( cd "$dest" && tar xf - )
            echo "$JPM_REV" > "$dest/.jsec-rev"
            note "checked out jpm rev $JPM_REV from $JPM_SRC"
            RESOLVED_SRC="$dest"; return 0
        fi
    fi

    [ "$LOCAL_ONLY" -eq 1 ] && die "--local requested but jpm rev $JPM_REV not found in local mirror ${JPM_SRC:-unset}."
    log "Cloning jpm rev $JPM_REV from $JPM_URL..."
    if is_sha "$JPM_REV"; then
        git clone "$JPM_URL" "$dest" >/dev/null 2>&1 || die "clone of $JPM_URL failed."
        git -C "$dest" checkout --quiet "$JPM_REV" || die "jpm rev $JPM_REV not found."
    else
        git clone --depth 1 --branch "$JPM_REV" "$JPM_URL" "$dest" >/dev/null 2>&1 || die "clone of jpm tag/branch $JPM_REV failed."
    fi
    echo "$JPM_REV" > "$dest/.jsec-rev"
    note "cloned jpm rev $JPM_REV from $JPM_URL"
    printf '%s' "$dest"
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
    [ -x "$JANET_BIN" ] || die "Janet binary missing after install: $JANET_BIN"
    note "built Janet -> $JANET_BIN ($("$JANET_BIN" -e '(print janet/version)'))"
}

bootstrap_jpm() {
    log "Bootstrapping jpm rev $JPM_REV against in-tree Janet..."
    # Env vars force jpm's generated default-config.janet to point INTO the
    # toolchain. This is the whole point: the baked headerpath must resolve to
    # <prefix>/include/janet, never a host include dir.
    _log="$SCRATCH_DIR/.last-make.log"
    if ! ( cd "$1" && \
           PREFIX="$TOOLCHAIN_DIR" \
           JANET_BINPATH="$TOOLCHAIN_DIR/bin" \
           JANET_MODPATH="$JANET_MODPATH" \
           JANET_HEADERPATH="$JANET_HEADERPATH" \
           JANET_LIBPATH="$TOOLCHAIN_DIR/lib" \
           JANET_MANPATH="$TOOLCHAIN_DIR/share/man/man1" \
           JANET_STRICT_MODPATH=true \
           "$JANET_BIN" bootstrap.janet ) >"$_log" 2>&1; then
        printf '%s\n' "--- output ---" >&2; cat "$_log" >&2; printf '%s\n' "--- end output ---" >&2
        die "jpm bootstrap failed (see output above)."
    fi
    [ -x "$JPM_BIN" ] || die "jpm binary missing after bootstrap: $JPM_BIN"
    [ -f "$JANET_MODPATH/jpm/default-config.janet" ] || die "jpm default-config.janet missing under $JANET_MODPATH/jpm/"
    note "bootstrapped jpm -> $JPM_BIN"
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
    info "headerpath: $JANET_HEADERPATH"
    info "modpath:    $JANET_MODPATH"
    if [ -f "$JANET_MODPATH/jpm/default-config.janet" ]; then
        info "jpm baked :headerpath -> $(grep -o ':headerpath "[^"]*"' "$JANET_MODPATH/jpm/default-config.janet" | sed 's/:headerpath //')"
    fi
    if [ -n "$ACTIONS" ]; then
        log "Actions taken:"
        printf '%s' "$ACTIONS"
    fi
    log "Build/test with $JANET_BIN and $JPM_BIN (never the host janet/jpm)."
}

have_toolchain() {
    [ -x "$JANET_BIN" ] && [ -x "$JPM_BIN" ] && \
        [ -f "$JANET_HEADERPATH/janet.h" ] && \
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
    rm -rf "$TOOLCHAIN_DIR"
fi

mkdir -p "$SRC_DIR" "$TOOLCHAIN_DIR" "$SCRATCH_DIR"

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

resolve_janet_src
build_janet "$RESOLVED_SRC"
resolve_jpm_src
bootstrap_jpm "$RESOLVED_SRC"
write_stamp
print_summary
