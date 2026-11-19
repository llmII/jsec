#!/bin/sh
# Portable POSIX sh (no bash-isms: BSD/Solaris /bin/sh safe).
set -eu

# ==============================================================================
# JSEC Hermetic In-Tree Toolchain Seed Wrapper (POSIX)
# ==============================================================================
# Minimal shell bootstrap: ensures a seed janet binary exists at
# .work/seed/janet and delegates all toolchain management to
# scripts/bootstrap-toolchain.janet.
# ==============================================================================

SEED_JANET_REV="8b6d56edae8c1eb5ae19b024087a065b6918b9ef"
JANET_URL="${JANET_URL:-https://github.com/janet-lang/janet.git}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(dirname -- "$SCRIPT_DIR")
WORK_DIR="$ROOT_DIR/.work"
SEED_DIR="$WORK_DIR/seed"
SEED_JANET="$SEED_DIR/janet"
JANET_SRC_DIR="$WORK_DIR/src/janet"

if [ ! -x "$SEED_JANET" ]; then
    mkdir -p "$SEED_DIR" "$WORK_DIR/src"
    if [ -x "$WORK_DIR/libexec/janet" ]; then
        cp "$WORK_DIR/libexec/janet" "$SEED_JANET"
        chmod +x "$SEED_JANET"
    else
        printf '==> Building seed Janet into %s...\n' "$SEED_JANET"
        CC="${CC:-}"
        if [ -z "$CC" ]; then
            if command -v cc >/dev/null 2>&1; then CC="cc"
            elif command -v gcc >/dev/null 2>&1; then CC="gcc"
            elif command -v clang >/dev/null 2>&1; then CC="clang"
            else CC="cc"; fi
        fi
        MAKE="${MAKE:-}"
        if [ -z "$MAKE" ]; then
            if command -v gmake >/dev/null 2>&1; then MAKE="gmake"
            else MAKE="make"; fi
        fi
        if [ ! -f "$JANET_SRC_DIR/Makefile" ]; then
            rm -rf "$JANET_SRC_DIR"
            mkdir -p "$JANET_SRC_DIR"
            if [ -n "${JANET_SRC:-}" ] && git -C "$JANET_SRC" cat-file -e "$SEED_JANET_REV^{commit}" 2>/dev/null; then
                git -C "$JANET_SRC" archive "$SEED_JANET_REV" | ( cd "$JANET_SRC_DIR" && tar xf - )
            else
                git clone "$JANET_URL" "$JANET_SRC_DIR" >/dev/null 2>&1
                git -C "$JANET_SRC_DIR" checkout --quiet "$SEED_JANET_REV"
            fi
            echo "$SEED_JANET_REV" > "$JANET_SRC_DIR/.jsec-rev"
        fi
        "$MAKE" -C "$JANET_SRC_DIR" CC="$CC" build/janet >/dev/null 2>&1
        cp "$JANET_SRC_DIR/build/janet" "$SEED_JANET"
        chmod +x "$SEED_JANET"
    fi
fi

exec "$SEED_JANET" "$SCRIPT_DIR/bootstrap-toolchain.janet" "$@"
