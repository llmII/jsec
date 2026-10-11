#!/bin/sh
# Run jsec tests with ALL sanitizers (ASan + LSan + UBSan) under the hermetic
# .work/san toolchain.
# Usage: ./sanitizers/run-tests.sh [test-runner-args...]
#
# Equivalent to `.work/bin/jpm run self-test-san` (or `jpm run test/sanitized`)
# when called with no arguments, and accepts custom test/runner.janet flags
# when arguments are passed.

set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)"
TOOLCHAIN_DIR="${JSEC_SAN_TOOLCHAIN:-$PROJECT_DIR/.work/san}"
LOG_DIR="$TOOLCHAIN_DIR/scratch/san-logs"
HALT="${JSEC_SAN_HALT:-0}"

cd "$PROJECT_DIR"

if [ ! -x "$TOOLCHAIN_DIR/bin/janet" ]; then
    sh "$PROJECT_DIR/scripts/bootstrap-toolchain.sh" \
        --sanitizer san --toolchain "$TOOLCHAIN_DIR"
fi

if [ ! -d "$TOOLCHAIN_DIR/lib/janet/assay" ] || [ ! -d "$TOOLCHAIN_DIR/lib/janet/spork" ]; then
    JSEC_SAN=1 "$TOOLCHAIN_DIR/bin/jpm" deps
fi
JSEC_SAN=1 "$TOOLCHAIN_DIR/bin/jpm" build
JSEC_SAN=1 "$TOOLCHAIN_DIR/bin/jpm" install

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

export PATH="$TOOLCHAIN_DIR/bin:$PATH"
export ASAN_OPTIONS="suppressions=$SCRIPT_DIR/asan.supp:detect_leaks=1:halt_on_error=$HALT:print_stacktrace=1:fast_unwind_on_malloc=0:exitcode=23:log_path=$LOG_DIR/san.log"
export LSAN_OPTIONS="suppressions=$SCRIPT_DIR/lsan.supp:print_suppressions=0:print_stacktrace=1:fast_unwind_on_malloc=0:exitcode=23:log_path=$LOG_DIR/san.log"
export UBSAN_OPTIONS="suppressions=$SCRIPT_DIR/ubsan.supp:halt_on_error=$HALT:print_stacktrace=1:exitcode=23:log_path=$LOG_DIR/san.log"

if [ "$#" -eq 0 ]; then
    set -- -f '{unit,regression,coverage}' -j fiber:16,thread:6,subprocess:6
fi

rc=0
"$TOOLCHAIN_DIR/bin/janet" test/runner.janet "$@" || rc=$?

found=0
for f in "$LOG_DIR"/san.log.*; do
    if [ -f "$f" ] && [ -s "$f" ]; then
        found=$((found + 1))
    fi
done

if [ "$found" -gt 0 ]; then
    printf '\n=== Sanitizer findings (%d process log(s) in %s) ===\n' "$found" "$LOG_DIR"
    for f in "$LOG_DIR"/san.log.*; do
        if [ -f "$f" ] && [ -s "$f" ]; then
            printf '\n--- %s ---\n' "$f"
            cat "$f"
        fi
    done
    [ "$rc" -ne 0 ] && exit "$rc"
    exit 23
fi

exit "$rc"
