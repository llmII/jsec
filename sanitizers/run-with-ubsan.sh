#!/bin/sh
# Run jsec code or tests under the hermetic UndefinedBehaviorSanitizer toolchain (.work/ubsan).
# Usage: ./sanitizers/run-with-ubsan.sh janet script.janet [args...]
#        ./sanitizers/run-with-ubsan.sh test [test-runner-args...]

set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)"
TOOLCHAIN_DIR="${JSEC_SAN_TOOLCHAIN:-$PROJECT_DIR/.work/ubsan}"
LOG_DIR="$TOOLCHAIN_DIR/scratch/san-logs"
HALT="${JSEC_SAN_HALT:-0}"

cd "$PROJECT_DIR"

if [ ! -x "$TOOLCHAIN_DIR/bin/janet" ]; then
    sh "$PROJECT_DIR/scripts/bootstrap-toolchain.sh" \
        --sanitizer ubsan --toolchain "$TOOLCHAIN_DIR"
fi

if [ "${1:-}" = "test" ] || [ ! -f "$TOOLCHAIN_DIR/lib/janet/jsec/tls-stream.so" ] || [ "${JSEC_SAN_REBUILD:-0}" = "1" ]; then
    if [ ! -d "$TOOLCHAIN_DIR/lib/janet/assay" ] || [ ! -d "$TOOLCHAIN_DIR/lib/janet/spork" ]; then
        JSEC_UBSAN=1 "$TOOLCHAIN_DIR/bin/jpm" deps
    fi
    JSEC_UBSAN=1 "$TOOLCHAIN_DIR/bin/jpm" build
    JSEC_UBSAN=1 "$TOOLCHAIN_DIR/bin/jpm" install
fi

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

export PATH="$TOOLCHAIN_DIR/bin:$PATH"
export UBSAN_OPTIONS="suppressions=$SCRIPT_DIR/ubsan.supp:halt_on_error=$HALT:print_stacktrace=1:exitcode=23:log_path=$LOG_DIR/san.log"

rc=0
case "${1:-}" in
    test)
        shift
        if [ "$#" -eq 0 ]; then
            set -- -f '{unit,regression,coverage}' -j fiber:16,thread:6,subprocess:6
        fi
        "$TOOLCHAIN_DIR/bin/janet" test/runner.janet "$@" || rc=$?
        ;;
    *)
        "$@" || rc=$?
        ;;
esac

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
