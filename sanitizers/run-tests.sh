#!/bin/sh
# Run jsec tests with ALL sanitizers enabled
# Usage: ./sanitizers/run-tests.sh [test-runner-args...]
#
# Requires library built with: JSEC_DEBUG=1 JSEC_ASAN=1 JSEC_UBSAN=1 jpm build && jpm install
#
# For individual sanitizers, use:
#   ./sanitizers/run-with-asan.sh   - AddressSanitizer only
#   ./sanitizers/run-with-ubsan.sh  - UndefinedBehaviorSanitizer only

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Find libasan.so for preload (ASan requires this)
LIBASAN=$(gcc -print-file-name=libasan.so 2>/dev/null)
if [ "$LIBASAN" != "libasan.so" ] && [ -n "$LIBASAN" ]; then
    export LD_PRELOAD="$LIBASAN"
fi

# Set all sanitizer options
export ASAN_OPTIONS="suppressions=$SCRIPT_DIR/asan.supp:detect_leaks=0:halt_on_error=0:print_stacktrace=1:fast_unwind_on_malloc=0"
export UBSAN_OPTIONS="suppressions=$SCRIPT_DIR/ubsan.supp:halt_on_error=0:print_stacktrace=1"
export LSAN_OPTIONS="suppressions=$SCRIPT_DIR/lsan.supp"

cd "$PROJECT_DIR"
exec janet test/runner.janet "$@"
