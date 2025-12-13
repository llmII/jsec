#!/bin/sh
# Run jsec code with UndefinedBehaviorSanitizer
# Usage: ./sanitizers/run-with-ubsan.sh janet script.janet [args...]
#        ./sanitizers/run-with-ubsan.sh test [test-runner-args...]
#
# Requires library built with: JSEC_DEBUG=1 JSEC_UBSAN=1 jpm build && jpm install
#
# NOTE: When the library is compiled with -fsanitize=undefined, UBSan is built
# into the .so files directly. We just need to set UBSAN_OPTIONS for runtime
# behavior. LD_PRELOAD is NOT needed and can actually break module loading.

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# UBSan options - suppress OpenSSL issues, continue on error
export UBSAN_OPTIONS="suppressions=$SCRIPT_DIR/ubsan.supp:halt_on_error=0:print_stacktrace=1"

cd "$PROJECT_DIR"

case "$1" in
    test)
        shift
        exec janet test/runner.janet "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
