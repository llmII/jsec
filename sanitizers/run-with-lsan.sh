#!/bin/sh
# Run jsec code with LeakSanitizer
# Usage: ./sanitizers/run-with-lsan.sh janet script.janet [args...]
#        ./sanitizers/run-with-lsan.sh test [test-runner-args...]
#
# LeakSanitizer is bundled with ASan. This script runs ASan with leak
# detection enabled.
#
# Requires library built with: JSEC_DEBUG=1 JSEC_ASAN=1 jpm build && jpm install
#
# NOTE: ASan (and thus LSan) requires the runtime to be loaded before the program
# starts. Since janet itself isn't compiled with ASan, we must LD_PRELOAD the
# ASan runtime.
# IMPORTANT: Must use the SAME ASan library that was used to compile the jsec
# libraries. By default jpm uses cc/gcc, so we prefer GCC's libasan.

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Find GCC's ASan library (jpm typically uses gcc)
find_asan_lib() {
    # First, try to detect what the library was actually linked against
    if [ -f "$PROJECT_DIR/build/jsec/cert.so" ]; then
        linked=$(ldd "$PROJECT_DIR/build/jsec/cert.so" 2>/dev/null | grep -o '/[^ ]*libasan[^ ]*' | head -1)
        if [ -n "$linked" ] && [ -f "$linked" ]; then
            echo "$linked"
            return 0
        fi
    fi
    
    # Prefer GCC's ASan (jpm default compiler)
    if command -v gcc >/dev/null 2>&1;
 then
        lib="$(gcc -print-file-name=libasan.so 2>/dev/null)"
        if [ -n "$lib" ] && [ "$lib" != "libasan.so" ] && [ -f "$lib" ]; then
            echo "$lib"
            return 0
        fi
    fi
    
    # Fallback to clang
    if command -v clang >/dev/null 2>&1;
 then
        for lib in \
            "$(clang -print-file-name=libclang_rt.asan-x86_64.so 2>/dev/null)" \
            "$(clang -print-file-name=libclang_rt.asan.so 2>/dev/null)"; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                echo "$lib"
                return 0
            fi
        done
    fi
    
    # System paths
    for lib in /usr/lib64/libasan.so* /usr/lib/libasan.so* /usr/lib/x86_64-linux-gnu/libasan.so*; do
        if [ -f "$lib" ]; then
            echo "$lib"
            return 0
        fi
    done
    
    return 1
}

ASAN_LIB=$(find_asan_lib)
if [ -z "$ASAN_LIB" ]; then
    echo "Error: Cannot find ASan library (required for LSan)." >&2
    echo "Make sure you have gcc with ASan support installed." >&2
    exit 1
fi

echo "Using LSan via ASan library: $ASAN_LIB" >&2

# LSAN options - suppress OpenSSL leaks
export LSAN_OPTIONS="suppressions=$SCRIPT_DIR/lsan.supp:print_suppressions=0"
# ASan with leak detection enabled
export ASAN_OPTIONS="suppressions=$SCRIPT_DIR/asan.supp:detect_leaks=1:halt_on_error=0:print_stacktrace=1:fast_unwind_on_malloc=0"
export LD_PRELOAD="$ASAN_LIB"

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