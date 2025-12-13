#!/bin/bash
set -e

# ==============================================================================
# JSEC Static ASan Build Script
# ==============================================================================
# This script builds a fully static, AddressSanitizer-enabled environment for
# testing jsec. It avoids LD_PRELOAD issues by compiling everything (OpenSSL,
# Janet, and jsec) from source with consistent sanitizer flags.
# ==============================================================================

# --- Configuration ---
JANET_VERSION="1.40.1"
JANET_URL="https://github.com/janet-lang/janet/archive/refs/tags/v${JANET_VERSION}.tar.gz"

# Use OpenSSL 3.x as per project requirements
OPENSSL_VERSION="3.4.0"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

# JPM tag (for bootstrapping)
JPM_TAG="v1.1.0"
JPM_URL="https://github.com/janet-lang/jpm/archive/refs/tags/${JPM_TAG}.tar.gz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRATCH_DIR="${SCRIPT_DIR}/scratch"
JSEC_ROOT="$(dirname "$(dirname "${SCRIPT_DIR}")")/jsec"

# Compiler selection
CC=${CC:-cc}
CXX=${CXX:-c++}

echo "=== Building with ${CC} ==="

# Create scratch area
mkdir -p "${SCRATCH_DIR}"
cd "${SCRATCH_DIR}"

# --- 1. Build OpenSSL (Static + ASan) ---
if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    curl -L -o "openssl.tar.gz" "${OPENSSL_URL}"
    tar xf "openssl.tar.gz"
fi

# Determine OpenSSL install path for this compiler
OSSL_INSTALL="${SCRATCH_DIR}/openssl-install-${CC##*/}"

if [ ! -f "${OSSL_INSTALL}/lib64/libssl.a" ] && [ ! -f "${OSSL_INSTALL}/lib/libssl.a" ]; then
    echo "Building OpenSSL..."
    cd "openssl-${OPENSSL_VERSION}"
    
    # Clean previous builds
    make clean || true
    
    # Configure
    # no-shared: static libs only
    # -fsanitize=address: enable ASan
    # -g -O1: debug info, reasonable opt
    ./config no-shared -fsanitize=address -g -O1 -fno-omit-frame-pointer \
             --prefix="${OSSL_INSTALL}" \
             --openssldir="${OSSL_INSTALL}/ssl" \
             CC="${CC}" CXX="${CXX}"

    make -j$(nproc)
    make install_sw # install software only (skip docs)
    cd ..
fi

# Find lib dir (lib or lib64)
if [ -d "${OSSL_INSTALL}/lib64" ]; then
    OSSL_LIB="${OSSL_INSTALL}/lib64"
else
    OSSL_LIB="${OSSL_INSTALL}/lib"
fi
OSSL_INC="${OSSL_INSTALL}/include"

echo "OpenSSL ready at ${OSSL_INSTALL}"

# --- 2. Build Janet (Static + ASan) ---
if [ ! -d "janet-${JANET_VERSION}" ]; then
    echo "Downloading Janet ${JANET_VERSION}..."
    curl -L -o "janet.tar.gz" "${JANET_URL}"
    tar xf "janet.tar.gz"
fi

JANET_INSTALL="${SCRATCH_DIR}/janet-install-${CC##*/}"

if [ ! -f "${JANET_INSTALL}/bin/janet" ]; then
    echo "Building Janet..."
    cd "janet-${JANET_VERSION}"
    
    make clean || true
    
    # Inject ASan flags
    # We use the same flags as OpenSSL to ensure ABI compatibility
    make -j$(nproc) \
        CC="${CC}" \
        CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address" \
        PREFIX="${JANET_INSTALL}"
        
    make install
    cd ..
fi

JANET_BIN="${JANET_INSTALL}/bin/janet"
JANET_INC="${JANET_INSTALL}/include"
echo "Janet ready at ${JANET_BIN}"

# --- 3. Bootstrap JPM ---
# We need jpm to install dependencies and build jsec.
# We'll install a local jpm using our custom janet.

JPM_INSTALL="${SCRATCH_DIR}/jpm-install-${CC##*/}"
mkdir -p "${JPM_INSTALL}"

if [ ! -f "${JPM_INSTALL}/bin/jpm" ]; then
    echo "Bootstrapping JPM..."
    if [ ! -d "jpm-${JPM_TAG#v}" ]; then
        curl -L -o "jpm.tar.gz" "${JPM_URL}"
        tar xf "jpm.tar.gz"
    fi
    
    cd "jpm-${JPM_TAG#v}"
    
    # Install jpm into our local directory
    "${JANET_BIN}" bootstrap.janet "${JPM_INSTALL}"
    cd ..
fi

JPM_BIN="${JPM_INSTALL}/bin/jpm"
echo "JPM ready at ${JPM_BIN}"

# --- 4. Setup Project Environment ---
# We want to build jsec using our custom tools.
# We'll use a separate tree for this build to not pollute the main project.

BUILD_TREE="${SCRATCH_DIR}/jsec-build-${CC##*/}"
mkdir -p "${BUILD_TREE}"

# Copy jsec source to build tree to avoid messing up source dir
# (Optional, but safer. For now we build IN source but use local tree)
cd "${JSEC_ROOT}"

# Install dependencies (spork, etc) into a local tree specific to this build
echo "Installing dependencies..."
# We set JANET_HEADERPATH to point to our custom janet headers
# We set JPM_TREE to our local build tree
export JANET_HEADERPATH="${JANET_INC}"
export JANET_LIBPATH="${JANET_INSTALL}/lib"
export JANET_TREE="${BUILD_TREE}"
export JANET_PATH="${BUILD_TREE}/lib"

# Configure flags for jpm to use our static OpenSSL
export CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer -I${OSSL_INC} -I${JANET_INC}"
export LDFLAGS="-fsanitize=address -L${OSSL_LIB}"

# Install deps declared in project.janet
"${JPM_BIN}" install --local

# --- 5. Build JSEC ---
echo "Building JSEC..."

# Enable ASan build mode in project.janet (adds extra flags)
export JSEC_ASAN=1
export JSEC_DEBUG=1

# Force rebuild
"${JPM_BIN}" clean
"${JPM_BIN}" build --local

echo "Build complete."

# --- 6. Run Tests ---
echo "Running Tests..."

# We need to tell the loader where to find:
# 1. Our built modules (in $BUILD_TREE)
# 2. OpenSSL libs (if they were shared, but they are static so it's fine)
# 3. ASan runtime (linked into executable)

# Configure test filter if not provided
export JSEC_TEST_FILTER="${JSEC_TEST_FILTER:-TLS}" # Default to TLS suite to save time
# export JSEC_TEST_FILTER="" # Uncomment to run all

# Run the runner using our CUSTOM janet
# We must add our build tree to syspath
"${JANET_BIN}" -p "${BUILD_TREE}" test/runner.janet

echo "Done."