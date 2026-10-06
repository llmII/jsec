#!/bin/sh
# The launcher establishes the environment; the real binaries are private.
set -eu

PREFIX=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

unset JANET_PATH JANET_MODPATH JANET_HEADERPATH JANET_LIBPATH \
      JANET_BINPATH JANET_BUILDPATH JANET_MANPATH JANET_TREE

PATH="$PREFIX/bin:$PATH"
export PATH

exec "$PREFIX/libexec/janet" "$PREFIX/libexec/jpm" "$@"
