#!/bin/sh
#
# Builds h2o in the MSYS2 "msys" environment and runs the unit tests.
#
# The msys environment is a POSIX emulation layer on Windows (Cygwin). h2o
# needs a few adjustments to build there, and all of them are applied from
# the outside, so that the source tree is not modified:
#
#   -D_GNU_SOURCE             Cygwin hides getaddrinfo() and struct addrinfo
#   -include alloca.h         Cygwin declares alloca() there, not in stdlib.h
#   an empty sys/syscall.h    h2o includes it but uses nothing from it
#   -Dipi_spec_dst=ipi_addr   a Linux-only member of struct in_pktinfo
#
# The packages that the build needs are msys/openssl-devel, msys/zlib-devel
# and msys/cmake; the script says so if they are missing.
#
# The unit tests that fail in this environment fail for reasons of the
# environment and not of the code (they pass in the CI on Linux); they are
# listed in MSYS_EXPECTED_FAILURES below, and a failure that is not on the
# list fails the script.
#
# usage: misc/msys-build.sh [build-directory]

set -e

REPO=$(cd "$(dirname "$0")/.." && pwd)
BUILD_DIR=${1:-/tmp/h2o-build-msys}
UNIT_TESTS="lib/common/serverutil.c lib/file.c issues/293.c src/ssl.c"

# the groups of the unit tests that fail in this environment
MSYS_EXPECTED_FAILURES=${MSYS_EXPECTED_FAILURES:-"$UNIT_TESTS"}

missing=
for p in openssl-devel zlib-devel cmake; do
    pacman -Q "$p" >/dev/null 2>&1 || missing="$missing $p"
done
if [ -n "$missing" ]; then
    echo "missing packages:$missing" >&2
    echo "install them with: pacman -S$missing" >&2
    exit 1
fi

# the shim for the header that h2o includes but does not use
SHIM_DIR="$BUILD_DIR/shim"
mkdir -p "$SHIM_DIR/sys"
cat > "$SHIM_DIR/sys/syscall.h" <<'EOT'
/* empty: h2o includes <sys/syscall.h> but uses nothing from it, and the
   header does not exist on this platform */
EOT

CFLAGS="-D_GNU_SOURCE -include alloca.h -I$SHIM_DIR -Dipi_spec_dst=ipi_addr"

echo "--- configuring ---"
cd "$REPO"
CC=gcc CXX=g++ cmake -S "$REPO" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CFLAGS" >/dev/null

echo "--- building ---"
cd "$BUILD_DIR"
CC=gcc CXX=g++ cmake --build . -j"$(nproc 2>/dev/null || echo 4)" >/dev/null
# the unit tests are a target of their own, and are not part of "all"
CC=gcc CXX=g++ cmake --build . --target t-00unit-evloop.t -j"$(nproc 2>/dev/null || echo 4)" >/dev/null

echo "--- unit tests ---"
H2O_ROOT="$REPO" "$BUILD_DIR/t-00unit-evloop.t.exe" > "$BUILD_DIR/unit.log" 2>&1 || true

failed=$(grep -E '^not ok [0-9]+ - ' "$BUILD_DIR/unit.log" | sed -e 's/^not ok [0-9]* - //' | sort)
unexpected=
for f in $failed; do
    case " $MSYS_EXPECTED_FAILURES " in
        *" $f "*) ;;
        *) unexpected="$unexpected $f" ;;
    esac
done

total=$(grep -cE '^(ok|not ok) [0-9]+ - ' "$BUILD_DIR/unit.log" || true)
echo "$total groups, failing:$failed"
if [ -n "$unexpected" ]; then
    echo "unexpected failures:$unexpected" >&2
    echo "the details are in $BUILD_DIR/unit.log" >&2
    exit 1
fi
echo "the unit tests pass, except for the failures that this environment causes"
