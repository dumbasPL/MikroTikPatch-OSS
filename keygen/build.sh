#!/bin/sh
# Build the keygen binaries from keygen.c: statically linked musl, no other
# dependencies.
#
#   keygen_x86    32-bit i386 ELF   (RouterOS x86)
#   keygen_arm64  aarch64 ELF       (RouterOS arm64)
#   keygen_host   x86_64 ELF        (local testing only)
#
# Usage:
#   build.sh            build keygen_x86 and keygen_arm64 (default)
#   build.sh x86        build only keygen_x86
#   build.sh arm64      build only keygen_arm64
#   build.sh host       build only keygen_host
#   build.sh all        same as no arguments
#
# Only the toolchains for the requested targets are needed: an x86-only build
# never looks for an aarch64 compiler, and an arm64-only build never boots the
# i386 toolchain.
#
# The licence key pair is baked in at compile time from
# CUSTOM_LICENSE_PUBLIC_KEY / CUSTOM_LICENSE_PRIVATE_KEY (32-byte little-endian
# hex, as `mikrotikpatch genkeys` emits them).  When they are unset the key
# recovered from the shipped keygen is used.
#
# Toolchains (override with CC_X86 / CC_ARM64 / CC_HOST):
#   x86    i486-linux-musl-gcc / i686-linux-musl-gcc, or the local toolchain
#          built by tools/musl_i386.sh (run automatically when no i386 musl
#          compiler is in PATH)
#   arm64  aarch64-linux-musl-gcc, or the local toolchain built by
#          tools/musl_aarch64.sh (run automatically when no aarch64 musl
#          compiler is in PATH)
#   host   musl-gcc
set -e
cd "$(dirname "$0")"

ROOT=$(cd .. && pwd)
TOOLCHAIN="$ROOT/.toolchain"
STUBS="$TOOLCHAIN/stubs"

CFLAGS="-std=gnu11 -Os -static -s -fno-pie -no-pie -fno-stack-protector"

# ---- targets --------------------------------------------------------------
BUILD_X86=0
BUILD_ARM64=0
BUILD_HOST=0

if [ $# -eq 0 ]; then
    BUILD_X86=1
    BUILD_ARM64=1
fi
for arg in "$@"; do
    case "$arg" in
        x86|i386|i486|i686) BUILD_X86=1 ;;
        arm64|aarch64)      BUILD_ARM64=1 ;;
        host)               BUILD_HOST=1 ;;
        all)                BUILD_X86=1; BUILD_ARM64=1 ;;
        *)
            echo "unknown argument: $arg" >&2
            echo "usage: $0 [x86] [arm64] [host]" >&2
            exit 2
            ;;
    esac
done
if [ "$BUILD_X86" -eq 0 ] && [ "$BUILD_ARM64" -eq 0 ] && [ "$BUILD_HOST" -eq 0 ]; then
    echo "nothing to build" >&2
    exit 2
fi

# ---- key material ---------------------------------------------------------
DEFS=""
if [ -n "$CUSTOM_LICENSE_PUBLIC_KEY" ]; then
    DEFS="$DEFS -DKEYGEN_LICENSE_PUBLIC_HEX=\"$CUSTOM_LICENSE_PUBLIC_KEY\""
fi
if [ -n "$CUSTOM_LICENSE_PRIVATE_KEY" ]; then
    DEFS="$DEFS -DKEYGEN_LICENSE_PRIVATE_HEX=\"$CUSTOM_LICENSE_PRIVATE_KEY\""
fi

find_x86_cc() {
    for c in "${CC_X86:-}" i486-linux-musl-gcc i686-linux-musl-gcc \
             i386-linux-musl-gcc "$TOOLCHAIN/i386-musl/bin/musl-gcc"; do
        [ -n "$c" ] || continue
        if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
    done
    return 1
}

find_arm_cc() {
    for c in "${CC_ARM64:-}" aarch64-linux-musl-gcc \
             "$TOOLCHAIN/aarch64-musl/bin/musl-gcc"; do
        [ -n "$c" ] || continue
        if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
    done
    return 1
}

# Some distributions (Arch) patch gcc to link -latomic_asneeded, which is not
# available for cross/64-bit targets.  An empty archive satisfies the link and
# is ignored by toolchains that do not ask for it.
make_stubs() {
    mkdir -p "$STUBS"
    [ -f "$STUBS/libatomic_asneeded.a" ] || ar rcs "$STUBS/libatomic_asneeded.a"
}

# ---- x86 ------------------------------------------------------------------
if [ "$BUILD_X86" -eq 1 ]; then
    X86_CC=$(find_x86_cc || true)
    if [ -z "$X86_CC" ]; then
        echo "==> no i386 musl compiler in PATH; building one (tools/musl_i386.sh)"
        sh "$ROOT/tools/musl_i386.sh"
        X86_CC=$(find_x86_cc || true)
    fi
    if [ -z "$X86_CC" ]; then
        echo "ERROR: no i386 musl compiler found (set CC_X86)" >&2
        exit 1
    fi
    echo "==> keygen_x86   ($X86_CC)"
    $X86_CC $CFLAGS $DEFS -Wl,-m,elf_i386 -o keygen_x86 keygen.c
fi

# ---- arm64 ----------------------------------------------------------------
if [ "$BUILD_ARM64" -eq 1 ]; then
    ARM_CC=$(find_arm_cc || true)
    if [ -z "$ARM_CC" ]; then
        echo "==> no aarch64 musl compiler in PATH; building one (tools/musl_aarch64.sh)"
        sh "$ROOT/tools/musl_aarch64.sh"
        ARM_CC=$(find_arm_cc || true)
    fi
    if [ -z "$ARM_CC" ]; then
        echo "ERROR: no aarch64 musl compiler found (set CC_ARM64)" >&2
        exit 1
    fi
    make_stubs
    echo "==> keygen_arm64 ($ARM_CC)"
    $ARM_CC $CFLAGS $DEFS -L"$STUBS" -o keygen_arm64 keygen.c
fi

# ---- host -----------------------------------------------------------------
if [ "$BUILD_HOST" -eq 1 ]; then
    HOST_CC=${CC_HOST:-musl-gcc}
    make_stubs
    echo "==> keygen_host  ($HOST_CC)"
    $HOST_CC $CFLAGS $DEFS -L"$STUBS" -o keygen_host keygen.c
fi

echo "built:"
BUILT=""
[ "$BUILD_X86" -eq 1 ] && BUILT="$BUILT keygen_x86"
[ "$BUILD_ARM64" -eq 1 ] && BUILT="$BUILT keygen_arm64"
[ "$BUILD_HOST" -eq 1 ] && BUILT="$BUILT keygen_host"
ls -l $BUILT
file $BUILT 2>/dev/null || true
