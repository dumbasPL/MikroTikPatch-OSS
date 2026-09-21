#!/bin/sh
# Build a minimal aarch64 musl toolchain for the keygen (static libc only).
#
# musl compiles its own libc, so the only requirements are a cross compiler
# and binutils for aarch64.  The result is installed under
# .toolchain/aarch64-musl and picked up automatically by keygen/build.sh.
#
# Usage: tools/musl_aarch64.sh [musl-version]   (default 1.2.6)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${1:-1.2.6}
PREFIX="$ROOT/.toolchain/aarch64-musl"
CACHE="$ROOT/.toolchain/cache"
SRC="$ROOT/.toolchain/musl-$VERSION-aarch64"

find_cc() {
    for c in "${CC_AARCH64:-}" aarch64-linux-gnu-gcc; do
        [ -n "$c" ] || continue
        if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
    done
    return 1
}

CC_AARCH64=$(find_cc || true)
if [ -z "$CC_AARCH64" ]; then
    echo "ERROR: no aarch64 cross compiler found (set CC_AARCH64)" >&2
    echo "       Debian/Ubuntu: apt install gcc-aarch64-linux-gnu" >&2
    echo "       Arch:          pacman -S aarch64-linux-gnu-gcc" >&2
    echo "       (an aarch64-linux-musl-gcc in PATH is used directly and" >&2
    echo "        does not need this script)" >&2
    exit 1
fi
case "$("$CC_AARCH64" -dumpmachine 2>/dev/null)" in
    aarch64*) ;;
    *) echo "ERROR: $CC_AARCH64 does not target aarch64" >&2; exit 1 ;;
esac

mkdir -p "$CACHE"
TARBALL="$CACHE/musl-$VERSION.tar.gz"
if [ ! -f "$TARBALL" ]; then
    echo "==> downloading musl-$VERSION"
    wget -nv -O "$TARBALL" "https://musl.libc.org/releases/musl-$VERSION.tar.gz"
fi

rm -rf "$SRC" "$PREFIX"
mkdir -p "$SRC"
tar -xzf "$TARBALL" -C "$SRC" --strip-components=1

echo "==> building musl-$VERSION for aarch64 (static)"
cd "$SRC"
CC="$CC_AARCH64" ./configure --target=aarch64-linux-musl --prefix="$PREFIX" \
    --disable-shared >/dev/null
make -j"$(nproc)" CROSS_COMPILE= AR=ar RANLIB=ranlib >/dev/null
make install CROSS_COMPILE= AR=ar RANLIB=ranlib >/dev/null

# musl installs a wrapper that calls the compiler it was built with; write our
# own so a custom CC_AARCH64 keeps working and the specs path is always right.
cat > "$PREFIX/bin/musl-gcc" <<EOF
#!/bin/sh
exec $CC_AARCH64 "\$@" -specs "$PREFIX/lib/musl-gcc.specs"
EOF
chmod +x "$PREFIX/bin/musl-gcc"

# Some distributions link -latomic_asneeded; an empty archive keeps that happy.
ar rcs "$PREFIX/lib/libatomic_asneeded.a"

echo "==> installed: $PREFIX/bin/musl-gcc"
