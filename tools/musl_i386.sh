#!/bin/sh
# Build a minimal i486 musl toolchain for the keygen (static libc only).
#
# musl compiles its own libc, so the only requirements are a host compiler that
# can target i386 (gcc -m32, i.e. multilib) plus ar/ranlib.  The result is
# installed under .toolchain/i386-musl and picked up automatically by
# keygen/build.sh.
#
# Usage: tools/musl_i386.sh [musl-version]      (default 1.2.6)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${1:-1.2.6}
PREFIX="$ROOT/.toolchain/i386-musl"
CACHE="$ROOT/.toolchain/cache"
SRC="$ROOT/.toolchain/musl-$VERSION"

command -v gcc >/dev/null 2>&1 || { echo "ERROR: gcc not found" >&2; exit 1; }
if ! printf 'int main(void){return 0;}\n' | gcc -m32 -x c - -o /dev/null 2>/dev/null; then
    echo "ERROR: the host gcc cannot link 32-bit binaries (needs multilib," >&2
    echo "       e.g. gcc-multilib + libc6-dev-i386 on Debian/Ubuntu)" >&2
    exit 1
fi

mkdir -p "$CACHE"
TARBALL="$CACHE/musl-$VERSION.tar.gz"
if [ ! -f "$TARBALL" ]; then
    echo "==> downloading musl-$VERSION"
    wget -nv -O "$TARBALL" "https://musl.libc.org/releases/musl-$VERSION.tar.gz"
fi

rm -rf "$SRC" "$PREFIX"
mkdir -p "$SRC"
tar -xzf "$TARBALL" -C "$SRC" --strip-components=1

echo "==> building musl-$VERSION for i486 (static)"
cd "$SRC"
CC="gcc -m32" ./configure --target=i486-linux-musl --prefix="$PREFIX" \
    --disable-shared >/dev/null
make -j"$(nproc)" CROSS_COMPILE= AR=ar RANLIB=ranlib >/dev/null
make install CROSS_COMPILE= AR=ar RANLIB=ranlib >/dev/null

# musl installs a wrapper that assumes a native compiler; point it at -m32.
# The specs replace GCC's *link spec, which for a 32-bit target also drops the
# linker emulation, so ask for it explicitly.
cat > "$PREFIX/bin/musl-gcc" <<EOF
#!/bin/sh
exec gcc -m32 "\$@" -specs "$PREFIX/lib/musl-gcc.specs" -Wl,-m,elf_i386
EOF
chmod +x "$PREFIX/bin/musl-gcc"

# Some distributions link -latomic_asneeded; an empty archive keeps that happy.
ar rcs "$PREFIX/lib/libatomic_asneeded.a"

echo "==> installed: $PREFIX/bin/musl-gcc"
