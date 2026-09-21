# MikroTikPatch

Patch RouterOS v7 packages to a custom licence/NPK key set and build bootable
CHR disk images. Everything is built in: no root privileges and no external
tools for downloads, ISO and squashfs handling, filesystems or zip files.

## Build

```sh
go build ./cmd/mikrotikpatch
```

Requirements:

* Go 1.24+ with cgo enabled and a C compiler.
* `liblzma` headers and library (Arch: `xz`; Debian/Ubuntu: `liblzma-dev`).
* For the keygen: only the toolchain of each architecture you build.
  `x86` needs a host `gcc` with 32-bit support (the i486 musl toolchain is
  built on demand); `arm64` needs an aarch64 musl compiler in `PATH`. The
  pipeline calls `keygen/build.sh [x86] [arm64] [host]` for the requested
  architectures only.
* `qemu-system-x86_64` / `qemu-system-aarch64` and UEFI firmware (OVMF /
  QEMU_EFI) only for `--boot-test`.

## Quick start

```sh
# Generate a key set (once).
./mikrotikpatch genkeys --out keys.env

# Patch a version and build the CHR images for both architectures.
./mikrotikpatch patch-v7 --version 7.24.4 --archs all --boot-test --legacy-bios
```

Artifacts land in `publish/<version>/`:

```
routeros-<version>[-<arch>].npk   patched main package
<component>-<version>[-<arch>].npk  re-signed component packages
all_packages-<arch>-<version>.zip   all components of one architecture
chr-<version>[-<arch>][-legacy-bios].img.zip   CHR disk images
```

Architectures, component signing, downloads and boot tests run in parallel.

## patch-v7 options

```
--version <x.y.z>          RouterOS version (required)
--archs x86,arm64          comma list, or "all" (default all)
--buildtime <seconds>      custom build time (default: original)
--keys-file <path>         key material file (default keys.env)
--build-dir <path>         scratch directory (default /tmp/build)
--publish-dir <path>       output directory (default ./publish)
--boot-test                boot each image in qemu and check the licence
--boot-test-timeout <s>    per-image timeout (default 600)
--legacy-bios              also build the x86 legacy-BIOS image
--skip-keygen              do not rebuild keygen_x86/keygen_arm64
--jobs <n>                 parallel CPU workers (default min(NumCPU,8))
```

## Other commands

```sh
./mikrotikpatch genkeys [--out keys.env]
```
