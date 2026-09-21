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
  `x86` needs a host `gcc` with 32-bit support; `arm64` needs an aarch64
  cross compiler (`gcc-aarch64-linux-gnu` on Debian/Ubuntu, the
  `aarch64-linux-gnu-gcc` package on Arch). The musl toolchains are built on
  demand by `tools/musl_i386.sh` and `tools/musl_aarch64.sh`; an
  `aarch64-linux-musl-gcc` already in `PATH` is used as-is. The pipeline
  calls `keygen/build.sh [x86] [arm64] [host]` for the requested
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

## Automated releases

`.github/workflows/check-release.yml` runs hourly and on demand. On a schedule
it asks `upgrade.mikrotik.com` for the newest RouterOS version on the release
channel and compares it with the releases in this repository. When the version
is new (and no release tagged `v<version>` exists yet) it calls
`.github/workflows/build-release.yml`, which patches both architectures,
boot-tests the CHR images in QEMU and publishes a release: the body contains
the upstream changelog and the assets are the CHR images
(`chr-*.img.zip`), the main packages
(`routeros-<version>[-<arch>].npk`) and the package archives
(`all_packages-<arch>-<version>.zip`). Beta and rc versions are marked as
pre-releases.

Manual runs (**Actions → Check for new RouterOS releases → Run workflow**)
build the latest or a specific version and upload the result as workflow
artifacts; tick `create_release` to publish a release instead. Every image is
boot tested before it is published (`boot_test`, on by default; hosted runners
have no KVM, so the emulated boot tests are slow). The same inputs are
available when running **Build patched RouterOS release** directly.

One-time setup:

1. Generate the key set and keep it forever:
   `./mikrotikpatch genkeys --out keys.env`
2. Store the complete contents of `keys.env` in a repository secret named
   `KEYS_ENV` (the build refuses to run without it). Every patched device
   trusts these keys, so regenerating them invalidates all previous releases.
3. Optional: set the repository variable `ROUTEROS_CHANNEL` to `long-term`,
   `testing` or `development` to change the channel the hourly check uses
   (default `stable`).

GitHub disables scheduled workflows after 60 days without repository activity;
re-enable the schedule from the Actions tab if that happens.
