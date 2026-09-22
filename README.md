# MikroTikPatch

Patch RouterOS v7 CHR images with custom keys.

## Differences vs [elseif/MikroTikPatch](https://github.com/elseif/MikroTikPatch)

- Fully open source, no pre-compiled binaries, no password protected ZIPs, etc.
- Possible to run locally (because everything is open source)
- No shell access (massive security hole IMO)
- Physical Reboot required to activate feature flags (another massive security hole IMO)
- No third party cloud connectivity (because who knows what's running there. Manual updates still work)

Why am I not publishing keys? So that in the rare case you trust me (and github actions),
you can still have a relatively secure system with minimal effort.
If you don't tryst me, it's very easy to generate your own keys and builds.
There is no benefit in releasing the keys, the keygen already runs automatically.

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

## patch-v7 options

```
--version <x.y.z>          RouterOS version (required)
--archs x86,arm64          comma list, or "all" (default all)
--buildtime <seconds>      custom build time (default: original)
--keys-file <path>         key material file (default keys.env)
--build-dir <path>         scratch directory (default /tmp/build)
--publish-dir <path>       output directory (default ./publish)
--boot-test                boot each image in qemu and check the licence
--boot-test-timeout <s>    per-image timeout, seconds or duration (default 600)
--legacy-bios              also build the x86 legacy-BIOS image
--skip-keygen              do not rebuild keygen_x86/keygen_arm64
--jobs <n>                 parallel CPU workers (default min(NumCPU,8))
```

## Automated releases

One-time setup:

1. Fork the repo, enable actions.
2. Generate the key set and keep it forever: `./mikrotikpatch genkeys --out keys.env`
3. Store the complete contents of `keys.env` in a repository secret named `KEYS_ENV`.
4. Optional: set the repository variable `ROUTEROS_CHANNEL` to `long-term`,
   `testing` or `development` to change the channel the hourly check uses
   (default `stable`).

## AI disclosure

This whole thing has been reverse engineered and re-written by DeepSeek V4.1 Flash.
While I do know what I'm doing, and could do this myself, I don't have this much free time for a side project made only because I hate fake "open source" projects.
While reverse engineering the original MikroTikPatch I didn't find any evidence of a backdoor, but I would still rather use this 
truly open slop than trust the random chinese dude won't add anything extra to the encrypted zip in the future.