# The `upgrade.mikrotik.com` API

Reverse-engineered from the RouterOS 7.24.4 x86 build (`/nova/bin/sys2` of the
patched `routeros-7.24.4.npk` in `publish/`) and cross-checked against the live
server.  `sys2` is the only binary in the squashfs that references the upgrade
host; the HTTP client itself lives in `/lib/libumsg.so`.

## TL;DR

The whole API is a set of read-only `GET`s to static files: one tiny version
pointer per major/channel, a changelog, a package index CSV and the NPK blobs.
There is no authentication, no POST, and no server-side computation — the
router compares the returned version with its own.  **It can be served from a
plain static site** (see the assessment at the end).

## Endpoints

### 1. Update check

```
GET /routeros/NEWESTa<major>.<channel>?version=<installed-version>
Host: upgrade.mikrotik.com
```

Response body (`text/plain`, 18 bytes for 7.24.4):

```
7.24.4 1789558341
```

* `<major>` is the major number of the **installed** version (currently `6` or
  `7`), taken from the packed version field in `sys2`.
* `<channel>` is one of `long-term`, `stable`, `testing`, `development`; the
  dot between major and channel is literal.  Unknown combinations (e.g.
  `NEWESTa7.foo`, `NEWESTa8.stable`) return 404.
* The second token is a Unix build timestamp; the router stores it and shows it
  as the release date.
* `?version=` is sent by the router but **ignored by the server**: `7.0.0`,
  `99.0`, `garbage` and no query at all all returned the identical body
  (verified 2026-09-21).  This is what makes the endpoint trivially static.

Current response matrix at the time of writing:

| path | body |
|---|---|
| `NEWESTa6.long-term` | `6.49.22 1789563951` |
| `NEWESTa6.stable` | `6.49.22 1789563951` |
| `NEWESTa6.testing` | `7.23.7 1789561155` |
| `NEWESTa6.development` | `7.23.7 1789561155` |
| `NEWESTa7.long-term` | `7.23.7 1789561155` |
| `NEWESTa7.stable` | `7.24.4 1789558341` |
| `NEWESTa7.testing` | `7.24.4 1789558341` |
| `NEWESTa7.development` | `7.25beta5 1789557101` |

### 2. Changelog

```
GET /routeros/<version>/CHANGELOG
```

Plain text, displayed by the router when an update is available.

### 3. Package index

```
GET /routeros/<version>/packages.csv
```

CSV with a header line and one row per component package:

```
arch,name,size
x86,calea,24721
arm64,container,1187985
...
```

`arch` values are the RouterOS architecture names (`x86`, `arm`, `arm64`,
`mipsbe`, `mmips`, `ppc`, `tile`); the router filters rows by its own arch,
uses `size` for the disk-space check / progress display and `name` to build
download filenames.  The main `routeros` package is not listed — it is always
downloaded separately.  This endpoint is **v7-only**: the 6.49.22 `sys2`
contains no reference to it.

### 4. Package download

```
GET /routeros/<version>/<bundle>-<version>[-<arch>].npk
```

* v7.x main package: `routeros-<version>[-<arch>].npk` with no suffix for x86
  (`routeros-7.24.4.npk`, `routeros-7.24.4-arm64.npk`, ...); components:
  `<name>-<version>[-<arch>].npk` (`calea-7.24.4.npk`,
  `wifi-qcom-7.24.4-arm64.npk`).
* v6.x (`version <= 0x6ffffff`) uses the older layout: main package
  `routeros-<arch>-<version>.npk` (`routeros-arm-6.49.22.npk`) and components
  `<name>-<version>-<arch>.npk` (`calea-6.49.22-arm.npk`), both verified live.
* Downloads are resumable: the client sends `Range: bytes=<offset>-` and the
  stock server answers `206` with `Accept-Ranges: bytes`.

## How the router builds the requests (evidence)

Strings in `sys2` (file offsets; vaddr = offset + `0x8048000` and `.rodata`
starts at `0x8084000`):

| offset | string |
|---|---|
| `0x3cd57` | `upgrade.mikrotik.zzz` (patched in place from `upgrade.mikrotik.com`) |
| `0x4201c`-`0x4203b` | `long-term`, `stable`, `testing`, `development` |
| `0x42041` | `NEWESTa` |
| `0x42049` | `/routeros/%s?version=%s` |
| `0x4212f` / `0x4213a` | `/routeros/` / `/CHANGELOG` |
| `0x4235a` | `/packages.csv` |
| `0x41ba1` / `0x41bb4` | `routeros-%s-%s.npk` / `%s-%s%s.npk` |

The 6.49.22 ARM `sys2` uses the same scheme with a single pre-composed format
string: `/routeros/NEWESTa%d.%s?version=%s` (major, channel, installed
version), and the same four channel names.

Code paths:

* `0x806442c` builds the check URL: picks the channel name by an enum,
  converts the byte at `+0xcb` (the major byte of the packed version at
  `+0xc8`) to decimal, concatenates `"NEWESTa" + major + "." + channel`, then
  `snprintf("/routeros/%s?version=%s", path, version2string(installed))`.
* `0x8064ad8` parses the check reply: splits the body on the first space,
  keeps the prefix as the latest version (trimmed of `\n\r`), `atoi()`s the
  remainder as the build timestamp.
* `0x8064eaf` fetches the changelog, `0x8065f08` the CSV, `0x80650f3` /
  `0x80657fd` the NPK blobs — all against the same host string.
* `lib/libumsg.so` sends `GET <path> HTTP/1.1`, `Host:`, `Connection: close`,
  `User-Agent: RouterOS <version>` and `Range: bytes=<n>-` on resume.  It sends
  no `Accept-Encoding`, no cookies and no auth.

## Assessment: serving it from a static site

Yes — the API is a perfect fit for a static host/CDN.  The only mutable files
are the `NEWESTa<major>.<channel>` pointers; everything else is immutable,
version-addressed content.

Requirements / caveats:

* **Serve at the domain root.**  The host is patched in place, so the path
  prefix `/routeros/...` is hard-coded; the site cannot live under a sub-path.
* **HTTPS with a valid certificate.**  The scheme is hard-coded `https`.  Any
  public-CA static host works; the hostname must be exactly 20 characters long
  because the replacement is in-place (`upgrade.mikr.invalid`, the host
  genkeys emits, is 20 characters like the stock host).
* **One pointer file per supported major/channel.**  A router on 7.x asks for
  `NEWESTa7.<channel>`; a 6.x router asks for `NEWESTa6.<channel>`.  The file
  is a single line: `<version> <unix-timestamp>\n`.
* **Regenerate `packages.csv`.**  Re-signing and re-packing NPKs changes file
  sizes, so the stock CSV no longer matches (e.g. arm64 `calea`:
  20625 → 24721, x86 `container`: 1175697 → 1163409).  The router only uses
  these numbers for the free-space estimate and progress bar, but writing the
  patched sizes keeps them honest.
* **Range support is recommended** (resume of ~20 MB `routeros` downloads);
  every mainstream static host (S3/CloudFront, Cloudflare, Netlify, GitHub
  Pages, nginx) supports it.  Without it, downloads just restart from zero.
* **No redirects, no SPA fallback.**  The router parses the body blindly; a
  host that redirects unknown paths to an HTML index would feed garbage to the
  version parser.  Missing paths should return a plain 404.
* **Volume limits** are the only real constraint: the main NPK is ~20 MB and a
  full per-arch package set is ~60-80 MB, so hosts with hard site-size caps
  need pruning to the desired versions/architectures.

A minimal tree built from this repo's `publish/` output:

```
routeros/
├── NEWESTa6.stable            # "6.49.22 1789563951\n"
├── NEWESTa7.stable            # "7.24.4 1789558341\n"
├── NEWESTa7.long-term
├── NEWESTa7.testing
├── NEWESTa7.development
└── 7.24.4/
    ├── CHANGELOG              # copied from publish/7.24.4/CHANGELOG
    ├── packages.csv           # stock CSV with patched sizes substituted
    ├── routeros-7.24.4.npk    # patched + re-signed
    ├── calea-7.24.4.npk
    └── ...                    # every other published *.npk
```

This was validated with a local static tree served by `python3 -m http.server`:
the check request (including `?version=7.10.2`), the changelog, the CSV and
the NPK downloads all resolved to plain files; unknown channel names returned
404, matching the stock server.
