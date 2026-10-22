<!--
SPDX-FileCopyrightText: 2026 The ULAI contributors

SPDX-License-Identifier: CC0-1.0
-->

# Signed AppImage fixtures

Small AppImages built with the **real tools**, so that `ulai verify` is
tested against what publishers actually produce (SPEC §3.2, ADR-016). Real
apps are never committed; they are fetched by hand into `~/.cache`.

| File | Built with | Signature |
|---|---|---|
| `upstream-rsa3072.AppImage` | upstream `appimagetool --sign` | embedded, RSA-3072, text (0x01), SHA-512 |
| `upstream-ed25519.AppImage` | upstream `appimagetool --sign` | embedded, Ed25519 (legacy EdDSA), text, SHA-512 |
| `goappimage-rsa3072.AppImage` | go-appimage `appimagetool` | embedded, RSA-3072, binary (0x00), SHA-256 |
| `elf32-rsa3072.AppImage` | upstream `appimagetool --sign` with `--runtime-file runtime-i686` (`ARCH=i686`) | embedded, RSA-3072 (`elf32.pub.asc`), text, SHA-512; an **ELF32** runtime |
| `legacy-unsigned.AppImage` + `.sig` | upstream `appimagetool`, then `gpg --detach-sign` | detached (ADR-016), RSA-3072, binary, SHA-512 |

The first three contain `/.ulai/manifest.json` (ULAI files). The legacy
file has no manifest. `rsa3072.pub.asc` and `ed25519.pub.asc` are the
public keys; `fingerprints.txt` lists them. The private keys existed only in
the build VM's temporary GnuPG home and were deleted.

## How they were made

Built on 2026-10-22 inside a disposable Ubuntu 26.04 VM, as an unprivileged
user, so that no third-party binary ran on a developer machine:

```
scripts/vm-run.sh ubuntu-26.04 tests/fixtures/appimage/payload <out-dir>
```

The script is `payload/run.sh`. Keys are random, so a rebuild changes every
file; the tests depend only on the structure.

Tool versions (`versions.txt`):

```
appimagetool: appimagetool, continuous build (git version 854e19e), build 313 built on 2026-10-04 14:58:08 UTC
go-appimagetool: appimagetool version 305
gpg: gpg (GnuPG) 2.4.8
os: "Ubuntu 26.04.1 LTS" 7.0.0-38-generic
```

Tool downloads (`tool-urls.txt`) and their SHA-256 (`tools.sha256`):

```
appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
go-appimagetool https://github.com/probonopd/go-appimage/releases/download/continuous/appimagetool-951-x86_64.AppImage
runtime-x86_64 https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64
95cbe7cce9717fce90c484e34052ee7c7f1d7635b33c12525b4776826a7d29b6  appimagetool
7c974f525d5bcde2712dd080e0b079a6c3802113a337f0ab142522dcefbf452d  go-appimagetool
617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46  runtime-x86_64
```

Exact commands (`commands.txt`):

```
+ ./appimagetool --runtime-file runtime-x86_64 --sign --sign-key 274B98827C6B507E7DE3F1703C63EF189CEBAA76 UlaiDir /tmp/out/upstream-rsa3072.AppImage
+ ./appimagetool --runtime-file runtime-x86_64 --sign --sign-key BBFE415C9B50B9430589F2D0F2E75C54A2005C93 UlaiDir /tmp/out/upstream-ed25519.AppImage
+ ./appimagetool --runtime-file runtime-x86_64 LegacyDir /tmp/out/legacy-unsigned.AppImage
+ gpg --batch --detach-sign -u 274B98827C6B507E7DE3F1703C63EF189CEBAA76 --digest-algo SHA512 -o /tmp/out/legacy-unsigned.AppImage.sig /tmp/out/legacy-unsigned.AppImage
+ (in a git repository with pubkey.asc and privkey.asc at its root) VERSION=1.0 ./go-appimagetool UlaiDir
```

SHA-256 of each fixture (`SHA256SUMS`):

```
84df1dfb472849e14479cafad8d671a5a842696245870109f0b2068adfd3880c  ./ed25519.pub.asc
444d60d7f6e64335146a86321946836aee85670f4117cdc7a615e1dfe2ff0899  ./goappimage-rsa3072.AppImage
85b9807816a8b12265b65693d461cd625606fde46e446b0c1ec16a5cd2b55714  ./legacy-unsigned.AppImage
84749ef8ff953022463b8254a68eaa657bd3a0e40b69051293ec67bd0176a19d  ./legacy-unsigned.AppImage.sig
8a6bdaf1e9b8c422a3e565c16888bf60a007a0a22c2a2db5b31b15edc57fb8c6  ./rsa3072.pub.asc
4c10eb82475b1f618170b34dea8be14f193e1ae3671addb22c9dfda1deb73700  ./upstream-ed25519.AppImage
4a6d218d54235ba8a0bff74f6c12e8a2f8ba4a4e0eeae1e651be310dee8a4577  ./upstream-rsa3072.AppImage
```

### The ELF32 fixture

Built in a second run of the same kind of VM (Ubuntu 26.04, 2026-10-22) with
upstream `appimagetool` (continuous build 313) and
`https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-i686`:

```
ARCH=i686 ./appimagetool --runtime-file runtime-i686 --sign --sign-key <elf32 fingerprint> D elf32-rsa3072.AppImage
```

Its AppDir holds only `AppRun` (a shell script), a desktop entry and a PNG,
written for ULAI (CC0-1.0); it has no manifest.

## Licences

Each AppImage consists of an AppImage **runtime** followed by a SquashFS
image of an AppDir. The AppDir content (a two-line `AppRun` shell script, a
desktop entry, a 1×1 PNG and a manifest) was written for ULAI and is
**CC0-1.0**.

- The upstream runtime (`AppImage/type2-runtime`, used by upstream
  `appimagetool`) is MIT. According to its LICENSE file it statically links
  musl (MIT), libfuse (LGPL-2.1-only: "GNU LGPLv2", without "or later", with
  the 2.1 text), squashfuse (BSD-2-Clause), libzstd (BSD-3-Clause OR
  GPL-2.0-only) and zlib (Zlib).
- go-appimage embeds `runtime-fuse3-x86_64` from `probonopd/static-tools`
  (MIT). It is built from the same runtime source against the same libraries.
  **Not verified** binary by binary.

`REUSE.toml` therefore annotates the AppImages as
`MIT AND LGPL-2.1-only AND BSD-2-Clause AND (BSD-3-Clause OR GPL-2.0-only) AND Zlib AND CC0-1.0`,
and every other file here as CC0-1.0.
