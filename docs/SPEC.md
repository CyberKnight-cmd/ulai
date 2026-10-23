# ULAI Specification — v0.1 (draft)

MUST, SHOULD and MAY are used as in RFC 2119. Items marked **[verify]** must be
confirmed by experiment before this version is frozen; record results in the
experiment log in RESEARCH.md.

## 1. Scope

**In scope:** desktop and command-line applications for Linux, x86_64 first and
aarch64 next, distributed as one file and run without root.

**Out of scope for v0:** kernel modules, drivers, system services, VPN clients
and anything that needs root at runtime. These stay distro packages.

## 2. Terminology

- **ULAI file** — an app file conforming to §3.
- **Legacy AppImage** — an AppImage type 2 without a ULAI manifest.
- **Handler** — `ulai-handler` (GUI) and `ulai` (CLI), the user-facing tools.
- **Launcher** — `ulai-run`, which builds the sandbox and starts the app.
- **Store** — per-user, content-addressed storage of installed apps (§8).
- **Trust level** — Strict, Guarded or Full (§6).
- **Landlock ABI** — the integer returned by
  `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.

## 3. The ULAI file

A ULAI file MUST:

1. Be a valid AppImage type 2: an ELF executable with magic `0x414902` at
   offset 8, followed by an appended filesystem image that its runtime can mount.
2. Use SquashFS for the image (zstd compression RECOMMENDED). Legacy
   AppImages MAY use DwarFS (magic `DWARFS`, used by uruntime/AnyLinux);
   handlers read it in-process (§3.5), but ULAI files themselves stay
   SquashFS.
3. Contain at the image root: `AppRun` (the entry point), exactly one `.desktop`
   file, and an icon, following AppDir conventions.
4. Contain `/.ulai/manifest.json` (§4).
5. Be signed (§3.2). Unsigned files are allowed only as development builds and
   are always treated as Strict by default.

A ULAI file SHOULD use the extension `.ulai`. Handlers MUST NOT rely on the
extension: detection is by AppImage magic plus manifest presence.

### 3.1 Image offset and sections

The image starts where the ELF ends: `offset = e_shoff + e_shentsize × e_shnum`,
which is how AppImage tooling computes it. Verified on four ELF64 runtimes
(upstream type2-runtime, the older AppImageKit runtime, electron-builder's, and
uruntime) and on upstream's ELF32 `runtime-i686`: the filesystem magic sits
exactly at that offset in every file tested (RESEARCH.md, 2026-10-21/22).

- Compute the offset with checked arithmetic; overflow, or an offset past the
  end of the file, makes the file corrupt.
- The filesystem magic (`hsqs` for SquashFS, `DWARFS` for DwarFS) MUST start
  exactly at the offset. Handlers MUST NOT scan for it.
- `.sha256_sig`, `.sig_key`, `.digest_md5` and `.upd_info` MUST each appear at
  most once. Each MUST lie entirely inside the file, MUST NOT overlap another
  section, and MUST NOT overlap the filesystem image. Otherwise the file is
  corrupt.

### 3.2 Signature

- Use the AppImage signature sections. `.sha256_sig` holds an ASCII-armored
  OpenPGP detached signature. `.sig_key` holds the publisher's public key.
  Ed25519 keys are RECOMMENDED.
- **Digest.** SHA-256 over the whole file, with the byte ranges of
  `.sha256_sig` **and** `.sig_key` zero-filled. Zero each section's range
  independently: never assume the two sections are contiguous. `.digest_md5`
  and every other byte are hashed unchanged.
  - *Discrepancy:* the AppImage specification text mentions zeroing only
    `.sha256_sig`. Real tools zero both: go-appimage; AppImageKit's validate
    after the fix for issue #949; Krita's `validate_appimage_signature.sh`.
    ULAI follows the tools.
- **What is signed.** The OpenPGP detached signature covers the digest
  *text*, not the AppImage itself: the 64-character **lowercase hex** SHA-256,
  with **no trailing newline**. Measured (RESEARCH.md, S1):

  | Tool | Signature type | Hash | Keys |
  |---|---|---|---|
  | upstream `appimagetool` (continuous build 313, gpgme, GnuPG 2.4.8) | text (0x01) | SHA-512 | RSA, Ed25519 (legacy EdDSA) |
  | go-appimage `appimagetool` (build 951) | binary (0x00) | SHA-256 | RSA only (its OpenPGP library cannot sign with EdDSA) |
  | Krita's `sign_appimage.sh` | gpg defaults | — | — |

  Handlers MUST accept both signature types. For text signatures,
  canonicalisation changes nothing because the message has no line endings.
- **Signature policy:**
  - Hash algorithms: SHA-256, SHA-384 and SHA-512 are accepted; SHA-1, MD5
    and anything else are rejected.
  - Keys: RSA of at least 2048 bits; Ed25519, both the legacy EdDSA form and
    the RFC 9580 Ed25519 algorithm. Any other algorithm is unsupported.
  - `.sig_key` MUST contain exactly one primary key, and its self-signature
    MUST verify. If a subkey made the signature, its binding signature MUST
    verify and it MUST carry the signing flag.
  - A revoked key makes the signature invalid. An expired key gives a valid
    result with a warning; the pinning policy (M3) decides what to do with it.
  - Fingerprints are always shown in full (v4: 40 hex digits; v6: 64), never
    as short key IDs.
- **Meaning of "valid".** A valid signature only shows that the file was
  signed by the key embedded in it. Trust comes from pinning (below).
- **Independence.** Verification needs only the ELF and its sections, not the
  filesystem reader. It therefore works on every AppImage whose ELF and
  sections parse, including DwarFS ones.
- Verification MUST complete before any other content of the file is trusted or
  displayed, including the manifest and the icon. Content shown from an
  unsigned or invalid file is labelled as not authenticated.
- **OpenPGP semantics are ULAI's job.** rPGP handles packets and cryptography
  and leaves these checks to the application. Each has a test with an
  independently made key:
  - A signing subkey needs a valid subkey binding signature **and** an
    embedded primary-key binding signature (back-signature, type 0x19). A
    signing subkey without one is rejected.
  - A key or subkey revocation signature present in the key makes the result
    invalid.
  - Expiry is judged at the signature's creation time. Expired before
    signing → invalid. Expired since → valid, with a warning.
  - Key flags must allow signing.
  - The algorithm policy above (no SHA-1 or MD5, RSA ≥ 2048 bits) applies to
    self-signatures and binding signatures too, not only to the file
    signature.
  - v5 (LibrePGP) keys and signatures are unsupported.
  - **Signatures from the future.** A signature whose creation time is more
    than 30 minutes after the verifier's clock is rejected (30 minutes is
    Sequoia's `CLOCK_SKEW_TOLERANCE`; up to and including 30 minutes is
    accepted). This applies to every signature relied on: the file
    signature, self-signatures, subkey bindings and back-signatures. A
    future self-signature or binding is not used; if no other valid one
    remains, the result is `signature_from_future` (exit 4). The message
    says how far in the future the signature is and asks the user to check
    the system clock.
  - **Critical subpackets.** RFC 9580 §5.2.3.7: a signature whose *hashed*
    area carries a critical subpacket ULAI does not understand is not used.
    ULAI understands no critical notation (the list of known notations in
    code is empty), so any critical notation counts, as do critical
    subpackets of unknown or experimental type and critical regular
    expressions. On a self-signature or binding this makes the key or
    subkey unusable unless another valid self-signature or binding exists.
    The check is ULAI's own and runs before the cryptography; it does not
    rely on rPGP. Critical subpackets in the unhashed area are not covered
    by the signature, so anyone could add them; they are ignored.
  - **What a signature file or section may contain.** ULAI splits it into
    packets by their own length headers before rPGP sees any of them
    (rPGP's detached-signature parser returns the first signature and never
    reads the rest).
    - Allowed: signature, marker and padding packets, and unknown
      non-critical packet types (40–63), which are skipped with a warning
      (RFC 9580 §4.3). Any other type (literal data, compressed data, keys,
      unassigned critical types, …) is `corrupt`. Partial or indeterminate
      packet lengths are `corrupt`.
    - A signature file: only whitespace before the armor and after its
      footer; for binary, nothing after the last packet. Anything else is
      `corrupt`.
    - `.sha256_sig`: packets are found by their length headers, never by
      trimming zero bytes. After the armor footer's line ending, or after
      the last binary packet, the rest of the section must be zero bytes;
      anything else is `corrupt`. Upstream appimagetool writes a newline
      after the footer and go-appimage writes none; both pass.
    - NUL padding is stripped from keys only after ASCII armor; binary keys
      are read as they are.
  - **Several signatures.** Up to 16 signature packets are allowed; more is
    `corrupt` (this bounds the verification work, since each candidate
    reads the signed data again).
    - The verdict is valid if at least one signature is valid by the
      trusted key (the embedded `.sig_key`, the `--key` file, or from M3
      the pinned key) under every rule above. Order does not matter.
    - Only document signatures count: binary (0x00) and text (0x01), which
      upstream appimagetool produces (S1). Any other type, such as a key
      certification (0x10–0x13), never counts and is reported as
      "ignored: not a document signature".
    - If a signature by the trusted key fails while another one by the same
      key is valid, the result is valid, with a warning.
    - If none is valid, the reported reason is, in this order: the worst
      failure of a signature by the trusted key (invalid, then from the
      future, unsupported, corrupt); else a signature rPGP cannot read
      (`unsupported`); else "made by a key that is not in the supplied key"
      (`invalid`); else "no document signature" (`unsupported`).
    - `--json` lists every signature with its fingerprint (or key id),
      algorithm, type, creation time and status: `valid`, `invalid`,
      `signature_from_future`, `unsupported`, `corrupt`, `unknown_key`,
      `ignored`, or `not_checked` when the trusted key itself is unusable.
      The human output shows the deciding signature and one line counting
      the others.
  - **Data ULAI cannot read is `unsupported`, not `invalid`.** If rPGP
    fails to parse a key or signature whose OpenPGP packet framing is
    intact, and whose first packet (after marker and padding packets) is
    the expected kind (public key or signature), the result is
    `unsupported` (exit 5): it is most likely valid OpenPGP that rPGP
    cannot read yet, for example a certificate with a subkey on an unknown
    curve (rpgp/rpgp#869). ULAI does not filter packets to work around
    this. Broken framing, or the wrong kind of data, is `corrupt` (exit 5).
  - Keys and signatures are limited to 64 KiB each (`unsupported` above
    that). For a `--key` file over the limit, the message suggests
    `gpg --export --export-options export-minimal <fingerprint>`, which
    leaves out third-party certifications.

#### 3.2.1 Detached signatures (legacy AppImages, ADR-016)

- Legacy AppImages without an embedded signature MAY be verified with a
  detached OpenPGP signature over the whole file's bytes, as produced by
  `gpg --detach-sign`. The policy above applies unchanged.
- The signature comes from `--signature <file>`, or from automatic discovery
  of exactly `<file>.sig` or `<file>.asc` in the same directory. Nothing
  else.
- The public key is never fetched from the network (no keyservers, no WKD).
  M1: `--key <file>`. From M3: also ULAI's per-user keyring of pinned keys.
- ULAI files always need their embedded signature; a detached signature next
  to a ULAI file is ignored.
- Results: valid (exit 0, reported as "detached signature, key supplied by
  you" with the full fingerprint); invalid (exit 4) when a key is available
  but verification fails; `signature_unverifiable` (exit 3) when a signature
  is found but no key is available.
- Trust is per app id (trust on first use). The first successfully verified key
  is pinned. Later versions MUST be signed by the pinned key; a different key
  blocks the update and shows the old and new fingerprints.

### 3.3 Update information

`.upd_info` MAY carry update information in the existing AppImage formats (for
example zsync URLs). Downloaded updates MUST pass §3.2 with the pinned key.

### 3.4 Runtime modes

The manifest's `runtime_mode` declares one of:

- **`native`** — the app uses the host's glibc and dynamic loader. No bundled ELF
  file may require a glibc symbol version newer than `glibc_floor`. The graphics
  stack and the libraries on the exclude list (§11.1) come from the host.
- **`portable`** — the app bundles its own dynamic loader and libc
  (sharun-style) and needs nothing from the host except the kernel. GPU comes
  from the shared driver pack (§11.3). This mode arrives in a later milestone.

### 3.5 Reading untrusted files

Applies to every file being inspected, validated, verified or installed.

- Never execute any part of it (AGENTS rule 1). Parse ELF, SquashFS and DwarFS
  in-process.
- Open the file once and read everything, including the digest, through that
  one open file.
- Use checked arithmetic for every offset and size.
- Inside the image, reject `..` components, absolute paths and NUL bytes.
  Symlinks resolve only inside the image: absolute targets resolve against the
  image root, never against the host filesystem. A hop limit turns symlink
  loops into errors.
- Enforce limits on total bytes, file count and compression ratio.
- Do not decode icons before M4; report only their type (by magic) and size.
- **Terminal output.** Every string taken from the file (names, paths,
  manifest fields, desktop-entry fields) is untrusted. Before printing it to
  a terminal, escape C0 and C1 control characters and the Unicode bidi
  controls U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069, so that a
  hostile file cannot fake verdict lines or spoof a fingerprint. JSON output
  stays raw, since JSON escaping already handles it.

## 4. Manifest (`/.ulai/manifest.json`)

```json
{
  "ulai": "0.1",
  "id": "org.example.Downloader",
  "name": "Example Downloader",
  "version": "2.4.1",
  "summary": "Download manager",
  "arch": ["x86_64"],
  "runtime_mode": "native",
  "glibc_floor": "2.28",
  "entry": "AppRun",
  "permissions": ["user-files", "network", "audio", "gpu", "notifications"],
  "sensitive_permissions": [
    { "id": "dotfile", "path": "~/.gitconfig", "kind": "file", "access": "read",
      "reason": "Shows your git name and email in the commit dialog" }
  ],
  "own_paths": ["~/.config/example-downloader", "~/.local/share/example-downloader"],
  "integrations": {
    "mime_types": ["x-scheme-handler/magnet"],
    "autostart": true,
    "native_messaging": [
      { "browser": "chromium-family", "host_manifest": "share/ulai/nm/org.example.downloader.json" },
      { "browser": "firefox", "host_manifest": "share/ulai/nm/org.example.downloader.firefox.json" }
    ]
  },
  "homepage": "https://example.org"
}
```

| Field | Required | Meaning |
|---|---|---|
| `ulai` | yes | Spec version of this manifest |
| `id` | yes | Reverse-DNS app id; SHOULD equal the AppStream id and the `.desktop` basename |
| `name`, `version`, `summary` | yes | Shown on the handler card |
| `arch` | yes | CPU architectures the image supports |
| `runtime_mode` | yes | `native` or `portable` (§3.4) |
| `glibc_floor` | if native | Highest glibc symbol version any bundled ELF needs |
| `entry` | no | Entry point inside the image; defaults to `AppRun` |
| `permissions` | yes | Ordinary permissions (§5.1); may be empty |
| `sensitive_permissions` | no | Objects; each one needs explicit consent (§5.2) |
| `own_paths` | no | Extra per-app directories under `$HOME` (§6.3 rules apply) |
| `integrations` | no | Written by the handler at install, with consent (ADR-011) |

Unknown fields MUST be ignored (forward compatibility). The manifest is at
most 64 KiB; larger files are rejected before parsing. Duplicate keys at any
level are rejected, so that different JSON parsers cannot read the same file
differently. The JSON Schema is published as
`schemas/manifest-0.1.schema.json` (MIT, ADR-015). `ulai validate` MUST
reject unknown permission identifiers, own paths outside `$HOME`, own paths
that equal or contain a protected path (§6.3), own paths that are too broad
(`~`, `~/.config`, `~/.local`, `~/.local/share`, `~/.cache`), and sensitive
permissions that break the rules of §5.2.

## 5. Permissions

### 5.1 Ordinary permissions

| Id | Grants | Strict | Guarded | Enforcement |
|---|---|---|---|---|
| `user-files` | Read/write all non-hidden entries of `$HOME` (except §6.3 exclusions) and removable media | no | yes | Landlock filesystem rules (rename/link control needs `REFER`, ABI ≥ 2; truncation control needs `TRUNCATE`, ABI ≥ 3) |
| `network` | TCP and UDP | no | yes | Network rights left unhandled; denial needs ABI ≥ 4 (TCP) and ≥ 10 (UDP) |
| `gpu` | `/dev/dri/*`, `/dev/nvidia*`, including ioctls | yes | yes | Filesystem rules (+ `IOCTL_DEV`, ABI ≥ 5) |
| `audio` | PipeWire and PulseAudio sockets. **Includes microphone access** (§14 O4) | no | yes | Socket rule (`RESOLVE_UNIX`); denial needs ABI ≥ 9, Linux 7.1+ |
| `notifications` | Notifications service and portal | yes | yes | D-Bus proxy (§7) |
| `system-bus` | System D-Bus (privileged actions remain behind polkit) | no | yes | Socket rule (`RESOLVE_UNIX`); denial needs ABI ≥ 9, Linux 7.1+ |

The Wayland socket is always available. Denying it is meaningless for GUI apps.

ABI numbers refer to the feature table in §6.2.

### 5.2 Sensitive permissions (never granted by default)

Each entry of `sensitive_permissions` is an object with an `id` and a
`reason`. The `reason` is required, says why the app needs the permission,
and is shown in the consent dialog (plain text, at most 300 characters, no
control or bidi characters).

```json
{ "id": "ssh-keys", "reason": "Pushes to your git remotes over SSH" }
{ "id": "dotfile", "path": "~/.gitconfig", "kind": "file", "access": "read",
  "reason": "Shows your git name and email in the commit dialog" }
```

| Id | Grants | Note shown to the user |
|---|---|---|
| `x11` | X11 sockets | X11 lets any app read the keystrokes and windows of other X11 apps |
| `secrets` | Secret Service on the session bus | Can read passwords stored in your keyring |
| `ssh-keys` | Read `~/.ssh` | Can use your SSH identities |
| `dotfile` | One specific hidden path (below) | Shown with the exact path and access |
| `camera` | `/dev/video*` | — |
| `full-home` | Read all of `$HOME`, including hidden files | For backup tools and file managers |

Only `dotfile` takes further fields, and it needs all of them:

- `path`: one hidden entry of the home directory or a path below one,
  written `~/.name[/…]`. It must already be normalised (no `.`, `..` or
  empty components, no trailing `/`) and is literal (no glob characters
  `* ? [ ] { }`).
  - It must not be inside the protected set (§6.3) or contain any part of
    it (so neither `~/.ssh/config` nor `~/.config` is allowed). Protected
    paths are reachable only through their own permissions: `ssh-keys`,
    `secrets` or `full-home`.
- `kind`: `file` or `dir`.
- `access`: `read` or `read-write`.

The same `id`, or the same `dotfile` path, may be listed only once. There is
no string form (`"dotfile:~/.foorc"` is not a permission).

Landlock rules attach to existing inodes, so a missing path needs care:

- `read-write` on a path that does not exist yet: after consent, the
  handler creates it at install time, as an empty file or a `0700`
  directory, depending on `kind`. Uninstalling leaves it in place, because
  it may hold the user's data by then.
- `read` on a path that does not exist: no rule is added. If the path
  appears later, the app gets access only after the next launch.

Integrations (`autostart`, `native_messaging`, `mime_types` that would replace
an existing default) are consented at install and written by the handler.

## 6. Trust levels and sandbox construction

### 6.1 Levels

- **Strict** — default for unsigned files and legacy AppImages. The app gets its
  own directories, the GPU and Wayland, and no user files, network, audio or
  system bus.
- **Guarded** — default for signed ULAI files. Everything a normal app does,
  except other apps' hidden data, secrets and auto-start points.
- **Full** — no sandbox and no `no_new_privs`; the app behaves like a
  distro-installed program. It must be explicitly chosen, with a second
  confirmation.

### 6.2 Protection labels (probed at every launch)

| Landlock ABI | Label | Meaning |
|---|---|---|
| ≥ 9 (Linux 7.1+) | **Strong** | Pathname sockets are controllable: the session bus can be forced through the proxy, and X11 can be blocked |
| 1–8 | **Weak** | Files are protected against honest and naive access, but a malicious app can reach the real session bus or X11 socket. Not real isolation (ADR-013) |
| unavailable | **None** | Strict and Guarded cannot run; fail closed (§6.6) |

The handler MUST show the label on the card and in app settings.

Measured on 2026-10-21 (evidence table in RESEARCH.md): Arch with Linux 7.2 is
Strong (ABI 10). Ubuntu 24.04 HWE and 26.04 (Linux 7.0, ABI 8), Fedora 44
(6.19, ABI 7) and Debian 13 (6.12, ABI 6) are all Weak. openSUSE Tumbleweed and
Linux Mint are still to be measured.

**What each ABI adds.** Constants come from `include/uapi/linux/landlock.h`;
ULAI's copies of items missing from the `landlock` crate are in
`ulai-core/src/sys.rs` (`uapi`) and are tested against the installed header.

| ABI | Adds | First kernel |
|---|---|---|
| 1 | Base filesystem access rights | 5.13 |
| 2 | `LANDLOCK_ACCESS_FS_REFER` | 5.19 |
| 3 | `LANDLOCK_ACCESS_FS_TRUNCATE` | 6.2 |
| 4 | TCP bind and connect (`LANDLOCK_ACCESS_NET_{BIND,CONNECT}_TCP`) | 6.7 |
| 5 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` | 6.10 |
| 6 | Abstract UNIX socket and signal scoping (`LANDLOCK_SCOPE_*`) | 6.12 |
| 7 | Audit logging of denials (`LANDLOCK_RESTRICT_SELF_LOG_*`) | 6.15 |
| 8 | `LANDLOCK_RESTRICT_SELF_TSYNC` (apply to all threads) | 7.0 |
| 9 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (pathname UNIX sockets) | 7.1 |
| 10 | UDP bind and connect/send (`LANDLOCK_ACCESS_NET_BIND_UDP`, `…_CONNECT_SEND_UDP`); quiet rules (`quiet_*` ruleset fields, `LANDLOCK_ADD_RULE_QUIET`) | 7.2 (inferred: 7.2.9 reports 10) |
| 11 | **Unconfirmed:** no_new_privs flag for `landlock_restrict_self()` | after 7.2 (not in the 7.2 header) |

Kernel versions for ABI 1–9 are from the kernel commits linked in the
`landlock` crate's documentation. The ABI 10 quiet rules are stated in the 7.2
header but were not in the original version of this table. The ABI 11 row comes
from a third-party pull-request note, not a kernel header. It stays
unconfirmed, and ULAI treats ABI 10 as the newest known ABI, until a released
header defines it.

### 6.3 Guarded policy construction (normative)

Inputs: image path `I`, permissions `P`, own paths `O`, `$HOME` = `H`,
`$XDG_RUNTIME_DIR` = `R`, Landlock ABI `a`.

1. `handled_fs` = every filesystem right known at ABI `a` (best effort).
2. `handled_net` = empty if `network ∈ P`; otherwise TCP bind/connect (a ≥ 4)
   plus the UDP rights (a ≥ 10). An empty handled set means unrestricted.
3. `scoped` = abstract UNIX sockets and signals (a ≥ 6).
4. Add `path_beneath` rules:
   1. `I`: read file, read dir, execute.
   2. System: for each existing path in `/usr /bin /sbin /lib /lib32 /lib64 /etc
      /opt /srv /sys /proc /var` (plus `/nix/store`, `/gnu/store` on non-FHS
      hosts): read file, read dir, execute. Never grant `/` itself, because that
      would cover `H`.
   3. Temporary: `/tmp`, `/var/tmp`, `/dev/shm` get full file rights. Shared
      temp is a known gap (§14 O8).
   4. Devices: `/dev/null /dev/zero /dev/full /dev/random /dev/urandom /dev/tty
      /dev/ptmx /dev/pts` get read and write (plus `IOCTL_DEV` for tty/pts). With
      `gpu`: `/dev/dri`, `/dev/nvidia*`, `/dev/nvidia-caps` get read, write and
      `IOCTL_DEV`.
   5. Runtime dir `R`: the Wayland socket(s); the proxy bus socket (§7);
      `pipewire-0` and `pulse/native` if `audio`; `R/doc` (document portal)
      read/write; `R/dconf` read. Socket rules need a ≥ 9. Never grant `R`
      itself.
   6. Home `H`: for each entry `e` of `H` (using `lstat`), if its name does not
      start with `.` and it is not excluded, grant user rights: read file, read
      dir, write file, truncate, make reg, make dir, make sym, remove file,
      remove dir, refer. **Excluded:** any directory listed in `$PATH` (for
      example `~/bin`). For symlinked entries, resolve the target and grant it
      only if it lies outside hidden directories, `$PATH` directories and the
      store. **[verify]** that Landlock rules attach to the resolved inode.
   7. Hidden allowlist (read-only, existing entries only):
      `~/.config/{gtk-3.0,gtk-4.0,fontconfig,kdeglobals,mimeapps.list,
      user-dirs.dirs,user-dirs.locale,qt5ct,qt6ct,Kvantum}`,
      `~/.local/share/{fonts,icons,themes,mime,applications}`, `~/.fonts`,
      `~/.icons`, `~/.themes`, `~/.XCompose`. M2 tunes this list with
      measurements.
   8. Own paths: `O` plus the defaults `~/.config/<id>`, `~/.local/share/<id>`,
      `~/.cache/<id>` and `~/.local/state/<id>`. The launcher creates them
      before restricting itself, because the app cannot create them afterwards.
      Grant full user rights.
   9. Removable media (with `user-files`): `/media`, `/run/media/$USER`, `/mnt`
      get user rights.
5. Set `PR_SET_NO_NEW_PRIVS`, restrict self, then exec.

**Protected set.** These are never reachable through `user-files`, `own_paths`
or the allowlist; only a matching sensitive permission can grant them. The list
is non-exhaustive; the allowlist design (ADR-005) is the real protection, and
this list exists for validation and consent wording: `~/.ssh`, `~/.gnupg`,
`~/.password-store`, `~/.local/share/keyrings`, browser profiles (`~/.mozilla`,
`~/.config/{google-chrome,chromium,BraveSoftware,microsoft-edge,vivaldi,opera}`),
`~/.thunderbird`, cloud credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`,
`~/.oci`, `~/.kube`, `~/.docker`), `~/.netrc`, `~/.git-credentials`,
`~/.config/gh`, crypto wallets (`~/.electrum`, `~/.bitcoin`, `~/.ethereum`, …),
shell startup files (`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`,
`~/.zprofile`, `~/.config/fish`), auto-start points (`~/.config/autostart`,
`~/.config/systemd`, `~/.local/share/systemd`, `~/.config/environment.d`,
`~/.xprofile`, `~/.xinitrc`), `~/.local/bin`, desktop shell extensions
(`~/.local/share/gnome-shell/extensions`, `~/.local/share/plasma`), and the ULAI
store.

**Semantics to respect.** Landlock rules only allow; there are no deny rules.
Rights granted on a directory apply to everything beneath it, and anything not
granted is denied for the handled rights. That is why `H` itself is never
granted. Access checks happen when files are opened and on path operations,
not on every read or write.

### 6.4 Strict

Same as Guarded, minus steps 4.6 and 4.9, network, audio and the system bus. File
access to user-picked files depends on §14 O3.

### 6.5 Full

No Landlock domain and no `no_new_privs`. The store, integration and updates
still apply.

### 6.6 Fail-closed rules

If ruleset creation fails, or the protection label is None, `ulai-run` MUST NOT
start a Strict or Guarded app. It exits with a documented error code; the
handler explains why and offers Full trust behind explicit consent. That choice
is not remembered unless the user ticks "always for this app".

## 7. Session bus mediation

- `ulai-run` starts `xdg-dbus-proxy` (outside the sandbox, before restricting
  itself) with `--filter` and this default policy:
  - **talk:** `org.freedesktop.portal.*`, `org.freedesktop.Notifications`,
    `org.freedesktop.FileManager1`, `org.kde.StatusNotifierWatcher`,
    `org.a11y.Bus`, `org.freedesktop.ScreenSaver`;
  - **own:** `<id>`, `<id>.*`, and an MPRIS name derived from `<id>`;
  - **only with a permission:** `org.freedesktop.secrets` (`secrets`);
  - **never by default:** `org.freedesktop.systemd1` (it can start unsandboxed
    processes), `ca.desrt.dconf` (§14 O6), `org.freedesktop.Flatpak*`,
    `org.kde.klauncher*`, `org.gnome.Shell`, and any name not listed above.
- The app receives `DBUS_SESSION_BUS_ADDRESS=unix:path=R/ulai/<id>/bus`.
- The proxy's lifetime is tied to the app through xdg-dbus-proxy's fd-based
  lifetime option, as Flatpak does it. **[verify]** the option name and
  behaviour.
- Enforcement needs the Strong label (§6.2). Otherwise the app could connect to
  the real bus socket directly.

## 8. Install layout and store

```
$XDG_DATA_HOME/ulai/                    (default ~/.local/share/ulai)
  objects/<b3[0:2]>/<b3>                content-addressed files; mode 0444, or 0555 if executable
  images/<sha256 of file>/              hardlink tree of the extracted image, read-only
  apps/<id>/current -> images/<sha>
  apps/<id>/previous -> images/<sha>    rollback target
  apps/<id>/app.json                    version, pinned key fingerprint, trust level,
                                        granted permissions, consents
  cache/                                "open once" extractions, garbage-collected
$XDG_DATA_HOME/applications/ulai-<id>.desktop   generated; Exec=ulai-run <id> %U
$XDG_DATA_HOME/icons/hicolor/<size>/apps/<id>.png
$XDG_RUNTIME_DIR/ulai/<id>/bus          proxy socket
```

Extraction rules:

- Reject `..` components and absolute paths.
- Keep symlinks only if they resolve inside the image.
- Drop setuid/setgid bits; refuse device nodes and FIFOs.
- Enforce limits on total size, file count and compression ratio (decompression
  bomb protection).

Generated `.desktop` files copy only safe keys (`Name`, `GenericName`,
`Comment`, `Icon`, `Categories`, `Keywords`, `MimeType`, `StartupWMClass`,
`Terminal`). `Exec` is always generated.

Uninstall removes `apps/<id>` and every file the handler generated (desktop
entry, icons, MIME, autostart, native-messaging manifests), then
garbage-collects unreferenced images and objects. User data in own paths is
kept unless the user picks "Remove app data".

## 9. Handler behaviour (double-click flow)

1. The desktop opens the file with `ulai-handler`, through the MIME
   registration for `*.ulai` and AppImage type 2. No executable bit is needed.
2. Parse the ELF and check the magic. Verify the signature (§3.2) before
   reading the manifest or icon.
3. Read the manifest. If it is absent, treat the file as a legacy AppImage.
4. Show the card: icon, name, version, publisher (pinned or new key
   fingerprint, "unknown publisher" or "unsigned"), protection label,
   ordinary permissions in plain language, each sensitive permission as a
   toggle (default off), and requested integrations.
5. Offer **Open once**, **Install** and **Cancel**, with a "Trust level" expander.
   Choosing Full needs a second confirmation.
6. Install: extract to the store, write integrations, then optionally launch.
7. On reinstall or update, a key mismatch blocks the action and shows both
   fingerprints.

Legacy AppImages default to Strict. The user may choose Guarded or Full; in
Guarded, unknown config locations may break the app (§14 O7).

## 10. Launch sequence (`ulai-run <id> [args]`)

1. Load `app.json`; resolve the image; read the trust level and granted
   permissions.
2. Probe the Landlock ABI and compute the label; apply §6.6.
3. Create own directories and `R/ulai/<id>/`.
4. Start xdg-dbus-proxy (Strict and Guarded).
5. Build the environment: `DBUS_SESSION_BUS_ADDRESS`, the variables AppImage
   apps expect (`APPDIR`, `APPIMAGE`, `ARGV0`; **[verify]** the full list), and
   the native-mode library rules (§11).
6. Build the ruleset (§6.3), set `no_new_privs`, restrict self.
7. `execve` the image's entry point with the arguments.

## 11. GPU

### 11.1 Native mode

The host provides glibc, the dynamic loader and the graphics stack. ULAI keeps
its own minimal list. It deliberately does not reuse AppImage's
`excludelist`: that file's licence is unclear (MIT in one place,
GPL-2.0-only in another), and its policy of always using the host copy breaks
apps when the host copy is older (pkg2appimage issue #538).

`ulai validate` checks every bundled ELF file by name (`DT_SONAME`, or the
file name):

`validate` findings never block running a legacy AppImage. They only gate
publishing `.ulai` files.

- **Error** (MUST come from the host in native mode):
  - glibc and the loader: `libc`, `libm`, `libdl`, `libpthread`, `librt`,
    `libresolv`, `libutil`, `libanl`, `ld-linux*`;
  - the GPU and driver stack, by **exact soname**:
    - glvnd: `libGL.so.1`, `libEGL.so.1`, `libGLX.so.0`,
      `libGLdispatch.so.0`, `libOpenGL.so.0`, `libGLESv2.so.2`,
      `libGLESv1_CM.so.1`;
    - glvnd vendor libraries: `libEGL_mesa.so.0`, `libGLX_mesa.so.0`,
      `libEGL_nvidia.so.0`, `libGLX_nvidia.so.0`, `libGLESv2_nvidia.so.2`,
      `libGLESv1_CM_nvidia.so.1`;
    - the rest of Mesa and the NVIDIA userspace: `libgbm.so.1`,
      `libglapi.so.0`, `libOSMesa.so.8`, `libxatracker.so.2`,
      `libcuda.so.1`, `nvidia_drv.so`;
  - driver families with no fixed soname: `libdrm.so*` and `libdrm_*`,
    `libnvidia-*`, Mesa's `libgallium-*` and `*_dri.so`, and the Mesa
    Vulkan drivers `libvulkan_*` (`libvulkan_radeon.so`,
    `libvulkan_intel.so`, …).
- **Warning:**
  - a bundled Vulkan loader, `libvulkan.so.1`. It works, but the host's
    loader is the one that matches the host's drivers;
  - `libstdc++`, `libgcc_s`, `libLLVM*`, `fontconfig` (report, and point to
    §11.2). Also report the highest `GLIBCXX` and `CXXABI` version required
    by any bundled ELF, and whether `libstdc++` is bundled; §11.2 needs that
    data.
- **Info** (allowed): renderers that run on top of the host's driver or on
  the CPU, which Chromium and so every Electron app ships. These are ANGLE
  as the unversioned `libEGL.so` and `libGLESv2.so`, and SwiftShader as
  `libvk_swiftshader.so` with `vk_swiftshader_icd.json`. Exact names
  measured in Obsidian 1.14.4.
- Everything else is bundled, with no message.

Matching is exact, so names that only look similar are not GPU libraries:
`libGLU.so.1` and `libGLEW.so.2.2` (ordinary libraries), ANGLE's `libEGL.so`
(info, above), and Qt's `libdrm-egl-server.so` and `libvulkan-server.so`
plugins. The name checked
is `DT_SONAME`, or the file name if there is none.

### 11.2 Library conflicts

When a bundled library (for example `libstdc++`, `libgcc_s` or `libz`) is older
than the host copy that the host GPU driver needs, the newer copy must win,
following the approach of Steam's pressure-vessel. v0 detects and reports this;
M6 implements the selection.

### 11.3 Portable mode (M6)

The app bundles its loader and libc. GPU comes from one shared driver pack per
machine (Mesa built against a glibc floor), kept in the store and downloaded
only when needed, with software rendering as the fallback. NVIDIA's proprietary
driver is not supported in portable mode.

## 12. Updates

- Per app, checks are on by default and can be turned off. Requests go only to
  that app's own update URL from `.upd_info`; there is no central ULAI server.
- Downloads are verified with the pinned key (§3.2), then switched in
  atomically. `previous` is kept, and if the app fails to launch after an
  update, the handler offers a rollback.

## 13. Threat model

**Assets:** secrets (keys, tokens, browser data, keyring items); integrity of
the user environment (startup files, auto-start points, other apps, the store);
user files, partially.

**Attacker:** the publisher of a malicious or compromised app file, such as the
2020–2022 supply-chain attack on Free Download Manager.

**In scope (Strong label):** reading other apps' data and secrets; persistence
through startup files, autostart, user services or cron; escaping through the
session bus; signalling or ptracing processes outside the sandbox; privilege
escalation via setuid; tampering with the store or other apps.

**Out of scope:** kernel exploits; X11 sessions once `x11` is granted; misuse of
user files the user granted; network exfiltration of granted data; a malicious
first install from a compromised publisher (TOFU only protects updates).

## 14. Open problems

- **O1 — Isolation below Landlock ABI 9.** See ADR-013.
- **O2 — Electron/Chromium sandbox under `no_new_privs`.** The setuid sandbox
  cannot work, and the namespace sandbox needs unprivileged user namespaces,
  which AppArmor restricts on Ubuntu 24.04+. Candidate: an AppArmor profile for
  `ulai-run` that permits user namespaces. Never fall back to `--no-sandbox`
  silently.
- **O3 — Portal identity.** xdg-desktop-portal treats ULAI apps as host apps and
  returns real paths, so a Strict app cannot open files the user picks. Track
  Flatpak Next's app-identity work (systemd-appd).
- **O4 — PipeWire.** Socket access includes the microphone and other streams;
  there is no per-app policy for non-Flatpak clients.
- **O5 — Files in the `$HOME` root.** New files directly in `$HOME`, and
  top-level entries created after launch, are not accessible. Granting
  creation on `$HOME` would expose hidden directories.
- **O6 — dconf/GSettings writes.** dconf can define custom keyboard shortcuts
  that run commands, so writes are treated as sensitive. Decide between a
  keyfile backend and per-key filtering.
- **O7 — Legacy apps' config locations are unknown.** Options: Flatpak-style XDG
  remapping, or heuristics. Measure the breakage.
- **O8 — Shared temp.** `/tmp` and `/dev/shm` are shared between apps, since
  there is no mount namespace.
- **O9 — Signature digest details.** Match upstream exactly (§3.2), and check how
  tools treat trailing data after the image.
- **O10 — X11 apps.** X11 clients are not isolated from each other; require `x11`
  consent and show the warning.

## 15. Versioning

The manifest's `ulai` field carries the spec version. Minor versions stay
backward compatible; handlers ignore unknown fields.

## 16. Command-line output and exit codes

Every `--json` output carries `"schema"` (an integer, bumped on breaking
changes) and `"status"` (a string). The `ulai doctor` schema is in
`docs/doctor-schema.md`.

`ulai verify` exit codes are **stable API**:

| Exit | `status` | Meaning |
|---|---|---|
| 0 | `valid` | The signature verifies with the key embedded in the file (§3.2) |
| 3 | `unsigned` | No signature (empty or missing `.sha256_sig`, and no detached signature found) |
| 3 | `signature_unverifiable` | A detached signature was found, but no key is available to check it (ADR-016) |
| 4 | `invalid` | The signature or digest does not match, or the key is revoked |
| 4 | `signature_from_future` | A signature relied on was created more than 30 minutes after this computer's clock (§3.2); check the clock |
| 5 | `corrupt` or `unsupported` | The ELF or sections are malformed, or the algorithm, key or filesystem is not supported |
| 1 | — | Internal error |
| 2 | — | Usage error |

`ulai inspect` exit codes:

| Exit | `status` | Meaning |
|---|---|---|
| 0 | `ok` | Inspected (the signature result is in the output; `authenticated` is true only if it is valid) |
| 5 | `corrupt` or `unsupported` | The file or its filesystem cannot be read (in M1, this includes DwarFS) |

`ulai validate` exit codes:

| Exit | `status` | Meaning |
|---|---|---|
| 0 | `conforms` | No errors (warnings allowed, e.g. an unsigned development build) |
| 4 | `does_not_conform` | At least one error |
| 5 | `corrupt` or `unsupported` | The file or its filesystem cannot be read (in M1, this includes DwarFS) |

Both also use 1 for internal errors and 2 for usage errors. In M1, verify
works on DwarFS images while inspect and validate report exit 5.

