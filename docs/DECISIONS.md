# Design decisions (ADR log)

Each entry: decision, rationale, status. Changing an **Accepted** ADR requires
the project owner's approval. New decisions get the next number.

**ADR-001 — Rust for all components.** Memory safety for security-critical
code, official Landlock bindings, easy static builds for small tools.
*Accepted.*

**ADR-002 — The file format is a strict superset of AppImage type 2.** Instant
compatibility with existing AppImages and tooling; no new container format to
maintain. The manifest lives inside the image at `/.ulai/manifest.json`;
signatures use the standard `.sha256_sig` / `.sig_key` ELF sections; updates use
`.upd_info`. *Accepted.*

**ADR-003 — Extension `.ulai`; `.AppImage` files are handled too.** `.ulx` was
rejected because it is already the Glulx game format (`application/x-glulx`). No
registered use of `.ulai` was found (Oct 2026). Detection is by AppImage magic
plus manifest presence, never by extension alone. *Accepted.*

**ADR-004 — Sandbox = Landlock + `no_new_privs` + xdg-dbus-proxy.** No
containers, user namespaces or setuid helpers in v0: they add complexity, and
user namespaces are restricted on Ubuntu 24.04+ and Debian 13+. Kernels without
Landlock ABI ≥ 9 are handled by ADR-013. *Accepted.*

**ADR-005 — Guarded mode is an allowlist, not a denylist.** Hidden files and
directories of other apps are invisible unless declared; the user's non-hidden
files are fully accessible. A denylist of "secret" paths always misses
something (tokens in `~/.netrc`, `~/.git-credentials`, `~/.config/gh`, …).
*Accepted.*

**ADR-006 — Install by extraction into a content-addressed store with
hardlinks.** No FUSE at runtime (FUSE mounting needs a setuid helper, which
`no_new_privs` disables). Identical files across apps share disk and page cache.
The handler never runs the file's own runtime to unpack it. *Accepted.*

**ADR-007 — GPU: native mode first.** Apps use the host glibc (≥ the manifest's
floor) and the host graphics stack; drivers are never bundled. Portable mode
(bundled loader and libc, plus one shared driver pack per machine) comes later.
The primary dev host runs NVIDIA's proprietary driver, which only native mode
supports. *Accepted.*

**ADR-008 — Trust = signature + trust-on-first-use key pinning per app id.** A
key change on update is blocked with a warning; unsigned files default to
Strict. Verified publishers and transparency logs come later. *Accepted.*

**ADR-009 — Handler UI = GTK4 + libadwaita (gtk4-rs).** All decisions live in
`ulai-core` so a Qt frontend can be added without logic changes. *Accepted.*

**ADR-010 — Agent-neutral repo instructions.** AGENTS.md is canonical;
CLAUDE.md imports it. *Accepted.*

**ADR-011 — Integration is done by the handler, never by the sandboxed app.**
Menu entries, MIME associations, autostart entries and browser
native-messaging manifests are declared in the manifest and written by the
handler at install time, with consent. The running app never needs write
access to those locations. *Accepted.*

**ADR-012 — License: GPL-3.0-or-later.** Chosen by the project owner
(2026-10-21) over the earlier recommendation, `MIT OR Apache-2.0`. ULAI is a
security tool that users must be able to audit, and copyleft keeps modified
versions open. The full text is in `LICENSE`. Every dependency must be
GPL-3.0-compatible: permissive licences (MIT, Apache-2.0, BSD, ISC, Zlib,
Unicode) are fine, while GPL-2.0-only and proprietary licences are not. At
adoption, all 51 locked dependencies were permissive. Apps that ULAI runs are
separate programs and are not affected by ULAI's licence. *Accepted.*

**ADR-013 — Isolation on kernels without Landlock ABI ≥ 9.** Below ABI 9,
Landlock cannot stop connections to pathname UNIX sockets, so a malicious app
can reach the real session bus (for example, asking `systemd --user` to start an
unsandboxed process) or the X11 socket.

**This is on the critical path.** ABI 9 needs Linux 7.1, and every
mainstream distribution measured on 2026-10-21 is below it: Ubuntu 24.04 HWE
and 26.04 (7.0, ABI 8), Fedora 44 (6.19, ABI 7) and Debian 13 (6.12, ABI 6).
Only the Arch dev host (7.2) is Strong. See the evidence table in RESEARCH.md.

Options:

- (a) Label it "weak isolation" and continue.
- (b) Use a minimal mount namespace via unprivileged user namespaces, where
  allowed, to hide the real sockets. On Ubuntu 24.04 and 26.04, AppArmor's
  `unprivileged_userns` profile lets `unshare` succeed but then denies
  `CAP_SYS_ADMIN`, so this needs an AppArmor profile (also SPEC §14 O2).
- (c) Refuse Guarded.
- (d) Mediate `connect()` and `sendmsg()` on pathname and abstract UNIX
  sockets with seccomp user notification. The supervisor (outside the
  sandbox) checks the address, performs the connect itself and injects the
  resulting fd into the app with `SECCOMP_IOCTL_NOTIF_ADDFD`. This avoids a
  time-of-check/time-of-use race on the socket address. Works without user
  namespaces. Prior art: nolabs-ai/nono (Apache-2.0), which uses
  `SECCOMP_IOCTL_NOTIF_ADDFD` in its Linux sandbox and supervisor; its design
  has not been reviewed in detail yet. Not implemented.

The M2 plan must choose among these options, using M2's measurements.
*Open.*

**ADR-014 — The CLI and launcher ship as static musl binaries; they depend
only on the kernel.** `ulai` and `ulai-run` are built for
`x86_64-unknown-linux-musl` as static executables. One file can be copied
into any test VM or distribution, nothing about the host libc is inferred
from our own libc, and neither tool needs `dlopen`. `ulai-handler` is out of
scope (GTK must link the host's libraries). aarch64 musl builds follow in M6.
*Accepted* (2026-10-21).

**ADR-015 — Licences for the parts other projects reuse.** The tools
(`ulai`, `ulai-run`, `ulai-handler`, `ulai-core`) stay GPL-3.0-or-later
(ADR-012). Two parts use other licences:

- Any code embedded into distributed app files (a future runtime stub,
  templates) is **MIT**, so apps under any licence can ship as `.ulai`.
- The format documents (`docs/SPEC.md`, and `docs/doctor-schema.md` as a
  format document) are **CC-BY-4.0**. The JSON Schemas (`schemas/`) are
  **MIT**.

Together these let other projects implement the format. `REUSE.toml` records
the licence of each path, and `LICENSES/` holds the texts. *Accepted*
(2026-10-21).

**ADR-016 — Detached signatures for legacy AppImages.** In the M1 spikes, none
of 10 real AppImages carried an embedded signature. Krita, for example, blanks
the embedded sections and publishes a separate `.sig` over the whole file
(RESEARCH.md, S3/S4).

- ULAI files: the embedded signature stays mandatory (SPEC §3.2). A detached
  signature next to a ULAI file is ignored.
- Legacy AppImages without an embedded signature may be verified with a
  detached OpenPGP signature over the whole file's bytes (what
  `gpg --detach-sign` produces).
- Where the signature comes from: `--signature <file>`, or automatic discovery
  of exactly `<file>.sig` or `<file>.asc` in the same directory. Nothing else.
- The public key is never fetched from the network: no keyservers, no WKD. In
  M1 it comes from `--key <file>`; from M3, also from ULAI's per-user keyring
  of pinned keys.
- Results:
  - Valid → exit 0, reported as "detached signature, key supplied by you",
    with the full fingerprint.
  - Signature found and a key available, but verification fails → invalid
    (exit 4). A matching-named signature that fails is a real red flag: a
    tampered file or the wrong version.
  - Signature found but no key available → exit 3, status
    `signature_unverifiable`.
- Signed checksum lists (SHA256SUMS plus a signature) are out of scope. They
  get their own ADR if real apps need them.
- Handler UX (M4): say that a signature file was found but ULAI doesn't have
  this publisher's key, and offer an import action that pins the key to the
  app id (M3).

*Accepted* (2026-10-22).

