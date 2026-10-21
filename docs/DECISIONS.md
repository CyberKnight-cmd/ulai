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

**ADR-012 — License.** Owner to decide. Recommendation: `MIT OR Apache-2.0`
(Rust ecosystem norm, simple for distro packaging). *Open.*

**ADR-013 — Isolation on kernels without Landlock ABI ≥ 9.** Below ABI 9,
Landlock cannot stop connections to pathname UNIX sockets, so a malicious app
can reach the real session bus (for example, asking `systemd --user` to start an
unsandboxed process) or the X11 socket. Options: (a) label it "weak isolation"
and continue; (b) use a minimal mount namespace via unprivileged user namespaces
where allowed, to hide the real sockets; (c) refuse Guarded. Decide after the
M2 measurements. *Open.*

**ADR-014 — The CLI and launcher ship as static musl binaries; they depend
only on the kernel.** `ulai` and `ulai-run` are built for
`x86_64-unknown-linux-musl` as static executables. One file can be copied
into any test VM or distribution, nothing about the host libc is inferred
from our own libc, and neither tool needs `dlopen`. `ulai-handler` is out of
scope (GTK must link the host's libraries). aarch64 musl builds follow in M6.
*Accepted* (2026-10-21).
