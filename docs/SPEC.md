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
2. Use SquashFS for the image (zstd compression RECOMMENDED). DwarFS MAY be
   allowed in a later version.
3. Contain at the image root: `AppRun` (the entry point), exactly one `.desktop`
   file, and an icon, following AppDir conventions.
4. Contain `/.ulai/manifest.json` (§4).
5. Be signed (§3.2). Unsigned files are allowed only as development builds and
   are always treated as Strict by default.

A ULAI file SHOULD use the extension `.ulai`. Handlers MUST NOT rely on the
extension: detection is by AppImage magic plus manifest presence.

### 3.1 Image offset

The image starts where the ELF ends: `offset = e_shoff + e_shentsize × e_shnum`,
which is how AppImage tooling computes it. **[verify]** against the upstream
type 2 runtime for both ELF32 and ELF64.

### 3.2 Signature

- Use the AppImage signature sections. `.sha256_sig` holds an ASCII-armored
  OpenPGP detached signature over the SHA-256 digest of the whole file, computed
  with `.sha256_sig` zero-filled. `.sig_key` holds the publisher's public key.
  Ed25519 keys are RECOMMENDED.
- **[verify]** whether upstream also zero-fills `.sig_key` when computing the
  digest. Implement exactly what upstream `appimagetool` does, and add test
  vectors made from upstream-signed files.
- Verification MUST complete before any other content of the file is trusted or
  displayed, including the manifest and the icon.
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
  "sensitive_permissions": [],
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
| `sensitive_permissions` | no | Each one needs explicit consent (§5.2) |
| `own_paths` | no | Extra per-app directories under `$HOME` (§6.3 rules apply) |
| `integrations` | no | Written by the handler at install, with consent (ADR-011) |

Unknown fields MUST be ignored (forward compatibility). `ulai validate` MUST
reject unknown permission identifiers, own paths outside `$HOME`, own paths
that equal or contain a protected path (§6.3), and own paths that are too broad
(`~`, `~/.config`, `~/.local`, `~/.local/share`, `~/.cache`).

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

| Id | Grants | Note shown to the user |
|---|---|---|
| `x11` | X11 sockets | X11 lets any app read the keystrokes and windows of other X11 apps |
| `secrets` | Secret Service on the session bus | Can read passwords stored in your keyring |
| `ssh-keys` | Read `~/.ssh` | Can use your SSH identities |
| `dotfile:<path>` | One specific hidden path, read-only or read-write | Shown with the exact path |
| `camera` | `/dev/video*` | — |
| `full-home` | Read all of `$HOME`, including hidden files | For backup tools and file managers |

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
| 11 | no_new_privs flag for `landlock_restrict_self()` | after 7.2 (not in the 7.2 header) |

Kernel versions for ABI 1–9 are from the kernel commits linked in the
`landlock` crate's documentation. The ABI 10 quiet rules are stated in the 7.2
header but were not in the original version of this table.

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

The host provides glibc, the dynamic loader and the graphics stack:
`libGL*`, `libEGL*`, `libGLX*`, `libGLdispatch*`, `libOpenGL*`, `libvulkan*`,
`libgbm*`, `libdrm*`, Mesa and NVIDIA driver files, and `libLLVM*`. It also
provides the base libraries on the AppImage project's exclude list (libc, libm,
libpthread, libdl, librt, the dynamic loader, …). `ulai validate` MUST reject
images that bundle any of these. Start from the AppImage exclude list and adjust
with test results.

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
