# `ulai doctor --json` — schema 1

`ulai doctor --json` prints one JSON object describing what the running system
supports and which protection ULAI can enforce on it. The human-readable
output (`ulai doctor`) shows the same facts.

`ulai doctor` needs no root, makes no network calls, and always exits 0 unless
the tool itself crashes (usage errors exit 2). A probe that fails is reported
as unknown with a reason; it never fails the tool.

## Rules

- `schema` is `1`. Adding fields does not change it; renaming or removing a
  field, or changing what a value means, bumps it.
- Every section has:
  - `status`: `"ok"` (everything known), `"partial"` (some fields unknown) or
    `"unknown"` (nothing could be determined);
  - `errors`: a list of `{ "field": "<dotted path>", "reason": "<text>" }`.
    `field` is `"*"` when the whole section is affected.
- In the data, **`null` means "not present / not applicable"**. Whether a
  value is *unknown* is stated only in `errors`. Consumers must check
  `errors` before reading `null` as absence.
- Errno values are symbolic strings (`"EPERM"`), or `"errno N"` for
  uncommon ones.
- Paths are absolute strings.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | integer | `1` |
| `status` | `"ok"`, `"partial"`, `"unknown"` | Overall result: `ok` when every section is `ok`, `unknown` when every section is `unknown`, `partial` otherwise. Every ULAI `--json` output carries `schema` and `status` |
| `ulai_version` | string | Version of the `ulai` binary |
| `kernel`, `lsm`, `landlock`, `userns`, `seccomp`, `yama`, `fuse`, `libc`, `session`, `gpu`, `dbus_proxy`, `xdg` | section | See below |

## Sections

### `kernel` — from `uname(2)`

| Field | Type |
|---|---|
| `release` | string or null |
| `arch` | string or null (machine, e.g. `x86_64`) |

### `lsm` — from `/sys/kernel/security/lsm`

| Field | Type | Meaning |
|---|---|---|
| `active` | string[] | Active LSMs in kernel order |
| `landlock_listed` | bool or null | `landlock` is in the list; `null` if the list is unknown |

### `landlock` — raw `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`

| Field | Type | Meaning |
|---|---|---|
| `state` | `"available"`, `"not_built"` (ENOSYS), `"disabled"` (EOPNOTSUPP), `"unknown"` (any other error) | |
| `abi` | integer or null | ABI the kernel reports |
| `errno` | string or null | Set when the syscall failed |
| `label` | `"strong"` (ABI ≥ 9), `"weak"` (1–8), `"none"` | SPEC §6.2. An unknown ABI gives `"none"` (fail closed) |
| `abi_newer_than_known` | bool | The kernel's ABI is above the newest one confirmed by a released kernel header (10) |
| `features` | object of bools | One key per SPEC §6.2 feature: `fs_base` (≥ 1), `refer` (≥ 2), `truncate` (≥ 3), `tcp_deny` (≥ 4), `ioctl_dev` (≥ 5), `ipc_scoping` (≥ 6), `audit` (≥ 7), `tsync` (≥ 8), `pathname_sockets` (≥ 9), `udp` (≥ 10), `quiet_rules` (≥ 10), `restrict_self_nnp` (≥ 11, unconfirmed) |
| `notes` | string[] | Contradictions with the LSM list |

### `userns` — unprivileged user namespaces

| Field | Type | Meaning |
|---|---|---|
| `sysctls` | object of integers | Only the keys that exist on this kernel: `max_user_namespaces`, `unprivileged_userns_clone`, `apparmor_restrict_unprivileged_userns` |
| `probe.result` | `"ok"`, `"failed"`, `"unknown"` | Live probe in a re-executed child process |
| `probe.failed_step` | step or null | First step that failed |
| `probe.steps` | `[{ "step", "ok", "errno" }]` | Steps attempted, in order, stopping at the first failure |
| `running_as_root` | bool | If true, the results say nothing about unprivileged users |

Steps, in order: `unshare` (`CLONE_NEWUSER|CLONE_NEWNS`), `setgroups`
(write `deny`), `uid_map`, `gid_map`, `mount_private` (`/` made
`MS_REC|MS_PRIVATE`), `mount_tmpfs` (on an empty temporary directory, inside
the child's namespace only).

### `seccomp` — seccomp user notification (ADR-013, SPEC §6.7)

| Field | Type | Meaning |
|---|---|---|
| `result` | `"ok"`, `"fallback_only"`, `"failed"`, `"unknown"` | `ok`: notification works and the supervisor can connect the app's own socket with `pidfd_getfd`. `fallback_only`: it works, but `pidfd_getfd` is refused (for example by Yama `ptrace_scope` ≥ 2), so only the `ADDFD` fallback is available. `failed`: the mechanism does not work |
| `steps` | `[{ "step", "ok", "errno" }]` | Every step attempted, in order. A failed method step does not stop the others |

Live probe in a re-executed child (`ulai __seccomp-probe`), which forks: its
child installs a filter (`SECCOMP_FILTER_FLAG_NEW_LISTENER`) that notifies on
`connect()`, passes the listener fd back over a socketpair made before the
filter, and connects twice to a socket in a private temporary directory. The
supervisor answers the first connect by connecting the app's own socket, and
the second by injecting a new one. It never lets a call continue. Steps:
`install_filter`, then for each connect `receive` and `read_memory` (the
address is read from `/proc/<pid>/mem` and `SECCOMP_IOCTL_NOTIF_ID_VALID` is
checked after the read), then `pidfd_getfd` and `proc_fd_connect` (connecting
through `/proc/self/fd/<O_PATH fd>`) for the first and `add_fd` (`ADDFD` with
`SETFD`, no `SEND`) for the second, and finally `app_connected` (the child saw
`connect()` return 0 both times).

### `yama`

| Field | Type | Meaning |
|---|---|---|
| `active` | bool or null | `false` when `/proc/sys/kernel/yama/ptrace_scope` does not exist |
| `ptrace_scope` | 0–3 or null | |
| `meaning` | string or null | Plain-language meaning of the scope |

### `fuse` — informational; ULAI does not use FUSE (ADR-006)

| Field | Type | Meaning |
|---|---|---|
| `dev_fuse` | bool or null | `/dev/fuse` exists and is a character device |
| `fusermount3`, `fusermount` | `{ "path", "setuid_root" }` or null | Found in `$PATH`, `/usr/bin` or `/bin` |
| `libfuse2` | `{ "found", "path" }` or null | `libfuse.so.2`, looked up like the GPU loaders |

### `libc` — the host's C library, never inferred from `ulai` itself

| Field | Type | Meaning |
|---|---|---|
| `glibc` | string or null | From `getconf GNU_LIBC_VERSION`, e.g. `"2.44"` |
| `musl_loader` | path or null | `/lib/ld-musl-*.so.1` |

### `session` — from the environment

| Field | Type | Meaning |
|---|---|---|
| `type` | string or null | `XDG_SESSION_TYPE` |
| `wayland_display` | string or null | `WAYLAND_DISPLAY` |
| `wayland_socket_exists` | bool or null | `null` when the socket cannot be located |
| `display` | string or null | `DISPLAY` |
| `current_desktop` | string or null | `XDG_CURRENT_DESKTOP` |

Empty variables are reported as `null`.

### `gpu`

| Field | Type | Meaning |
|---|---|---|
| `cards` | `[Card]` | `/sys/class/drm/card[0-9]+` (connectors such as `card1-DP-1` are skipped) |
| `nvidia` | `{ "version", "kernel_module": "open" \| "proprietary" }` or null | From `/proc/driver/nvidia/version` |
| `render_nodes` | path[] | `/dev/dri/renderD*` |
| `vulkan_icds` | `[Manifest]` | `*.json` in `/usr/share/vulkan/icd.d`, `/etc/vulkan/icd.d` |
| `egl_vendors` | `[Manifest]` | `*.json` in `/usr/share/glvnd/egl_vendor.d`, `/etc/glvnd/egl_vendor.d` |
| `loaders` | object | `source` (`"ldconfig"`, `"scan"`, `"none"`), plus `libvulkan.so.1`, `libEGL.so.1`, `libGL.so.1`: path or null |

`Card`: `name`, `pci_vendor` (e.g. `"0x10de"`, or null for non-PCI
devices), `vendor` (`"nvidia"`, `"amd"`, `"intel"` or null), `pci_device`,
`driver` (bound kernel driver, or null when unbound), `stack` (`"nvidia"` for
NVIDIA's proprietary userspace, `"mesa"`, or `"unknown"`).

`Manifest`: `path`, `library_path` (`ICD.library_path`, or null), `error`
(why the file could not be read or parsed, or null).

Library lookup parses `ldconfig -p`, keeping only entries for our
architecture. If ldconfig is missing, fails, or lists nothing (e.g. musl
systems), it scans `/usr/lib64`, `/usr/lib`, `/lib64`, `/lib`,
`/usr/lib/x86_64-linux-gnu`, `/lib/x86_64-linux-gnu`, `/usr/local/lib` and
`/run/opengl-driver/lib`.

### `dbus_proxy` — `xdg-dbus-proxy` (SPEC §7)

| Field | Type |
|---|---|
| `path` | path or null (not installed) |
| `version` | string or null (from `--version`) |

### `xdg` — XDG Base Directory specification

| Field | Type | Meaning |
|---|---|---|
| `home` | path or null | `HOME`, if absolute |
| `config_home`, `data_home`, `state_home`, `cache_home` | `{ "path", "source": "env" \| "default" }` or null | Relative values are ignored, as the specification requires |
| `data_dirs`, `config_dirs` | path[] | With the spec defaults (`/usr/local/share:/usr/share`, `/etc/xdg`) |
| `runtime_dir` | object | `path` (or null if unset; it has no default), `exists`, `owner_ok`, `mode` (e.g. `"0700"`), `mode_ok` |
| `ulai_store` | path or null | `$XDG_DATA_HOME/ulai` (SPEC §8) |

## Example

Abridged output from the Arch dev host (2026-10-21):

```json
{
  "schema": 1,
  "status": "ok",
  "ulai_version": "0.1.0",
  "kernel": { "status": "ok", "errors": [], "release": "7.2.9-arch1-1", "arch": "x86_64" },
  "landlock": {
    "status": "ok", "errors": [],
    "state": "available", "abi": 10, "errno": null, "label": "strong",
    "abi_newer_than_known": false,
    "features": { "fs_base": true, "refer": true, "truncate": true,
                  "tcp_deny": true, "ioctl_dev": true, "ipc_scoping": true,
                  "audit": true, "tsync": true, "pathname_sockets": true,
                  "udp": true, "quiet_rules": true, "restrict_self_nnp": false },
    "notes": []
  }
}
```

The full golden output for a synthetic system is in
`crates/ulai-core/tests/snapshots/doctor_full.json`.
