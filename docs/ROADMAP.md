# Roadmap

Durations are rough part-time estimates. Each milestone ends with a tagged
release and a short results entry in the experiment log in RESEARCH.md.

## M0 — Foundations and `ulai doctor` (~1 week)

- [ ] Cargo workspace with the crates listed in AGENTS.md. CI runs fmt, clippy
      (`-D warnings`) and tests.
      *(2026-10-21: workspace done; the workflow is written and every step was
      run locally, but it has not run on GitHub yet.)*
- [x] `ulai doctor` reports:
  - kernel version, active LSMs, Landlock ABI and the resulting protection
    label (SPEC §6.2);
  - unprivileged user-namespace status, including the AppArmor restriction;
  - FUSE availability, glibc version, session type (Wayland/X11);
  - GPU vendor and driver (Mesa or NVIDIA), and whether the Vulkan and EGL
    loaders are present;
  - whether xdg-dbus-proxy is installed, and the XDG directories.
- [x] Human-readable output and `--json` (schema: `docs/doctor-schema.md`).

**Done when:** it runs on the Arch dev host and three VMs, and the output has
been checked by hand.

*Status (2026-10-21): checked by hand on the Arch dev host and on a real
Ubuntu 24.04 machine. Two more systems (Debian 13 and Fedora) are still to do,
so M0 is not done.*

## M1 — Inspect, validate, verify (~2 weeks)

- [ ] ELF parsing, AppImage magic and image offset (SPEC §3.1). SquashFS listing
      and reading in-process: no FUSE and no execution.
- [ ] Manifest schema, and `ulai inspect` (human-readable and JSON).
- [ ] Signature verification compatible with upstream AppImage signing, with
      test vectors from upstream-signed files. Resolves SPEC §14 O9.
- [ ] `ulai validate` checks:
  - magic, manifest schema and permission vocabulary;
  - `own_paths` rules (SPEC §4);
  - no excluded libraries in the image (SPEC §11.1);
  - highest glibc symbol version ≤ `glibc_floor`;
  - no RPATH/RUNPATH pointing at absolute host paths;
  - the entry point exists and is executable;
  - `arch` matches the image.
- [ ] Fuzz the ELF, SquashFS and manifest parsers (cargo-fuzz), several hours each.

**Done when:** inspect, validate and verify work on 10 real AppImages, and on 3
crafted hostile files (bad signature, path traversal in the image, a
decompression bomb), without executing any of them.

## M2 — Sandbox (`ulai-run`) and the stealer suite (~3 weeks) — core research milestone

- [ ] Policy builder for Strict, Guarded and Full (SPEC §6), with ABI probing,
      protection labels and the fail-closed rules.
- [ ] xdg-dbus-proxy integration (SPEC §7).
- [ ] **Stealer test app**, packaged as a ULAI file. Each attempt reports pass or
      fail:
  - Read secrets: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.netrc`,
    `~/.git-credentials`, browser profile directories, wallet directories.
  - Look up an item through the Secret Service.
  - Plant persistence: write `~/.bashrc`, drop a file into
    `~/.config/autostart/` and `~/.config/systemd/user/`, write `/etc/cron.d`.
  - Escape the sandbox:
    - run `systemd-run --user`, and call `StartTransientUnit` over D-Bus;
    - connect to the real session-bus socket and to X11;
    - signal or ptrace a process outside the sandbox;
    - run `sudo` and `pkexec`.
  - Tamper with the ULAI store.
- [ ] **Gate:** on a kernel with the Strong label, every stealer attempt fails in
      Guarded mode, and the honest reference apps still work.
- [ ] Run the same suite on kernels with the Weak label and record the results.
      This feeds ADR-013.
- [ ] Census: run the reference apps in Guarded mode and log Landlock denials
      (audit logging, ABI ≥ 7). Classify each breakage, tune the hidden
      allowlist, and update SPEC.

## M3 — Install, store, integration (~2 weeks)

- [ ] Safe extraction (SPEC §8 rules) into the content-addressed store, with
      hardlinks and garbage collection.
- [ ] Generated desktop entries, icons and MIME entries. Uninstall removes
      everything the handler created.
- [ ] `ulai install`, `remove`, `list` and `run`; rollback through `previous`.
- [ ] Measure disk use across the reference set, with and without deduplication.

## M4 — Handler GUI (~2–3 weeks)

- [ ] GTK4/libadwaita card (SPEC §9):
  - Open once and Install;
  - toggles for sensitive permissions;
  - the protection label;
  - a double confirmation for Full trust.
- [ ] MIME registration for `*.ulai` and AppImage type 2 (shared-mime-info XML
      plus `MimeType=` in the desktop file). Double-click works without the
      executable bit.
- [ ] Legacy AppImage flow, Strict by default.
- [ ] Accessibility: keyboard-only use and screen-reader labels.

## M5 — Updates (~1–2 weeks)

- [ ] Read `.upd_info`, fetch, verify with the pinned key, switch atomically,
      and roll back if the app fails to launch.
- [ ] UX for blocked key changes.

## M6 — Hard problems (open-ended)

- [ ] Library conflict resolution for host GPU drivers, newest copy wins
      (SPEC §11.2).
- [ ] Electron/Chromium sandbox compatibility (SPEC §14 O2).
- [ ] Portable mode and the shared driver pack (SPEC §11.3); Alpine (musl).
- [ ] Isolation strategy for Landlock ABI < 9 (ADR-013).
- [ ] aarch64 builds.

## Test matrix

| System | Why it's in the matrix | Expected label |
|---|---|---|
| Arch Linux, dev host, NVIDIA proprietary | Newest kernel; native GPU mode on NVIDIA | **Strong** (ABI 10, kernel 7.2.9), measured 2026-10-21 |
| Ubuntu LTS (24.04 and 26.04) | Most users; AppArmor user-namespace restrictions | 24.04.5 with HWE kernel 7.0: **Weak** (ABI 8), measured 2026-10-21. 26.04: check |
| Fedora (current) | SELinux, GNOME | Check |
| Debian 13 | Kernel 6.12, so Landlock ABI 6 | Weak |
| openSUSE Tumbleweed | Rolling release, KDE | Check |
| Linux Mint (current) | Popular with people leaving Windows | Check |
| Alpine (from M6) | musl, needs portable mode | — |

## Reference apps

Initial set (check that each is actually available as an AppImage), chosen to
cover different toolkits and runtimes:

- an Electron app, e.g. Obsidian or Joplin;
- a Qt app, e.g. Krita or Kdenlive;
- a GTK app, e.g. Inkscape;
- a GPU-heavy app, e.g. OBS Studio;
- a command-line tool;
- two or three AnyLinux (sharun) AppImages.

## Benchmarks (for the paper and the demo)

Measure:

- cold and warm time to first window;
- memory use (RSS);
- disk use, with and without deduplication;
- launch overhead of `ulai-run` compared with running the same AppImage
  directly, and with the Flatpak build where one exists.

Report the hardware, the kernel and at least 10 runs with variance.

## Public demo

A two-minute video:

1. Download a `.ulai` file on Arch, Ubuntu and Fedora, double-click it, see the
   card, and the app runs.
2. Run the stealer test app in Guarded mode: every attempt fails, with the
   protection label visible on screen.
