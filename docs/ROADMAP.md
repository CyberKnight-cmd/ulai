# Roadmap

Durations are rough part-time estimates. Each milestone ends with a tagged
release and a short results entry in the experiment log in RESEARCH.md.

## M0 — Foundations and `ulai doctor` (~1 week)

- [x] Cargo workspace with the crates listed in AGENTS.md. CI runs fmt, clippy
      (`-D warnings`) and tests. *(First green GitHub Actions run on
      2026-10-21: run 39550362723.)*
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

*Status (2026-10-21): **all M0 tasks done.** Output was checked by hand on the
Arch dev host, on a real Ubuntu 24.04 machine, and in Debian 13, Fedora 44 and
Ubuntu 26.04 VMs (`scripts/vm-doctor.sh`). CI is green on GitHub. Not yet
tagged as a release.*

## M1 — Inspect, validate, verify (~2 weeks)

- [x] ELF parsing, AppImage magic and image offset (SPEC §3.1). SquashFS listing
      and reading in-process: no FUSE and no execution. DwarFS images are
      detected; `inspect` and `validate` report them as unsupported (exit 5),
      while `verify` works on them (SPEC §3.2, §16).
- [x] Manifest schema, and `ulai inspect` (human-readable and JSON).
- [x] Signature verification compatible with upstream AppImage signing, with
      test vectors from upstream-signed files. Resolves SPEC §14 O9.
- [x] `ulai validate` checks:
  - magic, manifest schema and permission vocabulary;
  - `own_paths` rules (SPEC §4);
  - no excluded libraries in the image, using ULAI's own list (SPEC §11.1);
    report GLIBCXX/CXXABI needs and whether libstdc++ is bundled;
  - highest glibc symbol version ≤ `glibc_floor`;
  - no RPATH/RUNPATH pointing at absolute host paths;
  - the entry point exists and is executable;
  - `arch` matches the image.
- [x] Fuzz the ELF, SquashFS and manifest parsers (cargo-fuzz), several hours each.
      *(2026-10-22: six targets exist and CI smoke-tests them; each has run
      for 1 hour without findings. The multi-hour runs are still to do.)*

**Done when:** inspect, validate and verify work on 10 real AppImages, and on 3
crafted hostile files (bad signature, path traversal in the image, a
decompression bomb), without executing any of them.

*Status (2026-10-23): "done when" is met. All three commands ran on the 10
real AppImages (30 runs) and on the crafted hostile files, each under
`strace -f -e trace=execve,execveat`, with no exec other than ulai's own.
All six fuzz targets ran for 3 hours each with no finding (RESEARCH.md).*

## M2 — Sandbox (`ulai-run`) and the stealer suite (~3 weeks) — core research milestone

Plan approved 2026-10-24 (ADR-013 → (d), SPEC §6.7).

- [ ] **Experiments first** (results in RESEARCH.md):
  - seccomp user notification with `ADDFD`, and `pidfd_getfd`, probed by
    `ulai doctor` on every test system;
  - what an address on a connected `AF_UNIX` stream or seqpacket socket can
    do with `sendto`/`sendmsg`;
  - `connect()` through `/proc/self/fd/<O_PATH fd>` to a socket;
  - io_uring `openat` and `connect` under Landlock.
- [ ] **Electron spike (decision point):** Obsidian under Landlock plus
      `no_new_privs`, with Chromium's sandbox on and with `--no-sandbox`, on
      Arch, and on Ubuntu 26.04 with and without an AppArmor profile for
      `ulai-run`. If Chromium's sandbox cannot run under Guarded on Ubuntu
      even with a profile, write up the options and stop. Electron apps are
      never silently defaulted to Full or `--no-sandbox`.
- [ ] Policy builder for Strict, Guarded and Full (SPEC §6), with ABI probing,
      protection labels and the fail-closed rules.
- [ ] `ulai-run --print-policy`: the exact Landlock ruleset, D-Bus policy and
      seccomp policy for an app (in M2, from `--appdir`).
- [ ] xdg-dbus-proxy integration (SPEC §7).
- [ ] Seccomp filter and `connect()` supervisor (SPEC §6.7), with a test that
      guards against a deadlock while the listener fd is handed over.
- [ ] **Stealer test app**, packaged as a ULAI file. Each attempt reports pass or
      fail:
  - Read secrets: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.netrc`,
    `~/.git-credentials`, browser profile directories, wallet directories.
    Also through a symlink planted in a user folder that points into
    `~/.ssh`.
  - Look up an item through the Secret Service.
  - Plant persistence: write `~/.bashrc`, drop a file into
    `~/.config/autostart/` and `~/.config/systemd/user/`, write `/etc/cron.d`,
    write a launcher into `~/.local/share/applications`, write into a
    `$PATH` directory such as `~/bin`, and use `at` and `crontab` (setuid).
  - Escape the sandbox:
    - run `systemd-run --user`, and call `StartTransientUnit` over D-Bus;
    - connect to the real session-bus socket and to X11;
    - io_uring `connect` and `openat`;
    - signal or ptrace a process outside the sandbox;
    - run `sudo` and `pkexec`.
  - Tamper with the ULAI store.
- [ ] **Gate:** on a kernel with the Strong label, every stealer attempt fails in
      Guarded mode, and the honest reference apps still work.
- [ ] Run the same suite on kernels with the Weak label, with the (d)
      supervisor. A system keeps the Weak label until the suite passes on it.
- [ ] Census: run the reference apps in Guarded mode and log Landlock denials
      (audit logging, ABI ≥ 7). Classify each breakage, tune the hidden
      allowlist, and update SPEC.
  - First on the Strong systems: Arch, plus a second VM with a 7.1+ kernel.
    Fedora 44 counts only if an updated kernel reaches ABI 9; otherwise it
    joins the Weak round.
  - Then on the Weak systems, once (d) works.
  - DwarFS apps are unpacked for the census with upstream `dwarfsextract`
    inside the test VM. That is harness setup only, never product code.
- [ ] **Fail-closed test:** in a VM booted without Landlock (`lsm=` without
      `landlock`), Strict and Guarded refuse to start.
- [ ] **Overhead:** launch time of `ulai-run` versus running the AppImage
      directly, n ≥ 10, with median and spread.

## M3 — Install, store, integration (~2 weeks)

- [ ] **Prerequisite, a hard requirement before any other M3 work:** full
      in-process DwarFS reading (listing and file contents) for legacy
      AppImages, with the same limits and hostile-file tests as SquashFS.
      Use the `dwarfs` crate (verified byte-identical to upstream
      `dwarfsextract`). Its zstd is C; a pure-Rust option was proposed
      upstream in oxalica/dwarfs-rs#3. If there is no response by the time M3
      is planned, fork the crate (MIT/Apache) with attribution and keep the
      patch upstreamable. Do not write our own DwarFS reader.

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
| Ubuntu LTS (24.04 and 26.04) | Most users; AppArmor user-namespace restrictions | 24.04.5 with HWE kernel 7.0 (real hardware): **Weak** (ABI 8). 26.04.1, kernel 7.0 (VM): **Weak** (ABI 8). Both measured 2026-10-21 |
| Fedora (current) | SELinux, GNOME | Fedora 44, kernel 6.19 (VM): **Weak** (ABI 7), measured 2026-10-21 |
| Debian 13 | Kernel 6.12, so Landlock ABI 6 | **Weak** (ABI 6, kernel 6.12.113, VM), measured 2026-10-21 |
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
