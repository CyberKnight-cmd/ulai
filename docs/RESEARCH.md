# Research notes and prior art (October 2026)

These are the findings that shaped the design. Where a link is missing, the
source is named so it can be found; add links as they are re-verified.

## Landscape

- **Flatpak** is the de facto desktop channel.
  - Development stalled in early 2025, then restarted with new maintainers
    (Linuxiac, 2025).
  - Germany's Sovereign Tech Agency is funding €508,640 over two years for
    network isolation, entitlements and new portals (Modal, August 2026).
  - "Flatpak Next" (Linux App Summit 2026) proposes systemd-appd for app
    identity and permissions. This may make systemd a dependency (OSNews,
    Phoronix).
  - 2026 security releases fixed sandbox escapes and a local root escalation
    (Phoronix, August 2026).
- **Snap** has a single store.
  - In January 2026, hijacked publisher domains were used to push wallet
    stealers (popey.com; Help Net Security).
  - CVE-2026-8933 is a local privilege escalation in snap-confine (Qualys,
    July 2026).
- **AppImage** has no sandbox and breaks when hosts change: libfuse2 was
  removed, and Ubuntu 24.04+ and Debian 13+ restrict user namespaces.
  - Spec: https://github.com/AppImage/AppImageSpec/blob/master/draft.md
- **AnyLinux / sharun** bundles everything, including the dynamic loader and
  libc, compresses with DwarFS, and uses uruntime's fallbacks when FUSE is
  missing.
  - https://github.com/Link4Electronics/AnyArch-AppImages
  - https://gh.nn.ci/pkgforge-dev/Anylinux-AppImages
  - Self-contained Mesa: https://github.com/pkgforge-dev/MESA-AppImage
- **Linyaps** (deepin) ships UAB bundles and claims 10+ distros, but has little
  traction outside deepin/UOS.
- **Steam Linux Runtime / pressure-vessel** runs apps in a container but
  imports the host's graphics drivers, swapping in newer host libraries where
  the drivers need them.
- **manylinux** (PEP 600 and auditwheel) is the only mass-adopted binary
  contract based on a glibc floor.
- **LSB** died in 2015.
  - https://lwn.net/Articles/658289
  - https://en.wikipedia.org/wiki/Linux_Standard_Base

## ABI and GPU

- Removing DT_HASH from glibc (2022) broke Easy Anti-Cheat. A CodeWeavers
  developer argued that Win32 is the only stable ABI on Linux (Arek Hiler's
  blog, 2022).
- Cross-distro ABI data prototype (libabigail):
  https://developers.redhat.com/articles/2024/05/20/application-binary-interface-compatibility-testing-libabigail
- Failure when bundled libraries clash with host drivers:
  https://gitlab.freedesktop.org/mesa/mesa/-/issues/5788
- NVIDIA's proprietary userspace is not part of Mesa, so Mesa-based stacks
  reach NVIDIA cards only through nouveau:
  https://github.com/waydroid/waydroid/discussions/1619
  - It also lacked musl support as of December 2022:
    https://wiki.alpinelinux.org/wiki/NVIDIA
- Flatpak's shared Mesa extension is about 140–170 MB. On a fresh system, a
  1.5 MB app needed about 1 GB of runtime downloads:
  https://discourse.flathub.org/t/flatpak-install-what-does-the-download-column-indicate-exactly/7262
- Linus Torvalds on shared libraries (May 2021): worth sharing only for truly
  standard system libraries; one-off libraries shouldn't be shared.
  - https://lkml.rescloud.iu.edu/2105.0/00127.html
  - https://lkml.iu.edu/hypermail/linux/kernel/2105.0/00435.html

## Security

- Dunlap, Enck and Reaves, "A Study of Application Sandbox Policies in Linux"
  (SACMAT 2022): 90.1% of Snaps versus 58.3% of Flatpaks were tamperproof.
- Free Download Manager supply-chain backdoor, 2020–2022. It used cron for
  persistence and stole browser data, passwords, wallets and cloud credentials:
  https://securelist.com/backdoored-free-download-manager-linux-malware/110465/
- Chromium stopped writing download-origin xattrs on Linux in 2019 (no security
  benefit, privacy risk):
  https://chromium.googlesource.com/chromium/src/+/a9b4fb70b4318b220deee0da7b1693d16b8ed071
- Landlock documentation (ABI table, best-effort pattern, `no_new_privs`
  requirement): https://docs.kernel.org/next/userspace-api/landlock.html
  - landrun, for the ABI 9 feature list:
    https://pkg.go.dev/github.com/zouuup/landrun
- Double-click UX: GNOME needs the executable permission set by hand, while
  KDE's Dolphin asks before executing.
  - https://bugs.kde.org/show_bug.cgi?id=392147
  - Long-standing AppImage discussion:
    https://github.com/AppImage/AppImageKit/issues/58

## Ideas parked for later

- **Apps as links.** fanotify pre-content events (Linux 6.14) let a service fill
  in file contents on first access.
  - https://lwn.net/Articles/998968/
  - https://github.com/amir73il/fsnotify-utils/wiki/Hierarchical-Storage-Management-API
- **Cross-OS:**
  - Cosmopolitan/APE (llamafile) runs one file on Linux, macOS, Windows and the
    BSDs, for CLI tools only;
  - WASI 0.3 shipped in June 2026.

## Naming

- `.ulx` is Glulx: https://fileinfo.com/filetypes/u
- No registered use of `.ulai` found (October 2026).

## Tooling

- Claude Code reads CLAUDE.md, which imports AGENTS.md:
  https://code.claude.com/docs/en/claude-md

## Evidence: systems tested with `ulai doctor`

All six systems were measured on 2026-10-21 with the same static `ulai` binary
(sha256 `5874501a…`, built from commit `0f6c8d7`), run as an unprivileged user.
Details for each system are in the experiment log below.

| System | Kernel | Landlock ABI | Label | User-namespace probe | FUSE | libc |
|---|---|---|---|---|---|---|
| Arch Linux (dev host, real hardware) | 7.2.9-arch1-1 | 10 | Strong | all 6 steps ok | /dev/fuse; fusermount3 + fusermount; libfuse2 | glibc 2.44 |
| Ubuntu 24.04.5 LTS (real hardware, HWE kernel) | 7.0.0-38-generic | 8 | Weak | fails at `setgroups` (EACCES); AppArmor restriction on | /dev/fuse; fusermount3 + fusermount; no libfuse2 | glibc 2.39 |
| Debian 13 (VM) | 6.12.113+deb13-cloud-amd64 | 6 | Weak | all 6 steps ok | /dev/fuse; no fusermount; no libfuse2 | glibc 2.41 |
| Fedora 44 Cloud (VM) | 6.19.10-300.fc44.x86_64 | 7 | Weak | all 6 steps ok | /dev/fuse; fusermount3; no libfuse2 | glibc 2.43 |
| Ubuntu 26.04.1 LTS (VM) | 7.0.0-38-generic | 8 | Weak | fails at `setgroups` (EACCES); AppArmor restriction on | /dev/fuse; fusermount3 + fusermount; no libfuse2 | glibc 2.43 |
| GitHub Actions `ubuntu-latest` (Ubuntu 24.04) | 7.0.0-1017-azure | 8 | Weak | fails at `setgroups` (EACCES); AppArmor restriction on | /dev/fuse; fusermount3 + fusermount; no libfuse2 | glibc 2.39 |

The userns probe steps, in order, are `unshare`, `setgroups`, `uid_map`,
`gid_map`, `mount_private` and `mount_tmpfs`. "fusermount3 + fusermount" means
both are present and setuid root. The VMs are headless cloud images with no
desktop session.

## Experiment log

Add one entry per experiment, in this format:
`YYYY-MM-DD · system and kernel · what was tested · result · commit link`.

- 2026-10-21 · Arch Linux dev host, kernel 7.2.9-arch1-1, x86_64, NVIDIA
  open kernel module 615.78.08, COSMIC on Wayland · M0 `ulai doctor`, static
  musl build · commit e35e62b
  - **Landlock:** the raw `landlock_create_ruleset(NULL, 0, VERSION)` returns
    **ABI 10**, so the label is **Strong** and every SPEC feature is
    enforceable. The active LSMs are `capability,landlock,lockdown,yama,bpf`.
  - **`landlock` crate 0.4.7 cannot report this.** `LandlockStatus::current()`
    is private, a status is only returned after creating a ruleset or
    restricting yourself, and the `ABI` enum stops at V9 (10 maps to V9). Hence
    the raw syscall in `ulai-core/src/sys.rs`.
  - **Not verified:** the feature→ABI table (TCP 4, IOCTL_DEV 5, scoping 6,
    audit 7, pathname sockets 9, UDP 10) comes from SPEC. The 7.2 uapi header
    defines the `RESOLVE_UNIX` and UDP rights, but I did not check which ABI
    introduced each one against kernel sources.
  - **User namespaces:** `max_user_namespaces=94304`,
    `unprivileged_userns_clone=1`, no AppArmor sysctl. As uid 1000, all six
    probe steps succeed: unshare, setgroups, uid_map, gid_map, `MS_PRIVATE`
    on `/`, and a tmpfs mount.
    - The host's `/proc/self/mountinfo` was identical before and after the
      probe (27 mounts).
    - The temporary probe directory was removed.
    - The shell was confirmed to run in the initial user namespace, with no
      seccomp and no `no_new_privs`.
  - **Network:** `strace -f -e trace=%network ulai doctor --json` shows zero
    network syscalls, including in child processes.
  - **Static musl build:** `ulai` is a 1.2 MB static-pie and `ulai-run` is
    0.4 MB. Neither has `PT_INTERP` or `NEEDED`.
    - Output is byte-identical to the glibc debug build.
    - It reports the host's glibc 2.44, so the value is not inferred from our
      own libc.
    - It also works under `env -i`, with no `PATH`.
  - **Speed:** 10 runs of `doctor --json` took 49–51 ms (median 50 ms),
    including the child-process probe.
  - **Not done:** the three test-matrix VMs (M0's "done when"), and running
    the CI workflow on GitHub.
- 2026-10-21 · Ubuntu 24.04.5 LTS on real hardware, HWE kernel
  7.0.0-38-generic, x86_64, Intel GPU (i915, 0x8086:0x0152) · M0 `ulai doctor`
  over SSH as uid 1000, with the static musl binary (sha256 `5874501a…`) built
  from commit 0f6c8d7
  - **Landlock:** **ABI 8 → Weak**. TCP, IOCTL_DEV, scoping and audit are
    enforceable; pathname sockets (9) and UDP (10) are not. The active LSMs
    are `lockdown,capability,landlock,yama,apparmor,ima,evm`. I had expected
    ABI 6; the HWE 7.0 kernel is newer than I assumed. On this machine,
    Guarded mode would carry the ADR-013 caveat.
  - **User namespaces:** `apparmor_restrict_unprivileged_userns=1`,
    `unprivileged_userns_clone=1`, `max_user_namespaces=41022`. In the doctor
    probe, `unshare(CLONE_NEWUSER|CLONE_NEWNS)` **succeeds**, and the next
    step (writing `setgroups`) fails with **EACCES**.
    - The kernel log shows AppArmor `userns_create` → "transitioning profile"
      to `unprivileged_userns`, then `DENIED capable sys_admin` for `ulai`.
    - Cross-check: util-linux `unshare --user --map-root-user` hits the same
      denial but reports `uid_map: EPERM`, because it writes uid_map first.
      `unshare --user true` (no maps) succeeds.
    - Conclusion: under this restriction, creating the namespace works, but
      nothing privileged inside it does. This is input for ADR-013 option (b)
      and SPEC O2.
  - **Other probes:** Yama `ptrace_scope=1`. `/dev/fuse` and setuid-root
    `fusermount`/`fusermount3` are present, but **no `libfuse.so.2`**. glibc
    is 2.39. `xdg-dbus-proxy` 0.1.5 is installed. Mesa ships eight Vulkan
    ICDs, plus the `50_mesa` EGL vendor file. The loaders were found via
    `ldconfig` under `/lib/x86_64-linux-gnu`.
  - **Every section reported `status: ok`** with no errors. Both runs exited
    0. No `/tmp/ulai-doctor-*` directory was left behind.
  - **Not covered:** no graphical session was logged in (only the GDM
    greeter), so the Session section shows the SSH `tty` session, and
    Wayland/X11 detection is untested on this machine.
- 2026-10-21 · Three QEMU/KVM VMs (2 vCPU, 2 GB) hosted on the Ubuntu 24.04
  machine (i3-3220, QEMU 8.2.2), booted from official cloud images
  (checksums verified; checksum files not signature-checked) with
  `scripts/vm-doctor.sh` · M0 `ulai doctor` as an unprivileged guest user
  (uid 1000), same static binary (sha256 `5874501a…`)

  | Guest | Kernel | Landlock | Label | userns probe | Yama | glibc |
  |---|---|---|---|---|---|---|
  | Debian 13 (trixie) | 6.12.113+deb13-cloud-amd64 | ABI 6 | Weak | all steps ok | 0 | 2.41 |
  | Fedora 44 Cloud | 6.19.10-300.fc44 | ABI 7 | Weak | all steps ok | 0 | 2.43 |
  | Ubuntu 26.04.1 LTS | 7.0.0-38-generic | ABI 8 | Weak | fails at `setgroups` (EACCES), `apparmor_restrict_unprivileged_userns=1` | 1 | 2.43 |

  - **Labels:** Debian 13's ABI 6 matches the roadmap's prediction. Fedora
    has SELinux in its LSM list and no `unprivileged_userns_clone` sysctl;
    doctor correctly omits that key there. Ubuntu 26.04 keeps the AppArmor
    user-namespace restriction, with the same behaviour as on 24.04.
  - **No guest is at ABI ≥ 9.** So far, only the Arch dev host gets Strong.
  - **xdg-dbus-proxy is not installed** on any of the three cloud images.
    `fusermount3` is present on Fedora and Ubuntu; libfuse2 is on none.
  - **GPU:** the cloud images are headless.
    - Fedora and Ubuntu show QEMU's standard VGA as `card0` (0x1234:0x1111,
      `bochs-drm`, unknown stack). Debian's `-cloud` kernel has no DRM driver
      at all.
    - None of the three has render nodes, Vulkan/EGL manifests or loaders.
  - **Every section reported `status: ok`** with no errors, both runs exited
    0, and no probe directories were left behind.
  - **Timing:** a full VM cycle (boot, cloud-init, two doctor runs,
    teardown) took about 60 s for Debian (after a 34 s image download),
    135 s for Fedora and 112 s for Ubuntu 26.04, including their downloads.
  - **Not covered:** desktop sessions and real GPUs in these guests,
    openSUSE Tumbleweed and Linux Mint.
- 2026-10-21 · GitHub Actions `ubuntu-latest` runner (Ubuntu 24.04, kernel
  7.0.0-1017-azure) · first CI run of the M0 workflow and the doctor smoke
  test · run 39550362723
  - fmt, clippy, the unsafe check, 91 tests (+1 ignored) and the static musl
    build all passed.
  - The runner's doctor output: **ABI 8 → Weak**,
    `apparmor_restrict_unprivileged_userns=1`, userns probe failing at
    `setgroups` with EACCES (the same pattern as on real Ubuntu), glibc 2.39,
    every section `ok`.
  - So the CLI integration tests, including the real re-exec probe, pass on a
    restricted Ubuntu kernel as well as on Arch.
