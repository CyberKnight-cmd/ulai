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
- 2026-10-21/22 · M1 spikes S1–S4 (no production code). Fixtures were built
  in a disposable Ubuntu 26.04 VM (kernel 7.0) on the Ubuntu machine, using
  `scripts/vm-run.sh`. Analysis ran on the Arch dev host (kernel 7.2.9) and
  only *read* the files; no AppImage was executed.
  - **S1, what the signature covers.** Built signed AppImages with upstream
    `appimagetool` (continuous build 313, git 854e19e, gpgme, GnuPG 2.4.8)
    using throwaway RSA-3072 and Ed25519 keys, and with go-appimage
    `appimagetool` (release 951, reports "version 305") using RSA-3072.
    - For each file, tested 4 digest variants × 4 message variants with
      `gpg --verify`. **Exactly one combination verified each time:**
      SHA-256 over the file with `.sha256_sig` and `.sig_key` zero-filled,
      signed as the lowercase hex string with no newline.
    - Zeroing `.digest_md5` as well breaks upstream signatures, because
      upstream fills that section. go-appimage leaves it empty.
    - Upstream: text (0x01) signatures with SHA-512, for both RSA and EdDSA.
      go-appimage: binary (0x00) with SHA-256.
    - Source reading agrees. Upstream (`src/appimagetool_sign.c`) hashes,
      signs, then embeds the signature and then the key, so both sections
      are still zero when the hash is taken. go-appimage
      (`internal/helpers/digest.go`) hashes both ranges as `0x00` bytes.
      Krita's `validate_appimage_signature.sh` zeroes each section
      separately with `dd`, then runs `tr -d '\n'`.
    - go-appimage quirks:
      - it uses the deprecated `golang.org/x/crypto/openpgp`, so RSA only;
      - it reads `pubkey.asc`/`privkey.asc` from the git repository root and
        **deletes `privkey.asc`** after reading it;
      - outside a git repository it signs but silently **does not embed the
        key**, still exiting 0 ("Almost a success").
    - In all runtimes seen, `.sha256_sig` ends exactly where `.sig_key`
      starts. ULAI still zeroes the two ranges independently (SPEC §3.2).
    - gpg 2.4.8 cannot create v6 keys, so v6 and RFC 9580 Ed25519 test
      vectors still need another source.
  - **S1b, rPGP 0.21.** Using gpg-made signatures of the same shapes over a
    64-character hex message:
    - text/SHA-512 and binary/SHA-256 verify for RSA and legacy EdDSA keys;
    - adding a trailing newline makes every signature fail;
    - **rPGP accepts an RSA signature with SHA-1**, so ULAI must reject
      SHA-1 and MD5 itself by checking the hash algorithm, not rely on the
      library.
  - **S2, filesystem readers.**
    - **SquashFS:** the seven SquashFS apps use only zstd (4) and gzip (3).
      backhand's zstd is the C libzstd, which breaks the static musl build
      (no `x86_64-linux-musl-gcc`), and would mean decompressing untrusted
      input in C.
      - A custom backhand `CompressionAction` that decodes zstd with
        `ruzstd` 0.9.1 (pure Rust, MIT), with gzip via `flate2`/miniz_oxide,
        builds as a static-pie with **zero `-sys` crates**.
      - It read **every file of all seven apps** (32,576 files, about
        3.2 GB) without errors, in 0.3–6.4 s each.
      - Per-file SHA-256 is **identical to `unsquashfs` 4.6.1** for Neovim
        (zstd, 2,130 files) and KeePassXC (gzip, 284 files).
    - **DwarFS:** `dwarfs` 0.2.1 (oxalica) read every file of the three
      AnyLinux apps (mpv, GIMP, OBS: 19,423 files, about 1.7 GB) in
      0.15–1.12 s. **Not yet cross-checked** against upstream
      `dwarfsextract`, because the Ubuntu machine was unreachable on
      2026-10-22.
      - Its zstd is also C (`zstd-safe`), but in a single call site
        (`section.rs:638`) that already enforces a decompressed-size limit,
        so a pure-Rust `ruzstd` path is a small change to propose upstream.
      - `squishy` 0.5.1's DwarFS code is "ported from dwarfs-rs" (modified
        copy, about 20% different), so it is not an independent
        implementation.
  - **S3, Krita.** The official `krita-6.0.4-x86_64.AppImage` has **no
    embedded signature**: Krita's release script
    (`strip_appimage_signature.sh`) nulls both sections to regenerate zsync
    files.
    - Krita instead publishes a separate `.sig`, which verifies over the
      **whole file**: v4 RSA, SHA-512, binary, primary key
      `E9FB29E74ADEACC5E3035B8AB69EB4CF7468332F` (uid "Dmitry Kazakov (main
      key)", fetched from keyserver.ubuntu.com).
    - Only the fingerprint was checked, not who owns the key.
  - **S4, real-app set** (fetched to `~/.cache/ulai-real-apps`, never
    committed):
    - SquashFS: Krita 6.0.4, Kdenlive 26.08.2, Shotcut 26.9.27, KeePassXC
      2.7.12, Audacity 4.0.1, Obsidian 1.14.4 (Electron), Neovim 0.12.6
      (command line).
    - AnyLinux DwarFS: OBS Studio 32.2.2, GIMP 3.2.6, mpv 0.41.0.
    - **None of the 10 carries an embedded AppImage signature.** All are
      ELF64, all have the filesystem magic exactly at the ELF end, and all
      four runtimes put the sections in the same order.
    - Inkscape was left out because no stable direct download URL was
      found.
- 2026-10-22 · Arch dev host (Ryzen 7 7435HS, kernel 7.2.9) and a disposable
  Ubuntu 26.04 VM on the Ubuntu machine · M1 follow-ups
  - **DwarFS cross-check (closes the open S2 item).** Upstream
    `dwarfsextract` (dwarfs-universal 0.15.8, sha256 `0ed66df8…`) ran in the VM.
    For mpv 0.41.0 (1,764 files, 260 symlinks) and GIMP 3.2.6 (9,772 files,
    668 symlinks), the `dwarfs` 0.2.1 crate gives the same counts and a
    **byte-identical SHA-256 for every file**.
    - Gotcha: `/tmp` in the 26.04 guest is a small tmpfs, so extract into the
      guest's home directory.
  - **ruzstd vs C zstd throughput.** Measured with backhand, reading every
    file of Krita 6.0.4 (zstd, 1,134 MB decompressed), single-threaded, warm
    page cache, 3 runs each, LTO release builds:
    - C libzstd: 1.14–1.17 s, about **980 MB/s**;
    - ruzstd 0.9.1: 3.53–3.55 s, about **320 MB/s**, i.e. about 3.1× slower.
    - This affects M3 extraction time (about 3.5 s for Krita on this CPU).
      Extraction can be parallelised across files, because ULAI's block cap
      is per thread.
  - **Real-app signature checks with `ulai verify`.** Krita 6.0.4's official
    detached `.sig` (binary, RSA-2048, SHA-512) verifies: exit 0, 0.62 s for
    386 MB in a release build. One flipped byte at offset 200,000,000 gives
    invalid (exit 4).
  - **Upstream proposal:** an optional pure-Rust zstd backend for dwarfs-rs,
    oxalica/dwarfs-rs#3 (opened 2026-10-22; the repository was last pushed
    2025-06-09).
- 2026-10-22 · Arch dev host (kernel 7.2.9) · M1 implementation results
  - **Real-app run.** verify, inspect and validate ran over all 10 real
    AppImages: 30 runs, each traced with `strace -f -e
    trace=execve,execveat`, and **every run showed exactly one exec (ulai
    itself)**.
    - Exit codes as designed: verify 3 (no embedded signatures), inspect 0
      for SquashFS and 5 for DwarFS, validate 4 (no manifest) or 5 (DwarFS).
    - validate needs 0–4 s per app and parses up to 1,250 bundled ELF files
      in memory.
  - **What validate found in real apps** (they are legacy AppImages, so
    "does not conform" is expected; the findings themselves are the data):
    - **Leaked build-machine RPATHs:** Kdenlive has 145 files with RPATH
      `/builds/multimedia/kdenlive/...`, Shotcut 354 with
      `/root/shotcut/Shotcut/Shotcut.app/lib`, and Krita 3 with
      `/builds/graphics/krita/_install/...`. A local user who can create
      those paths can make the loader pick up their libraries.
    - **Bundled driver-stack libraries:**
      - Obsidian (Electron) ships ANGLE's `libEGL.so` and `libGLESv2.so`
        plus the Vulkan loader `libvulkan.so.1`;
      - Shotcut ships `libvulkan.so.1`;
      - Audacity ships `libOpenGL.so.0`;
      - Kdenlive ships fontconfig (a warning).
    - Under SPEC §11.1, every Electron app packaged this way would fail
      native-mode validation. This needs a policy decision before M3.
    - **A classifier bug the run exposed:** Qt's Wayland plugins
      `libdrm-egl-server.so` and `libvulkan-server.so` were flagged until
      families were matched exactly (SPEC §11.1).
    - Highest symbol versions required: GLIBC 2.30–2.35, GLIBCXX
      3.4.26–3.4.32. Only Krita bundles libstdc++.
  - **Fuzzing (cargo-fuzz, nightly 1.101):** 1 hour each, the six targets
    in parallel, seeded from the fixtures. **No crash, hang (10 s timeout)
    or OOM in any target.** Executions per target:
    - container 5.6 M, image 9.8 M, signature 5.6 M;
    - manifest 52.1 M, elf 8.9 M, desktop 23.8 M.

    The roadmap's "several hours each" is still to do.
  - **Independent OpenPGP vectors:**
    - RFC 9580 A.3/A.6 (v6 Ed25519, text signature) verifies, and its
      fingerprint matches the RFC. A.1, a bare v4 key without a
      self-signature, is rejected.
    - Sequoia sq 1.3.1 (sequoia-openpgp 2.1.0) made a v6 key with a
      certification-only primary key and an Ed25519 signing subkey (v6
      back-signature); it verifies.
    - GnuPG 2.4.9 cannot even parse v6 packets.
    - rPGP 0.21 silently skips v5 key packets, so ULAI detects them itself
      and reports "unsupported".
  - **ELF32:** an AppImage built with upstream `runtime-i686` and signed by
    appimagetool has its filesystem magic exactly at the computed ELF end,
    and verify is valid. This closes SPEC §3.1's ELF32 check.
  - **Hostile files:** a flipped signature byte gives invalid; symlinks out
    of the image never read host files; a 20 MB ratio bomb is stopped by
    the 100× limit. Mutating any protection makes a test fail, except where
    noted in the tests (the per-block cap is proven by a unit test, because
    a crafted end-to-end block bomb is caught earlier by backhand).
- 2026-10-22 · Disposable Ubuntu 26.04 VM (6 GB, 4 vCPU) on the Ubuntu
  machine; VM writes on its HDD after the SSD incident below · OpenPGP
  interoperability test suite, `verify-only` subset
  - **Setup:**
    - suite commit `601692566e9d` (2026-10-09), built with Ubuntu's rustc
      1.93.1;
    - backends: `sqop` (sequoia-sop 0.37.3, Sequoia 2.1.0) as the producer
      and reference, and `tools/ulai-sop` (ULAI's own verifier and policy);
    - the README's package list lacks `libsqlite3-dev`, which the build
      needs.
  - **Results** (117 cases; the suite's score means "met the expectation"):

    | Implementation | Met | Missed | Neutral |
    |---|---|---|---|
    | sqop | 100 | 2 | 15 |
    | ulai-sop | 84 | 16 | 15 |

    Both miss the same 2 "V6 issuer FP" cases. ULAI's 14 own misses, as
    first analysed:
    - **Accepted what should be rejected (4), security-relevant:**
      signatures whose creation time is in the future (3 cases), and a
      signature with a critical unknown notation (1 case). rPGP rejects
      critical subpackets of unknown type while hashing (that case passed)
      but not critical notations. sqop rejects all four.
    - **Rejected what should be accepted, fail-closed (10):** "Mock PQ
      subkey" (6), one mock certificate over ULAI's 64 KiB key limit, and
      "SIG4_ricarda" plus the two mixed cases that use Ricarda's
      certificate (3).
  - **Correction, after re-analysis (same day):** the 3 Ricarda cases were
    **not** an rPGP problem, and those signatures carry no unknown packets.
    `ulai-sop` passes each signature to the verifier in binary form.
    Ricarda's binary signature ends in a `0x00` byte, and ULAI stripped
    trailing NULs from binary input as well as from armor, which truncated
    the signature ("PacketBodyReader errored"). This was a ULAI bug. It was
    fixed in `4c587eb`, together with a regression test.
  - Re-checked locally on Arch Linux after the fixes, case by case, from
    the artifacts saved in `results.json`, with `tools/ulai-sop`. The full
    suite has **not** been rerun.
    - The future-dated (3), critical-notation (1) and critical-subpacket
      cases are now rejected. Their unhashed variants are accepted, as the
      suite allows.
    - SIG4_ricarda and the two mixed Ricarda cases are now accepted.
    - "Mock PQ subkey": all `Unknown algo …` variants and all `… MPI
      encoding` variants are accepted. The three `… unknown curve, opaque
      encoding, small` cases (ECDSA, EdDSA, ECDH) still fail inside rPGP
      ("InvalidPacketContent"). Reported upstream as rpgp/rpgp#869, with a
      minimal reproducer that fails on rPGP 0.21.0 and on `main` at
      `136e5c883096`. The `big` variants are not in `results.json` (too
      large), so they were not re-checked.
    - The two "V6 issuer FP" cases fail in rPGP's signature parser
      ("Inconsistent subpacket length"). sqop misses them too, so they were
      not reported.
  - Raw results (`results.json`, 664 KB) are not committed; rerun with
    `tools/ulai-sop` and the payload described above.
- 2026-10-22 · Ubuntu machine (HP SSD S650 240GB, `sdc`) · **hardware
  incident during the interop build**
  - At 20:24:24 IST, SATA write commands to the root SSD timed out after
    42 s (`DID_TIME_OUT`), followed by I/O errors. ext4 aborted its journal
    and remounted `/` read-only.
  - After a restart, fsck ran and the system was clean. The rerun put every
    heavy write on the 1 TB HDD (`TMPDIR=/srv/archive/ulai-tmp`), and no disk
    error was logged in that boot.
  - The SSD's health (SMART) has not been checked; that needs root.
- 2026-10-22 · Arch Linux, kernel 7.2.9-arch1-1 · **rPGP 0.21 and packets
  next to a detached signature** (group 4 of the planned rPGP issue)
  - Method: a valid binary signature made by rPGP in a test, with one extra
    packet placed before or after it, then checked with
    `verify_detached`. The experiment test was removed afterwards.
  - Before the signature: marker (10), padding (21), unknown non-critical
    (40) and private (60) packets are skipped, and the signature verifies.
    An unknown critical packet (38) and a literal-data packet (11) make
    parsing fail.
  - After the signature: **every** extra packet is ignored, including the
    unknown critical packet and the literal-data packet.
    `DetachedSignature::from_bytes` returns the first signature and never
    reads the rest. GnuPG allows only signature, marker and padding packets
    in a detached signature. So the strictness gap is in how ULAI uses
    rPGP's API, not a bug in rPGP. It was not reported upstream; how to
    handle it is an open decision for the project owner.
  - Conclusion: rPGP already ignores unknown non-critical packets, as
    RFC 9580 §4.3 requires. Group 4 of the rPGP issue was dropped for that
    reason.
- 2026-10-22 · Arch Linux · **rPGP and unknown critical subpackets**
  - rPGP 0.21 rejects a critical subpacket of unassigned type (for example
    40) while hashing, both when signing and when verifying. It accepts
    critical subpackets in the experimental range (100–110), critical
    notations and critical regular expressions. ULAI now checks all of
    these itself, before the cryptography (SPEC §3.2).

