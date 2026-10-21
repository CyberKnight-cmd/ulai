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

## Experiment log

Add one entry per experiment, in this format:
`YYYY-MM-DD · system and kernel · what was tested · result · commit link`.
