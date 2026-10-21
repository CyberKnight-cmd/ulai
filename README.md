# ULAI — Universal Linux Application Interface

**One file. Double-click. Any distro. Sandboxed by default.**

ULAI gives Linux the convenience of a Windows `.exe` without its malware model:
download a `.ulai` file, double-click it, and the app runs — on any mainstream
distribution, without root, inside a kernel-enforced sandbox, with clean
install, uninstall and signed updates.

> **Status: pre-alpha, specification phase.** Nothing here is production-ready.
> Every claim in this repository must be backed by a test or a measurement.

## How it works

- **The file** is a strict superset of an AppImage (type 2): one ELF runtime plus
  one compressed image, with a manifest at `/.ulai/manifest.json` and a publisher
  signature in the standard AppImage signature sections. Existing AppImage tools
  keep working on it, and existing AppImages open in ULAI on day one.
- **The handler** (`ulai-handler`) opens the file on double-click — no `chmod +x`
  — verifies the signature, shows what the app is and what it may access, then
  runs it once or installs it.
- **The sandbox** is the kernel's own: Landlock + `no_new_privs` + a filtered
  session bus. No containers, no setuid helpers, no user namespaces. Apps see
  your real files and system; other apps' data, secrets and auto-start points
  stay off-limits unless you agree.
- **GPU drivers come from the host**, as on Windows. Apps never bundle them.

## Protection depends on your kernel

How well ULAI can isolate an app depends on the Landlock version of the
running kernel. `ulai doctor` reports it as a protection label:

- **Strong** needs Landlock ABI 9, which means **Linux 7.1 or newer**. Only at
  this level can ULAI stop an app from reaching the real session bus or the
  X11 socket.
- **Weak** (ABI 1–8) protects your files against honest and naive access, but
  is not real isolation from a malicious app. Most current distributions are
  here: in our tests, Ubuntu 24.04 and 26.04 (kernel 7.0), Fedora 44 (6.19)
  and Debian 13 (6.12) were all Weak. See ADR-013 for how this will be
  handled.
- **None** means no Landlock; sandboxed modes refuse to run.

Measured results are in [docs/RESEARCH.md](docs/RESEARCH.md).

## Principles

1. Depend only on what Linux promises to keep stable: the kernel ABI, versioned
   wire protocols (Wayland, D-Bus, …), and the GPU entry points.
2. Reuse before rebuild: AppImage, XDG specifications, AppStream, xdg-dbus-proxy.
3. Safe by default, real by default.
4. No root after the handler is installed. No telemetry. Ever.

## Documentation

- [Specification](docs/SPEC.md)
- [Roadmap and milestones](docs/ROADMAP.md)
- [Design decisions](docs/DECISIONS.md)
- [Research notes and prior art](docs/RESEARCH.md)
- [`ulai doctor --json` schema](docs/doctor-schema.md)
- Contributors and coding agents: start with [AGENTS.md](AGENTS.md)

## License

The tools are GPL-3.0-or-later; see [LICENSE](LICENSE) and ADR-012. So that
other projects can implement the format, the specification
([docs/SPEC.md](docs/SPEC.md)) is CC-BY-4.0 and the JSON Schemas
([schemas/](schemas/)) are MIT (ADR-015). Apps packaged as ULAI files keep
their own licences. [REUSE.toml](REUSE.toml) records the licence of every
file.
