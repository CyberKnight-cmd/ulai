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
- Contributors and coding agents: start with [AGENTS.md](AGENTS.md)

## License

To be decided by the project owner (see ADR-012 in docs/DECISIONS.md).
