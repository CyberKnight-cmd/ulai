# AGENTS.md — instructions for coding agents working on ULAI

## What this project is

ULAI makes Linux apps work like a Windows `.exe`: one file, double-click, any
distro — but signed, sandboxed by the kernel, and cleanly installable. The file
is an AppImage type 2 superset; the handler verifies, sandboxes (Landlock) and
integrates it.

Read in this order before writing code:
`README.md` → `docs/SPEC.md` → `docs/ROADMAP.md` (find the current milestone)
→ `docs/DECISIONS.md`. `docs/RESEARCH.md` explains *why*; read it before
proposing alternatives to an accepted decision.

## Non-negotiable rules

1. **Never execute code from a file that is being inspected, verified or
   installed.** Parse ELF and SquashFS in-process. Apps run only through
   `ulai-run`, after verification.
2. **Fail closed.** If the requested trust level cannot be enforced on this
   kernel, do not launch. Report why, and require an explicit user action to
   choose Full trust instead.
3. **No root at runtime.** After the handler package is installed, nothing may
   need root, write outside the user's XDG directories, or rely on setuid helpers.
4. **Never bundle GPU drivers** (Mesa, NVIDIA userspace, libGL/libEGL/libGLX/
   libvulkan/libgbm/libdrm, LLVM) inside app images. See SPEC §11.
5. **Probe, never assume, kernel features.** Query the Landlock ABI at runtime,
   apply SPEC §6.2, and always report the effective protection label.
6. **No telemetry.** Network access only for user-initiated downloads and the
   update checks described in SPEC §12.
7. **Do not change an accepted ADR silently.** If a task conflicts with
   `docs/DECISIONS.md`, stop and ask the project owner.
8. **No unverified claims** in docs, commit messages or the README. If something
   was not tested on a real system, say so explicitly.

## Architecture (Rust workspace)

```
crates/
  ulai-core/      library: manifest, ELF/AppImage parsing, SquashFS reading,
                  signature verification, policy model, store, desktop integration
  ulai-cli/       `ulai` binary: doctor, inspect, validate, verify, install,
                  remove, list, run, update
  ulai-run/       minimal launcher: builds the Landlock ruleset, starts
                  xdg-dbus-proxy, sets no_new_privs, execs the app.
                  Keep it small and auditable.
  ulai-handler/   GTK4 + libadwaita GUI: double-click flow, consent dialogs
packaging/        .desktop file, shared-mime-info XML, distro packaging (later)
tests/fixtures/   small synthetic test apps; large real AppImages are fetched by
                  scripts and never committed
```

Candidate crates (confirm each is maintained and licence-compatible before
adding): `landlock` (official Rust bindings), `goblin` or `object` (ELF),
`backhand` (SquashFS), `pgp` (rPGP, OpenPGP verification), `sha2`, `blake3`,
`serde` + `serde_json`, `clap`, `thiserror`, `anyhow`, `tracing`, `gtk4`,
`libadwaita`. If `landlock` lacks a newer ABI right that SPEC needs (for example
pathname UNIX-socket control), implement it in one small documented module and
propose it upstream.

## Engineering conventions

- Stable Rust, latest edition. `cargo fmt`, `cargo clippy --all-targets -- -D
  warnings` and `cargo test` must pass before any task counts as done.
- `#![forbid(unsafe_code)]` in every crate, except one `sys` module if raw
  syscalls are unavoidable; every `unsafe` block carries a `// SAFETY:` comment.
- Libraries return typed errors (`thiserror`); binaries use `anyhow`. Log with
  `tracing`. Never log secrets, file contents or full environment variables.
- Every security property in SPEC gets an automated test. The stealer suite
  (ROADMAP M2) is a regression gate for any change to `ulai-run` or the policy
  model.
- Small commits, Conventional Commits style (`feat(run): …`, `fix(core): …`).

## Workflow

1. Take the next unchecked task in the current milestone of `docs/ROADMAP.md`.
2. Write a short plan (files touched, tests to add). Share it before large
   changes, and always before touching `ulai-run`, the policy model or signature
   verification.
3. Tests first where practical; implement; run the full check suite.
4. Update `docs/SPEC.md` if behaviour changed, `docs/DECISIONS.md` if a
   decision was made, tick the task in `docs/ROADMAP.md`, and append
   measurements to the experiment log in `docs/RESEARCH.md`.
5. Report what was verified, on which system and kernel, and what was not.

## Environments

- Primary dev host: Arch Linux with the NVIDIA proprietary driver. Native GPU
  mode must work here.
- Test VMs: see the test matrix in `docs/ROADMAP.md`.
- Landlock tests need a kernel with Landlock in the active LSM list
  (`cat /sys/kernel/security/lsm`). CI skips them when unavailable; run them
  locally before merging any security-relevant change.
