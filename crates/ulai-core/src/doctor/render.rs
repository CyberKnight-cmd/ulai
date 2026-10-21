//! Human-readable `ulai doctor` output.
//!
//! `✓` = present / enforceable, `✗` = absent / not enforceable,
//! `?` = unknown (followed by the reason). Plain text, no colours.

use std::fmt::Write as _;
use std::path::Path;

use super::gpu::{Card, Manifest, Stack};
use super::landlock::{FEATURE_TABLE, State};
use super::libs::Source;
use super::userns::ProbeOutcome;
use super::xdg::{BaseDir, DirSource};
use super::{Report, Section};

const OK: &str = "✓";
const NO: &str = "✗";
const UNKNOWN: &str = "?";

struct Out(String);

impl Out {
    fn heading(&mut self, title: &str) {
        let _ = writeln!(self.0, "\n{title}");
    }

    fn line(&mut self, mark: &str, text: impl AsRef<str>) {
        let _ = writeln!(self.0, "  {mark} {}", text.as_ref());
    }

    fn check(&mut self, good: bool, text: impl AsRef<str>) {
        self.line(if good { OK } else { NO }, text);
    }

    fn note(&mut self, text: impl AsRef<str>) {
        let _ = writeln!(self.0, "    note: {}", text.as_ref());
    }

    fn errors<T>(&mut self, s: &Section<T>) {
        for e in &s.errors {
            if e.field == "*" {
                self.line(UNKNOWN, format!("unknown: {}", e.reason));
            } else {
                self.line(UNKNOWN, format!("{}: unknown ({})", e.field, e.reason));
            }
        }
    }
}

fn p(path: &Path) -> std::path::Display<'_> {
    path.display()
}

pub fn human(r: &Report) -> String {
    let mut o = Out(format!(
        "ULAI doctor {} (report schema {})\n",
        r.ulai_version, r.schema
    ));

    o.heading("Kernel");
    if let (Some(rel), Some(arch)) = (&r.kernel.data.release, &r.kernel.data.arch) {
        o.line(OK, format!("{rel} ({arch})"));
    }
    o.errors(&r.kernel);

    o.heading("Linux security modules");
    if r.lsm.data.landlock_listed.is_some() {
        o.line(OK, format!("active: {}", r.lsm.data.active.join(",")));
        o.check(
            r.lsm.data.landlock_listed == Some(true),
            "landlock in the active list",
        );
    }
    o.errors(&r.lsm);

    landlock(&mut o, r);
    userns(&mut o, r);

    o.heading("Yama");
    let y = &r.yama.data;
    match (y.active, y.ptrace_scope) {
        (Some(true), Some(v)) => o.line(
            OK,
            format!(
                "ptrace_scope = {v} ({})",
                y.meaning.unwrap_or("unknown meaning")
            ),
        ),
        (Some(false), _) => o.line(NO, "not active (no ptrace_scope sysctl)"),
        _ => {}
    }
    o.errors(&r.yama);

    fuse(&mut o, r);

    o.heading("Host C library");
    let l = &r.libc.data;
    if let Some(v) = &l.glibc {
        o.line(OK, format!("glibc {v}"));
    }
    if let Some(m) = &l.musl_loader {
        o.line(OK, format!("musl loader: {}", p(m)));
    }
    if l.glibc.is_none() && l.musl_loader.is_none() && r.libc.errors.is_empty() {
        o.line(NO, "neither glibc nor a musl loader found");
    }
    o.errors(&r.libc);

    session(&mut o, r);
    gpu(&mut o, r);

    o.heading("xdg-dbus-proxy");
    let d = &r.dbus_proxy.data;
    match (&d.path, &d.version) {
        (Some(path), Some(v)) => o.line(OK, format!("{} (version {v})", p(path))),
        (Some(path), None) => o.line(OK, p(path).to_string()),
        (None, _) => o.line(NO, "not installed (needed for Strict and Guarded, SPEC §7)"),
    }
    o.errors(&r.dbus_proxy);

    xdg(&mut o, r);
    o.0
}

fn landlock(o: &mut Out, r: &Report) {
    o.heading("Landlock");
    let ll = &r.landlock.data;
    let label = ll.label.as_str();
    match ll.state {
        State::Available => {
            let abi = ll.abi.unwrap_or(0);
            o.line(OK, format!("ABI {abi} → protection label: {label}"));
            if ll.abi_newer_than_known {
                o.note("kernel ABI is newer than this ULAI knows; newer features not listed");
            }
        }
        State::NotBuilt => o.line(
            NO,
            format!("not built into this kernel (ENOSYS) → protection label: {label}"),
        ),
        State::Disabled => o.line(
            NO,
            format!("built in but disabled at boot (EOPNOTSUPP) → protection label: {label}"),
        ),
        State::Unknown => o.line(
            UNKNOWN,
            format!("ABI unknown → protection label: {label} (fail closed)"),
        ),
    }
    if ll.state == State::Available {
        for ((name, min), on) in FEATURE_TABLE.iter().zip(ll.features.as_array()) {
            o.check(on, format!("{name} (ABI ≥ {min})"));
        }
    }
    for n in &ll.notes {
        o.note(n);
    }
    o.errors(&r.landlock);
}

fn userns(o: &mut Out, r: &Report) {
    o.heading("User namespaces");
    let u = &r.userns.data;
    for (k, v) in &u.sysctls {
        o.line(OK, format!("{k} = {v}"));
    }
    match u.probe.result {
        ProbeOutcome::Ok => o.line(
            OK,
            "live probe: unshare, uid/gid maps and tmpfs mount all work",
        ),
        ProbeOutcome::Failed => {
            let failed = u.probe.steps.iter().find(|s| !s.ok);
            if let Some(s) = failed {
                o.line(
                    NO,
                    format!(
                        "live probe failed at: {} ({})",
                        s.step.describe(),
                        s.errno.as_deref().unwrap_or("no errno")
                    ),
                );
            }
        }
        ProbeOutcome::Unknown => {}
    }
    if u.running_as_root {
        o.note("running as root: results do not apply to unprivileged users");
    }
    o.errors(&r.userns);
}

fn fuse(o: &mut Out, r: &Report) {
    o.heading("FUSE");
    let f = &r.fuse.data;
    if let Some(dev) = f.dev_fuse {
        o.check(dev, "/dev/fuse");
    }
    for (name, helper) in [
        ("fusermount3", &f.fusermount3),
        ("fusermount", &f.fusermount),
    ] {
        match helper {
            Some(h) if h.setuid_root => o.line(
                OK,
                format!(
                    "{name}: {} (setuid root; unusable under no_new_privs)",
                    p(&h.path)
                ),
            ),
            Some(h) => o.line(OK, format!("{name}: {} (not setuid root)", p(&h.path))),
            None => o.line(NO, format!("{name}: not found")),
        }
    }
    if let Some(lib) = &f.libfuse2 {
        match &lib.path {
            Some(path) => o.line(OK, format!("libfuse.so.2: {}", p(path))),
            None => o.line(NO, "libfuse.so.2: not found"),
        }
    }
    o.errors(&r.fuse);
}

fn session(o: &mut Out, r: &Report) {
    o.heading("Session");
    let s = &r.session.data;
    let show = |o: &mut Out, key: &str, v: &Option<String>| match v {
        Some(v) => o.line(OK, format!("{key}={v}")),
        None => o.line(NO, format!("{key} unset")),
    };
    show(o, "XDG_SESSION_TYPE", &s.session_type);
    match (&s.wayland_display, s.wayland_socket_exists) {
        (Some(d), Some(true)) => o.line(OK, format!("WAYLAND_DISPLAY={d} (socket present)")),
        (Some(d), Some(false)) => o.line(NO, format!("WAYLAND_DISPLAY={d} (socket missing)")),
        (Some(d), None) => o.line(OK, format!("WAYLAND_DISPLAY={d} (socket location unknown)")),
        (None, _) => o.line(NO, "WAYLAND_DISPLAY unset"),
    }
    show(o, "DISPLAY", &s.display);
    show(o, "XDG_CURRENT_DESKTOP", &s.current_desktop);
    o.errors(&r.session);
}

fn card_line(c: &Card) -> String {
    let vendor = match c.vendor {
        Some("nvidia") => "NVIDIA",
        Some("amd") => "AMD",
        Some("intel") => "Intel",
        _ => "unknown vendor",
    };
    let ids = match (&c.pci_vendor, &c.pci_device) {
        (Some(v), Some(d)) => format!(" ({v}:{d})"),
        (Some(v), None) => format!(" ({v})"),
        _ => String::new(),
    };
    let driver = match &c.driver {
        Some(d) => format!("driver {d}"),
        None => "no driver bound".to_owned(),
    };
    let stack = match c.stack {
        Stack::Nvidia => "NVIDIA proprietary userspace",
        Stack::Mesa => "Mesa",
        Stack::Unknown => "unknown stack",
    };
    format!("{}: {vendor}{ids}, {driver} → {stack}", c.name)
}

fn manifest_lines(o: &mut Out, title: &str, list: &[Manifest]) {
    if list.is_empty() {
        o.line(NO, format!("{title}: none"));
        return;
    }
    o.line(OK, format!("{title}:"));
    for m in list {
        let detail = match (&m.library_path, &m.error) {
            (_, Some(e)) => format!("error: {e}"),
            (Some(lib), None) => lib.clone(),
            (None, None) => "no library_path".to_owned(),
        };
        let _ = writeln!(o.0, "      {} → {detail}", p(&m.path));
    }
}

fn gpu(o: &mut Out, r: &Report) {
    o.heading("GPU");
    let g = &r.gpu.data;
    if g.cards.is_empty() {
        o.line(NO, "no DRM cards");
    }
    for c in &g.cards {
        o.check(c.driver.is_some(), card_line(c));
    }
    if let Some(nv) = &g.nvidia {
        o.line(
            OK,
            format!(
                "NVIDIA driver {} ({} kernel module)",
                nv.version.as_deref().unwrap_or("version unknown"),
                nv.kernel_module
            ),
        );
    }
    if g.render_nodes.is_empty() {
        o.line(NO, "render nodes: none");
    } else {
        let nodes: Vec<String> = g.render_nodes.iter().map(|n| p(n).to_string()).collect();
        o.line(OK, format!("render nodes: {}", nodes.join(", ")));
    }
    manifest_lines(o, "Vulkan ICDs", &g.vulkan_icds);
    manifest_lines(o, "EGL vendors", &g.egl_vendors);
    let via = match g.loaders.source {
        Source::Ldconfig => "via ldconfig",
        Source::Scan => "via directory scan",
        Source::None => "",
    };
    if g.loaders.source != Source::None {
        for (name, path) in [
            ("libvulkan.so.1", &g.loaders.libvulkan),
            ("libEGL.so.1", &g.loaders.libegl),
            ("libGL.so.1", &g.loaders.libgl),
        ] {
            match path {
                Some(path) => o.line(OK, format!("{name}: {} ({via})", p(path))),
                None => o.line(NO, format!("{name}: not found ({via})")),
            }
        }
    }
    o.errors(&r.gpu);
}

fn xdg(o: &mut Out, r: &Report) {
    o.heading("XDG directories");
    let x = &r.xdg.data;
    if let Some(h) = &x.home {
        o.line(OK, format!("HOME={}", p(h)));
    }
    let base = |o: &mut Out, key: &str, b: &Option<BaseDir>| {
        if let Some(b) = b {
            let src = match b.source {
                DirSource::Env => "",
                DirSource::Default => " (default)",
            };
            o.line(OK, format!("{key}={}{src}", p(&b.path)));
        }
    };
    base(o, "XDG_CONFIG_HOME", &x.config_home);
    base(o, "XDG_DATA_HOME", &x.data_home);
    base(o, "XDG_STATE_HOME", &x.state_home);
    base(o, "XDG_CACHE_HOME", &x.cache_home);
    let join = |v: &[std::path::PathBuf]| {
        v.iter()
            .map(|d| p(d).to_string())
            .collect::<Vec<_>>()
            .join(":")
    };
    o.line(OK, format!("XDG_DATA_DIRS={}", join(&x.data_dirs)));
    o.line(OK, format!("XDG_CONFIG_DIRS={}", join(&x.config_dirs)));
    let rd = &x.runtime_dir;
    match &rd.path {
        None => o.line(
            NO,
            "XDG_RUNTIME_DIR unset (needed for the D-Bus proxy socket)",
        ),
        Some(path) => match rd.exists {
            Some(false) => o.line(NO, format!("XDG_RUNTIME_DIR={} (missing)", p(path))),
            Some(true) => {
                let good = rd.owner_ok == Some(true) && rd.mode_ok == Some(true);
                let owner = if rd.owner_ok == Some(true) {
                    "owner ok"
                } else {
                    "wrong owner"
                };
                o.check(
                    good,
                    format!(
                        "XDG_RUNTIME_DIR={} ({owner}, mode {})",
                        p(path),
                        rd.mode.as_deref().unwrap_or("?")
                    ),
                );
            }
            None => {}
        },
    }
    if let Some(s) = &x.ulai_store {
        o.line(OK, format!("ULAI store: {}", p(s)));
    }
    o.errors(&r.xdg);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::doctor;
    use crate::host::{FileKind, MetaInfo, Uname};
    use crate::testing::FakeHost;

    /// A fixed, fully populated system: NVIDIA + Intel hybrid laptop, Wayland,
    /// Landlock ABI 10, user namespaces failing at the tmpfs mount.
    fn full_host() -> FakeHost {
        let mut h = FakeHost::new();
        h.uname = Ok(Uname {
            release: "7.2.9-arch1-1".into(),
            machine: "x86_64".into(),
        });
        h.landlock = Ok(10);
        h.userns = Ok(concat!(
            r#"{"steps":[{"step":"unshare","ok":true,"errno":null},"#,
            r#"{"step":"setgroups","ok":true,"errno":null},"#,
            r#"{"step":"uid_map","ok":true,"errno":null},"#,
            r#"{"step":"gid_map","ok":true,"errno":null},"#,
            r#"{"step":"mount_private","ok":true,"errno":null},"#,
            r#"{"step":"mount_tmpfs","ok":false,"errno":"EPERM"}]}"#
        )
        .into());
        let dir = |mode| MetaInfo {
            kind: FileKind::Dir,
            mode,
            uid: 1000,
        };
        let suid_root = MetaInfo {
            kind: FileKind::File,
            mode: 0o104755,
            uid: 0,
        };
        doctor::gpu::hybrid_fixture(&mut h);
        h.file(
            doctor::lsm::LSM_PATH,
            "capability,landlock,lockdown,yama,bpf",
        )
        .file("/proc/sys/user/max_user_namespaces", "94304\n")
        .file("/proc/sys/kernel/unprivileged_userns_clone", "1\n")
        .file(doctor::yama::PTRACE_SCOPE_PATH, "1\n")
        .meta(
            "/dev/fuse",
            MetaInfo {
                kind: FileKind::CharDevice,
                mode: 0o20666,
                uid: 0,
            },
        )
        .meta("/usr/bin/fusermount3", suid_root)
        .file_mode("/usr/bin/getconf", "", 0o755)
        .command("/usr/bin/getconf", 0, "glibc 2.44\n")
        .file_mode("/usr/bin/ldconfig", "", 0o755)
        .command(
            "/usr/bin/ldconfig",
            0,
            "3 libs found in cache `/etc/ld.so.cache'\n\
                 \tlibvulkan.so.1 (libc6,x86-64) => /usr/lib/libvulkan.so.1\n\
                 \tlibEGL.so.1 (libc6,x86-64) => /usr/lib/libEGL.so.1\n\
                 \tlibGL.so.1 (libc6) => /usr/lib32/libGL.so.1\n",
        )
        .file_mode("/usr/bin/xdg-dbus-proxy", "", 0o755)
        .command("/usr/bin/xdg-dbus-proxy", 0, "xdg-dbus-proxy 0.1.9\n")
        .file("/run/user/1000/wayland-0", "")
        .meta("/run/user/1000", dir(0o40700))
        .set_env("PATH", "/usr/local/bin:/usr/bin")
        .set_env("HOME", "/home/user")
        .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
        .set_env("XDG_SESSION_TYPE", "wayland")
        .set_env("WAYLAND_DISPLAY", "wayland-0")
        .set_env("DISPLAY", ":0")
        .set_env("XDG_CURRENT_DESKTOP", "KDE");
        h
    }

    /// Compares with a golden file; `ULAI_BLESS=1` rewrites it instead.
    fn assert_snapshot(name: &str, actual: &str) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/snapshots")
            .join(name);
        if std::env::var_os("ULAI_BLESS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, actual).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("missing snapshot {}; run with ULAI_BLESS=1", path.display())
        });
        assert!(
            expected == actual,
            "snapshot {name} differs; run with ULAI_BLESS=1 to update.\n--- expected\n{expected}\n--- actual\n{actual}"
        );
    }

    #[test]
    fn human_snapshot() {
        let report = doctor::run(&full_host());
        assert_snapshot("doctor_full.txt", &human(&report));
    }

    #[test]
    fn json_snapshot() {
        let report = doctor::run(&full_host());
        let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
        assert_snapshot("doctor_full.json", &json);
    }

    #[test]
    fn empty_host_snapshot() {
        // Everything unknown or absent: shows the `?` lines.
        let report = doctor::run(&FakeHost::new());
        assert_snapshot("doctor_empty.txt", &human(&report));
    }
}
