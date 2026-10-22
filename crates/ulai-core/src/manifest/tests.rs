// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde_json::{Value, json};

use super::*;

/// The example from SPEC §4.
fn spec_example() -> Value {
    json!({
      "ulai": "0.1",
      "id": "org.example.Downloader",
      "name": "Example Downloader",
      "version": "2.4.1",
      "summary": "Download manager",
      "arch": ["x86_64"],
      "runtime_mode": "native",
      "glibc_floor": "2.28",
      "entry": "AppRun",
      "permissions": ["user-files", "network", "audio", "gpu", "notifications"],
      "sensitive_permissions": [],
      "own_paths": ["~/.config/example-downloader", "~/.local/share/example-downloader"],
      "integrations": {
        "mime_types": ["x-scheme-handler/magnet"],
        "autostart": true,
        "native_messaging": [
          { "browser": "chromium-family", "host_manifest": "share/ulai/nm/org.example.downloader.json" },
          { "browser": "firefox", "host_manifest": "share/ulai/nm/org.example.downloader.firefox.json" }
        ]
      },
      "homepage": "https://example.org"
    })
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut v = spec_example();
    edit(&mut v);
    v
}

fn problems(v: &Value) -> Vec<Problem> {
    let m = parse(v.to_string().as_bytes()).unwrap_or_else(|e| panic!("{e}: {v}"));
    validate(&m)
}

fn assert_problem(v: &Value, field: &str) {
    let p = problems(v);
    assert!(
        p.iter().any(|p| p.field == field),
        "expected a problem in {field}, got {p:?}"
    );
}

#[test]
fn spec_example_is_valid() {
    assert_eq!(problems(&spec_example()), []);
    let m = parse(spec_example().to_string().as_bytes()).unwrap();
    assert_eq!(m.entry(), "AppRun");
    assert!(m.integrations.unwrap().autostart);
}

#[test]
fn unknown_fields_are_ignored() {
    let v = with(|v| {
        v["future_field"] = json!({"anything": [1, 2, 3]});
        v["integrations"]["future_integration"] = json!(true);
    });
    assert_eq!(problems(&v), []);
}

#[test]
fn duplicate_keys_are_rejected_at_any_level() {
    let top = br#"{"ulai":"0.1","id":"a.b","id":"c.d"}"#;
    assert_eq!(parse(top), Err(ParseError::DuplicateKey("id".into())));
    let nested = br#"{"integrations":{"autostart":false,"autostart":true}}"#;
    assert_eq!(
        parse(nested),
        Err(ParseError::DuplicateKey("autostart".into()))
    );
    let in_array = br#"{"x":[{"a":1},{"b":1,"b":2}]}"#;
    assert_eq!(parse(in_array), Err(ParseError::DuplicateKey("b".into())));
}

#[test]
fn size_cap_and_bad_json() {
    let mut big = spec_example();
    big["padding"] = json!("x".repeat(MAX_BYTES));
    assert_eq!(parse(big.to_string().as_bytes()), Err(ParseError::TooLarge));
    assert!(matches!(parse(b"{not json"), Err(ParseError::Json(_))));
    assert!(matches!(parse(b"{} trailing"), Err(ParseError::Json(_))));
    assert!(matches!(parse(b"[]"), Err(ParseError::Shape(_))));
    assert!(matches!(parse(br#"{"ulai":1}"#), Err(ParseError::Shape(_))));
    // Deep nesting stops at serde_json's recursion limit instead of overflowing the stack.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(matches!(parse(deep.as_bytes()), Err(ParseError::Json(_))));
}

#[test]
fn ids() {
    for good in [
        "org.example.App",
        "io.github.some_user.App-Name.Tool",
        "a.b",
    ] {
        assert_eq!(problems(&with(|v| v["id"] = json!(good))), [], "{good}");
    }
    for bad in [
        "app",
        "org..app",
        "org.example.",
        "1org.example",
        "org.9app",
        "org.example.app-name",
        "org/example",
        "org.ex ample",
        "",
    ] {
        assert_problem(&with(|v| v["id"] = json!(bad)), "id");
    }
    assert_problem(
        &with(|v| v["id"] = json!(format!("a.{}", "b".repeat(255)))),
        "id",
    );
}

#[test]
fn text_fields() {
    assert_problem(&with(|v| v["name"] = json!("  ")), "name");
    assert_problem(&with(|v| v["name"] = json!("x".repeat(101))), "name");
    assert_problem(&with(|v| v["name"] = json!("Evil\n  ✓ valid")), "name");
    assert_problem(&with(|v| v["summary"] = json!("abc\u{202E}def")), "summary");
    assert_problem(&with(|v| v["version"] = json!("1\u{1b}[31m")), "version");
}

#[test]
fn arch_runtime_and_glibc_floor() {
    assert_problem(&with(|v| v["arch"] = json!([])), "arch");
    assert_problem(&with(|v| v["arch"] = json!(["i386"])), "arch[0]");
    assert_problem(&with(|v| v["arch"] = json!(["x86_64", "x86_64"])), "arch");
    assert_problem(
        &with(|v| v["runtime_mode"] = json!("flatpak")),
        "runtime_mode",
    );
    assert_problem(
        &with(|v| {
            v.as_object_mut().unwrap().remove("glibc_floor");
        }),
        "glibc_floor",
    );
    assert_problem(&with(|v| v["glibc_floor"] = json!("2.28.1")), "glibc_floor");
    let portable = with(|v| {
        v["runtime_mode"] = json!("portable");
        v.as_object_mut().unwrap().remove("glibc_floor");
    });
    assert_eq!(problems(&portable), []);
}

#[test]
fn entry_and_image_paths() {
    for bad in ["/AppRun", "../x", "a/../b", "a//b", "./AppRun", ""] {
        assert_problem(&with(|v| v["entry"] = json!(bad)), "entry");
    }
    assert_eq!(problems(&with(|v| v["entry"] = json!("usr/bin/tool"))), []);
    assert_problem(
        &with(|v| v["integrations"]["native_messaging"][0]["host_manifest"] = json!("/etc/x.json")),
        "integrations.native_messaging[0].host_manifest",
    );
    assert_problem(
        &with(|v| v["integrations"]["native_messaging"][0]["browser"] = json!("opera")),
        "integrations.native_messaging[0].browser",
    );
}

#[test]
fn permissions() {
    assert_problem(
        &with(|v| v["permissions"] = json!(["root"])),
        "permissions[0]",
    );
    let p = problems(&with(|v| v["permissions"] = json!(["x11"])));
    assert!(p[0].message.contains("sensitive_permissions"), "{p:?}");
    assert_problem(
        &with(|v| v["permissions"] = json!(["gpu", "gpu"])),
        "permissions",
    );
    for good in [
        "x11",
        "secrets",
        "dotfile:~/.config/foo",
        "dotfile-rw:~/.foorc",
        "dotfile:~/.ssh",
    ] {
        assert_eq!(
            problems(&with(|v| v["sensitive_permissions"] = json!([good]))),
            [],
            "{good}"
        );
    }
    for bad in [
        "dotfile:~/Documents",
        "dotfile:/etc/passwd",
        "dotfile:~/./.x",
        "dotfile:~/.x/../y",
        "dotfile:",
        "admin",
    ] {
        assert_problem(
            &with(|v| v["sensitive_permissions"] = json!([bad])),
            "sensitive_permissions[0]",
        );
    }
}

#[test]
fn own_paths() {
    for good in [
        "~/.config/example",
        "~/.local/share/example",
        "~/Games/example",
        "~/.cache/example",
    ] {
        assert_eq!(
            problems(&with(|v| v["own_paths"] = json!([good]))),
            [],
            "{good}"
        );
    }
    for bad in [
        "~",
        "~/",
        "~/.config",
        "~/.local/share",
        "~/.cache", // too broad
        "/home/user/.config/x",
        "~user/x",
        "~/x/../../etc",
        "~/.config//x",
        "~/./x", // not inside $HOME
        "~/.ssh",
        "~/.ssh/known_hosts",
        "~/.config/autostart/x",
        "~/.mozilla/firefox", // inside protected
        "~/.local/share/ulai",
        "~/.local/share/ulai/apps", // the ULAI store
    ] {
        assert_problem(&with(|v| v["own_paths"] = json!([bad])), "own_paths[0]");
    }
    // Containing a protected path is as bad as being inside one.
    let p = problems(&with(|v| {
        v["own_paths"] = json!(["~/.local/share/gnome-shell"])
    }));
    assert!(p[0].message.contains("protected"), "{p:?}");
}

#[test]
fn integrations_and_homepage() {
    assert_problem(
        &with(|v| v["integrations"]["mime_types"] = json!(["text"])),
        "integrations.mime_types[0]",
    );
    assert_problem(
        &with(|v| v["integrations"]["mime_types"] = json!(["text/plain; charset=utf-8"])),
        "integrations.mime_types[0]",
    );
    for bad in [
        "http://example.org",
        "https://",
        "javascript:alert(1)",
        "https://exa mple.org",
    ] {
        assert_problem(&with(|v| v["homepage"] = json!(bad)), "homepage");
    }
}

#[test]
fn version_parse() {
    assert_eq!(parse_version("2.28"), Some((2, 28)));
    assert_eq!(parse_version("2.4"), Some((2, 4)));
    for bad in ["2", "2.", ".2", "2.x", "2.28.1", "+2.3"] {
        assert_eq!(parse_version(bad), None, "{bad}");
    }
}

/// The published schema must never be stricter than ULAI: every manifest
/// `validate` accepts, the schema accepts. (The schema is allowed to be
/// looser; see its description.) Also checks the schema rejects the clear
/// structural violations.
#[test]
fn schema_agrees_with_validator() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../../schemas/manifest-0.1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let corpus: Vec<Value> = vec![
        spec_example(),
        with(|v| v["id"] = json!("io.github.some_user.App-Name.Tool")),
        with(|v| v["future_field"] = json!(1)),
        with(|v| {
            v["runtime_mode"] = json!("portable");
            v.as_object_mut().unwrap().remove("glibc_floor");
        }),
        with(|v| {
            v["sensitive_permissions"] =
                json!(["x11", "dotfile:~/.config/foo", "dotfile-rw:~/.foorc"])
        }),
        with(|v| v["own_paths"] = json!(["~/Games/example", "~/.cache/example"])),
        with(|v| v["entry"] = json!("usr/bin/tool")),
        with(|v| {
            let o = v.as_object_mut().unwrap();
            for k in [
                "entry",
                "sensitive_permissions",
                "own_paths",
                "integrations",
                "homepage",
            ] {
                o.remove(k);
            }
        }),
    ];
    for m in &corpus {
        assert_eq!(problems(m), [], "corpus entry must be valid for ULAI: {m}");
        let errors: Vec<String> = validator.iter_errors(m).map(|e| e.to_string()).collect();
        assert!(
            errors.is_empty(),
            "schema rejects a manifest ULAI accepts: {errors:?}\n{m}"
        );
    }
    let rejected_by_both: Vec<Value> = vec![
        with(|v| v["ulai"] = json!("0.2")),
        with(|v| v["id"] = json!("app")),
        with(|v| v["arch"] = json!([])),
        with(|v| v["arch"] = json!(["i386"])),
        with(|v| v["runtime_mode"] = json!("flatpak")),
        with(|v| {
            v.as_object_mut().unwrap().remove("glibc_floor");
        }),
        with(|v| v["permissions"] = json!(["root"])),
        with(|v| v["permissions"] = json!(["gpu", "gpu"])),
        with(|v| v["own_paths"] = json!(["~/.config"])),
        with(|v| v["own_paths"] = json!(["/etc"])),
        with(|v| v["name"] = json!("bad\nname")),
        with(|v| v["homepage"] = json!("http://example.org")),
        with(|v| v["integrations"]["native_messaging"][0]["browser"] = json!("opera")),
    ];
    for m in &rejected_by_both {
        assert!(!problems(m).is_empty(), "ULAI accepts {m}");
        assert!(!validator.is_valid(m), "schema accepts {m}");
    }
}
