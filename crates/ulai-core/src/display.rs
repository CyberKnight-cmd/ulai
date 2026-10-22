// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Making untrusted strings safe to print on a terminal (SPEC §3.5).
//!
//! Names, paths, manifest and desktop-entry fields, and key user ids all come
//! from the file being inspected. Printed raw, they could move the cursor,
//! start a new line that looks like a ULAI verdict, or reorder characters
//! (Unicode bidi controls) so that a fingerprint reads differently from what
//! it is. JSON output does not need this: JSON escaping already covers it.

use std::fmt::Write as _;

/// Unicode bidirectional formatting characters (SPEC §3.5).
const BIDI: [char; 12] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Whether `c` must not reach a terminal unescaped: C0 controls (including
/// newline and ESC), DEL, C1 controls, and the bidi controls.
pub fn is_unsafe(c: char) -> bool {
    let u = u32::from(c);
    u < 0x20 || (0x7F..=0x9F).contains(&u) || BIDI.contains(&c)
}

/// Returns `s` with every unsafe character replaced by `\u{XXXX}`, and a
/// literal backslash written as `\\` so the escape cannot be faked.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if is_unsafe(c) {
            let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(escape("Krita 6.0.4 — Ünïcödé ✓"), "Krita 6.0.4 — Ünïcödé ✓");
    }

    #[test]
    fn fake_verdict_line_is_neutralised() {
        // A hostile app name that tries to print its own "valid" verdict.
        let name = "Evil\n  ✓ valid: signed by the key embedded in the file";
        let out = escape(name);
        assert!(!out.contains('\n'));
        assert_eq!(
            out,
            "Evil\\u{000A}  ✓ valid: signed by the key embedded in the file"
        );
    }

    #[test]
    fn terminal_escapes_and_c1_are_neutralised() {
        let out = escape("a\x1b[2J\x1b]0;title\x07b\u{0085}c\u{009B}31m\r\t\0\x7f");
        assert!(!out.chars().any(is_unsafe), "{out}");
        assert!(
            out.contains("\\u{001B}") && out.contains("\\u{009B}") && out.contains("\\u{0000}")
        );
    }

    #[test]
    fn bidi_spoofing_is_neutralised() {
        // RLO makes "…7468332F" display reversed in a terminal that honours
        // bidi controls; every listed control is escaped.
        let fpr = "E9FB29E74ADEACC5\u{202E}F2338647";
        assert_eq!(escape(fpr), "E9FB29E74ADEACC5\\u{202E}F2338647");
        for c in BIDI {
            assert!(is_unsafe(c), "{c:?}");
            assert!(!escape(&format!("x{c}y")).contains(c));
        }
    }

    #[test]
    fn backslash_cannot_forge_an_escape() {
        // Without doubling, "\u{000A}" typed literally would look like an
        // escaped newline.
        assert_eq!(escape("a\\u{000A}b"), "a\\\\u{000A}b");
    }
}
