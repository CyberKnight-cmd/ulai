#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: CC0-1.0

# Regenerates the OpenPGP policy fixtures with GnuPG, so that ULAI's verifier
# is tested against keys and signatures it did not make itself. Every key is
# a throwaway key generated here; only public keys and signatures are kept.
# Writes <case>.key.asc, <case>.sig.asc and cases.tsv next to this script.
set -euo pipefail
cd "$(dirname "$0")"
rm -f ./*.key.asc ./*.sig.asc ./*.gpg cases.tsv
GNUPGHOME=$(mktemp -d); export GNUPGHOME; chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT
T0=1577836800   # 2020-01-01T00:00:00Z: fixed clock for the time-based cases
DAY=86400
g() { gpg -q --batch --pinentry-mode loopback --passphrase '' "$@"; }
at() { local t=$1; shift; g --faked-system-time "$t!" "$@"; }
fpr() { gpg --with-colons -k "$1" | awk -F: '/^fpr/{print $10; exit}'; }
subfpr() { gpg --with-colons -k "$1" | awk -F: '/^fpr/{n++} /^fpr/&&n==2{print $10; exit}'; }
printf '%s' 9f2c4e8a1b6d0f3e7a5c2b9d8e1f4a6c3b7d0e9f2a5c8b1d4e7f0a3c6b9d2e5f > msg
key() { gpg --armor --export "$@"; }
sig() { local t=$1 who=$2; shift 2; at "$t" --armor --detach-sign -u "$who" "$@" -o - msg; }
case_() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> cases.tsv; }

# --- valid: the shapes real tools produce (RESEARCH.md S1) ---
at $T0 --quick-gen-key 'rsa3072 <rsa3072@fixtures.ulai.invalid>' rsa3072 sign never
R=$(fpr rsa3072@fixtures.ulai.invalid)
key "$R" > rsa3072-text-sha512.key.asc;   sig $((T0+DAY)) "$R" --textmode --digest-algo SHA512 > rsa3072-text-sha512.sig.asc
key "$R" > rsa3072-binary-sha256.key.asc; sig $((T0+DAY)) "$R" --digest-algo SHA256 > rsa3072-binary-sha256.sig.asc
case_ rsa3072-text-sha512 valid "upstream appimagetool shape"
case_ rsa3072-binary-sha256 valid "go-appimage shape"

at $T0 --quick-gen-key 'ed25519 <ed25519@fixtures.ulai.invalid>' ed25519 sign never
E=$(fpr ed25519@fixtures.ulai.invalid)
key "$E" > ed25519-text-sha512.key.asc; sig $((T0+DAY)) "$E" --textmode --digest-algo SHA512 > ed25519-text-sha512.sig.asc
case_ ed25519-text-sha512 valid "legacy EdDSA Ed25519 key"

# --- algorithm policy ---
at $T0 --quick-gen-key 'rsa1024 <rsa1024@fixtures.ulai.invalid>' rsa1024 sign never
W=$(fpr rsa1024@fixtures.ulai.invalid)
key "$W" > rsa1024.key.asc; sig $((T0+DAY)) "$W" --digest-algo SHA256 > rsa1024.sig.asc
case_ rsa1024 unsupported "RSA-1024"
key "$R" > sha1-data.key.asc; sig $((T0+DAY)) "$R" --digest-algo SHA1 > sha1-data.sig.asc
case_ sha1-data unsupported "Sha1"
at $T0 --cert-digest-algo SHA1 --quick-gen-key 'sha1self <sha1self@fixtures.ulai.invalid>' rsa3072 sign never
S1=$(fpr sha1self@fixtures.ulai.invalid)
key "$S1" > sha1-selfsig.key.asc; sig $((T0+DAY)) "$S1" --digest-algo SHA256 > sha1-selfsig.sig.asc
case_ sha1-selfsig unsupported "Sha1"

# --- subkeys and back-signatures ---
at $T0 --quick-gen-key 'subkey <subkey@fixtures.ulai.invalid>' ed25519 cert never
P=$(fpr subkey@fixtures.ulai.invalid)
at $T0 --quick-add-key "$P" ed25519 sign never
SK=$(subfpr subkey@fixtures.ulai.invalid)
key "$P" > subkey-signs.key.asc; sig $((T0+DAY)) "$SK!" --digest-algo SHA512 > subkey-signs.sig.asc
case_ subkey-signs valid "signing subkey with back-signature"
gpg --export "$P" | python3 strip-backsig.py > subkey-no-backsig.key.asc
cp subkey-signs.sig.asc subkey-no-backsig.sig.asc
case_ subkey-no-backsig invalid "back-signature"
key "$P" > primary-cannot-sign.key.asc; sig $((T0+DAY)) "$SK!" --digest-algo SHA512 > /dev/null
# The certification-only primary key cannot sign data; GnuPG refuses to make
# that signature, so this case is covered by no-sign-flag below.

# --- revocation ---
at $T0 --quick-gen-key 'revoked <revoked@fixtures.ulai.invalid>' rsa3072 sign never
V=$(fpr revoked@fixtures.ulai.invalid)
sig $((T0+DAY)) "$V" --digest-algo SHA256 > primary-revoked.sig.asc
sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$V.rev" | at $((T0+2*DAY)) --import
key "$V" > primary-revoked.key.asc
case_ primary-revoked invalid "revoked"

at $T0 --quick-gen-key 'subrev <subrev@fixtures.ulai.invalid>' ed25519 cert never
P2=$(fpr subrev@fixtures.ulai.invalid)
at $T0 --quick-add-key "$P2" ed25519 sign never
SK2=$(subfpr subrev@fixtures.ulai.invalid)
sig $((T0+DAY)) "$SK2!" --digest-algo SHA512 > subkey-revoked.sig.asc
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' | at $((T0+2*DAY)) --command-fd 0 --edit-key "$P2" >/dev/null 2>&1
key "$P2" > subkey-revoked.key.asc
case_ subkey-revoked invalid "subkey has been revoked"

# --- expiry, judged at signing time ---
at $T0 --quick-gen-key 'expbefore <expbefore@fixtures.ulai.invalid>' rsa3072 sign never
X=$(fpr expbefore@fixtures.ulai.invalid)
sig $((T0+2*DAY)) "$X" --digest-algo SHA256 > expired-before-signing.sig.asc
# A newer self-signature (made at T0 + 12h) sets expiry to T0 + 36h.
at $((T0+DAY/2)) --quick-set-expire "$X" 1d
key "$X" > expired-before-signing.key.asc
case_ expired-before-signing invalid "had expired when the signature was made"

at $T0 --quick-gen-key 'expsince <expsince@fixtures.ulai.invalid>' rsa3072 sign 10d
Y=$(fpr expsince@fixtures.ulai.invalid)
key "$Y" > expired-since.key.asc; sig $((T0+DAY)) "$Y" --digest-algo SHA256 > expired-since.sig.asc
case_ expired-since valid+warning "expired since"

# --- key flags ---
at $T0 --quick-gen-key 'noflag <noflag@fixtures.ulai.invalid>' rsa3072 sign never
N=$(fpr noflag@fixtures.ulai.invalid)
sig $((T0+DAY)) "$N" --digest-algo SHA256 > no-sign-flag.sig.asc
# A newer self-signature drops the sign capability.
printf 'change-usage\nS\nQ\nsave\n' | at $((T0+2*DAY)) --expert --command-fd 0 --edit-key "$N" >/dev/null 2>&1
key "$N" > no-sign-flag.key.asc
case_ no-sign-flag invalid "not allowed to sign"

# --- hostile user id (terminal spoofing, SPEC §3.5): RLO and LRI ---
at $T0 --quick-gen-key $'Publisher \u202eFE3C 2B1A\u2066 <bidi@fixtures.ulai.invalid>' ed25519 sign never
BI=$(fpr bidi@fixtures.ulai.invalid)
key "$BI" > bidi-uid.key.asc; sig $((T0+DAY)) "$BI" --digest-algo SHA256 > bidi-uid.sig.asc
case_ bidi-uid valid "user id with bidi controls; must be escaped when shown"

# --- structure ---
key "$R" "$E" > two-keys.key.asc; cp rsa3072-binary-sha256.sig.asc two-keys.sig.asc
case_ two-keys corrupt "exactly one primary key"
key "$E" > wrong-key.key.asc; cp rsa3072-binary-sha256.sig.asc wrong-key.sig.asc
case_ wrong-key invalid "not in the supplied key"

# Binary (non-armored) encodings, as `gpg --detach-sign` and `gpg --export`
# write by default (Krita's .sig is binary).
gpg --dearmor < rsa3072-binary-sha256.key.asc > rsa3072-binary-sha256.key.gpg
gpg --dearmor < rsa3072-binary-sha256.sig.asc > rsa3072-binary-sha256.sig.gpg

gpg --version | head -1 > gnupg-version.txt
rm -f primary-cannot-sign.key.asc
