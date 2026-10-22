#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: CC0-1.0

# Builds the signed AppImage fixtures with the real tools. Runs INSIDE a
# disposable VM, as an unprivileged user (third-party binaries are never
# executed on the host):
#
#   scripts/vm-run.sh ubuntu-26.04 tests/fixtures/appimage/payload <out-dir>
#
# Writes to /tmp/out: the fixture AppImages, a detached signature, the
# public keys, tool versions and checksums, and the exact commands used.
# Private keys never leave the VM's temporary GnuPG home.
set -euo pipefail
out=/tmp/out
mkdir -p "$out"
cd /tmp/payload
export ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1
GNUPGHOME=$(mktemp -d); export GNUPGHOME; chmod 700 "$GNUPGHOME"

dl() { curl -fsSL --retry 3 -o "$1" "$2"; chmod +x "$1"; echo "$1 $2" >> "$out/tool-urls.txt"; }
dl appimagetool    https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
dl go-appimagetool https://github.com/probonopd/go-appimage/releases/download/continuous/appimagetool-951-x86_64.AppImage
dl runtime-x86_64  https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64
sha256sum appimagetool go-appimagetool runtime-x86_64 > "$out/tools.sha256"
{ echo "appimagetool: $(./appimagetool --version 2>&1 | head -1)"
  echo "go-appimagetool: $(./go-appimagetool --version 2>&1 | head -1)"
  echo "gpg: $(gpg --version | head -1)"
  echo "os: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2) $(uname -r)"; } > "$out/versions.txt"

# Two AppDirs; their content is CC0-1.0. AppRun is never executed by ULAI.
appdir() {
	local dir=$1 id=$2 name=$3
	mkdir -p "$dir"
	printf '#!/bin/sh\necho "%s"\n' "$name" > "$dir/AppRun"; chmod +x "$dir/AppRun"
	printf '[Desktop Entry]\nType=Application\nName=%s\nExec=AppRun\nIcon=%s\nCategories=Utility;\nTerminal=true\n' \
		"$name" "$id" > "$dir/$id.desktop"
	base64 -d > "$dir/$id.png" <<<'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
}
appdir UlaiDir org.ulai.Fixture "ULAI Fixture"
mkdir -p UlaiDir/.ulai
cat > UlaiDir/.ulai/manifest.json <<'MAN'
{
  "ulai": "0.1",
  "id": "org.ulai.Fixture",
  "name": "ULAI Fixture",
  "version": "1.0",
  "summary": "Signed test fixture",
  "arch": ["x86_64"],
  "runtime_mode": "native",
  "glibc_floor": "2.17",
  "permissions": []
}
MAN
appdir LegacyDir org.ulai.LegacyFixture "Legacy Fixture"

genkey() { gpg -q --batch --passphrase '' --quick-gen-key "$1" "$2" sign never; gpg --with-colons --list-keys "$1" | awk -F: '/^fpr/{print $10; exit}'; }
fpr_rsa=$(genkey 'ULAI fixture RSA-3072 <rsa3072@fixtures.ulai.invalid>' rsa3072)
fpr_ed=$(genkey 'ULAI fixture Ed25519 <ed25519@fixtures.ulai.invalid>' ed25519)
gpg --armor --export "$fpr_rsa" > "$out/rsa3072.pub.asc"
gpg --armor --export "$fpr_ed" > "$out/ed25519.pub.asc"
printf 'rsa3072 %s\ned25519 %s\n' "$fpr_rsa" "$fpr_ed" > "$out/fingerprints.txt"

run() { echo "+ $*" >> "$out/commands.txt"; "$@" >> "$out/build.log" 2>&1; }
run ./appimagetool --runtime-file runtime-x86_64 --sign --sign-key "$fpr_rsa" UlaiDir "$out/upstream-rsa3072.AppImage"
run ./appimagetool --runtime-file runtime-x86_64 --sign --sign-key "$fpr_ed" UlaiDir "$out/upstream-ed25519.AppImage"
run ./appimagetool --runtime-file runtime-x86_64 LegacyDir "$out/legacy-unsigned.AppImage"
run gpg --batch --detach-sign -u "$fpr_rsa" --digest-algo SHA512 -o "$out/legacy-unsigned.AppImage.sig" "$out/legacy-unsigned.AppImage"

# go-appimage reads pubkey.asc/privkey.asc from the root of the git
# repository it runs in, and deletes privkey.asc after reading it.
mkdir go && cd go
git init -q .
gpg --armor --export "$fpr_rsa" > pubkey.asc
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$fpr_rsa" > privkey.asc
echo "+ (in a git repository with pubkey.asc and privkey.asc at its root) VERSION=1.0 ./go-appimagetool UlaiDir" >> "$out/commands.txt"
VERSION=1.0 ../go-appimagetool ../UlaiDir > "$out/build-go.log" 2>&1
rm -f privkey.asc
mv ./*.AppImage "$out/goappimage-rsa3072.AppImage"
cd ..
rm -rf "$GNUPGHOME"
chmod a-x "$out"/*.AppImage
(cd "$out" && sha256sum ./*.AppImage ./*.sig ./*.asc | sort -k2) > "$out/SHA256SUMS"
ls -la "$out"
