#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Builds seed corpora for the fuzz targets from the committed fixtures.
# usage: fuzz/seed.sh   (then: cargo +nightly fuzz run <target>)
set -euo pipefail
cd "$(dirname "$0")"
fx=../tests/fixtures
for t in container image manifest signature elf desktop; do mkdir -p "corpus/$t"; done
cp "$fx"/appimage/goappimage-rsa3072.AppImage corpus/container/
# The SquashFS image of each fixture (everything after the runtime).
for f in "$fx"/appimage/*.AppImage; do
	off=$(python3 - "$f" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read(4096)
if d[4] == 2:  # ELF64
    shoff, = struct.unpack_from("<Q", d, 0x28); se, sn = struct.unpack_from("<HH", d, 0x3A)
else:  # ELF32
    shoff, = struct.unpack_from("<I", d, 0x20); se, sn = struct.unpack_from("<HH", d, 0x2E)
print(shoff + se * sn)
PY
)
	tail -c +"$((off + 1))" "$f" > "corpus/image/$(basename "$f" .AppImage).sqfs"
	head -c "$off" "$f" > "corpus/elf/$(basename "$f" .AppImage).runtime"
done
cat > corpus/manifest/spec-example.json <<'JSON'
{"ulai":"0.1","id":"org.example.Downloader","name":"Example Downloader","version":"2.4.1","summary":"Download manager","arch":["x86_64"],"runtime_mode":"native","glibc_floor":"2.28","entry":"AppRun","permissions":["user-files","network"],"sensitive_permissions":["dotfile:~/.foorc"],"own_paths":["~/.config/example"],"integrations":{"mime_types":["x-scheme-handler/magnet"],"autostart":true,"native_messaging":[{"browser":"firefox","host_manifest":"share/nm.json"}]},"homepage":"https://example.org"}
JSON
cp "$fx"/openpgp/*.sig.asc "$fx"/openpgp/*.key.asc "$fx"/openpgp/*.gpg corpus/signature/
printf '[Desktop Entry]\nType=Application\nName=ULAI Fixture\nName[de]=X\nExec=AppRun %%U\nIcon=org.ulai.Fixture\n[Desktop Action a]\nExec=x\n' > corpus/desktop/entry.desktop
printf '\x89PNG\r\n\x1a\n' > corpus/desktop/png
echo "seeded: $(for t in container image manifest signature elf desktop; do printf '%s=%s ' "$t" "$(find "corpus/$t" -type f | wc -l)"; done)"
