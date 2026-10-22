#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Fail if anything in the static musl builds of ulai and ulai-run compiles or
# links C (ADR-014): no crate in their dependency trees, including build
# dependencies, may depend on `cc` or `pkg-config`. Checking for a `-sys`
# suffix would be wrong: linux-raw-sys, for example, is pure Rust.
#
# usage: scripts/check-no-c.sh [manifest-path] [package...]
set -euo pipefail
manifest=${1:-Cargo.toml}
shift || true
packages=("$@")
[[ ${#packages[@]} -gt 0 ]] || packages=(ulai-cli ulai-run)
target=x86_64-unknown-linux-musl
status=0
for p in "${packages[@]}"; do
	tree=$(cargo tree --manifest-path "$manifest" -p "$p" --target "$target" \
		-e normal,build --prefix none --format '{p}')
	if bad=$(grep -E '^(cc|pkg-config) v' <<<"$tree" | sort -u) && [[ -n $bad ]]; then
		echo "error: $p ($target) pulls in C toolchain crates:" >&2
		echo "$bad" >&2
		cargo tree --manifest-path "$manifest" -p "$p" --target "$target" \
			-e normal,build -i cc 2>/dev/null | head -20 >&2 || true
		status=1
	else
		echo "ok: $p ($target) has no cc or pkg-config in its dependency tree"
	fi
done
exit "$status"
