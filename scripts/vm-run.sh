#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run a payload inside a disposable QEMU/KVM VM booted from an official
# distribution cloud image, as an unprivileged user, and copy its results back.
#
# usage: scripts/vm-run.sh <distro> <payload-dir> <out-dir>
#   distro: debian-13 | fedora-44 | ubuntu-26.04
#
# Set ULAI_VM_PACKAGES (space-separated) to have cloud-init install
# distribution packages at boot, before the payload runs.
#
# <payload-dir> is copied to /tmp/payload in the guest, and `run.sh` inside it
# runs there as the guest user `ulai` (uid 1000, no sudo) with network access
# through QEMU user networking. Whatever it writes to /tmp/out is copied to
# <out-dir>/<distro>/. Use this to run third-party tools (e.g. upstream
# appimagetool) without executing them on the host.
#
# Needs: qemu-system-x86_64, qemu-img, cloud-localds, curl, ssh, scp, and
# read/write access to /dev/kvm. No root.
#
# Base images are downloaded once into $ULAI_VM_CACHE (default
# ~/.cache/ulai-vms) and checked against the distribution's checksum file on
# every run. Each run gets a throwaway overlay disk, cloud-init seed and SSH
# key, deleted on exit; the guest's SSH port is forwarded to 127.0.0.1 only.
# The checksum files themselves are not signature-checked.
set -euo pipefail

usage() {
	echo "usage: $0 <debian-13|fedora-44|ubuntu-26.04> <payload-dir> <out-dir>" >&2
	exit 2
}
[[ $# -eq 3 ]] || usage
distro=$1 payload=$2 out=$3

case $distro in
debian-13)
	base=https://cloud.debian.org/images/cloud/trixie/latest
	file=debian-13-genericcloud-amd64.qcow2
	sums=SHA512SUMS
	sumtool=sha512sum
	;;
fedora-44)
	base=https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images
	file=Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
	sums=Fedora-Cloud-44-1.7-x86_64-CHECKSUM
	sumtool=sha256sum
	;;
ubuntu-26.04)
	base=https://cloud-images.ubuntu.com/releases/26.04/release
	file=ubuntu-26.04-server-cloudimg-amd64.img
	sums=SHA256SUMS
	sumtool=sha256sum
	;;
*) usage ;;
esac

[[ -f $payload/run.sh ]] || { echo "missing $payload/run.sh" >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo "no access to /dev/kvm" >&2; exit 1; }

cache=${ULAI_VM_CACHE:-$HOME/.cache/ulai-vms}
mkdir -p "$cache" "$out"

# --- base image: download if needed, always verify -------------------------
curl -fsSL --retry 3 -o "$cache/$distro.$sums" "$base/$sums"
want=$(grep -F "$file" "$cache/$distro.$sums" | grep -oE '[0-9a-f]{64,128}' | head -n1)
[[ -n $want ]] || { echo "no checksum for $file in $sums" >&2; exit 1; }

verify() { [[ -f $cache/$file ]] && [[ $($sumtool "$cache/$file" | cut -d' ' -f1) == "$want" ]]; }
if ! verify; then
	echo "downloading $file" >&2
	curl -fsSL --retry 3 -o "$cache/$file.part" "$base/$file"
	mv "$cache/$file.part" "$cache/$file"
	verify || { echo "checksum mismatch for $file" >&2; exit 1; }
fi

# --- throwaway VM state ------------------------------------------------------
work=$(mktemp -d "${TMPDIR:-/tmp}/ulai-vm.XXXXXX")
pid=
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
	if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		sleep 1
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -rf -- "$work"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -C ulai-vm -f "$work/key"
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: ulai
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
ssh_pwauth: false
EOF
if [[ -n ${ULAI_VM_PACKAGES:-} ]]; then
	{
		echo "packages:"
		for p in $ULAI_VM_PACKAGES; do echo "  - $p"; done
	} >>"$work/user-data"
fi
printf 'instance-id: ulai-%s\nlocal-hostname: ulai-%s\n' "$distro" "$distro" >"$work/meta-data"
cloud-localds "$work/seed.iso" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$file" "$work/disk.qcow2" 12G

port=$((20000 + RANDOM % 20000))
qemu-system-x86_64 \
	-enable-kvm -cpu host -smp 2 -m 2048 \
	-drive file="$work/disk.qcow2",if=virtio,format=qcow2 \
	-drive file="$work/seed.iso",if=virtio,format=raw,readonly=on \
	-netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$port"-:22 \
	-device virtio-net-pci,netdev=n0 \
	-display none -monitor none -serial file:"$work/console.log" \
	-daemonize -pidfile "$work/qemu.pid"
pid=$(cat "$work/qemu.pid")

sshopts=(-i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes)
guest() { ssh "${sshopts[@]}" -p "$port" ulai@127.0.0.1 "$@"; }

echo "waiting for $distro to boot (port $port)" >&2
for _ in $(seq 120); do
	guest true 2>/dev/null && break
	sleep 5
done
guest true || { cp "$work/console.log" "$out/$distro.console.log"; echo "guest never came up" >&2; exit 1; }
guest 'cloud-init status --wait >/dev/null 2>&1 || true' # finish package installs

# --- run the payload as the unprivileged guest user -------------------------
tar -C "$payload" -cf - . | guest 'rm -rf /tmp/payload /tmp/out && mkdir -p /tmp/payload /tmp/out && tar -C /tmp/payload -xf -'
set +e
guest 'cd /tmp/payload && bash ./run.sh' 2>&1 | tee "$work/run.log"
rc=${PIPESTATUS[0]}
set -e
mkdir -p "$out/$distro"
cp "$work/run.log" "$out/$distro/run.log"
guest 'tar -C /tmp/out -cf - .' | tar -C "$out/$distro" -xf -
echo "payload exit $rc; results in $out/$distro/" >&2
exit "$rc"
