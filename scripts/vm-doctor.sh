#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run `ulai doctor` inside a disposable QEMU/KVM VM booted from an official
# distribution cloud image, as an unprivileged user, and save the output.
#
# usage: scripts/vm-doctor.sh <distro> <ulai-binary> <out-dir>
#   distro: debian-13 | fedora-44 | ubuntu-26.04
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
	echo "usage: $0 <debian-13|fedora-44|ubuntu-26.04> <ulai-binary> <out-dir>" >&2
	exit 2
}
[[ $# -eq 3 ]] || usage
distro=$1 bin=$2 out=$3

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

[[ -x $bin ]] || { echo "not executable: $bin" >&2; exit 2; }
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

# --- run doctor as the unprivileged guest user ------------------------------
scp "${sshopts[@]}" -P "$port" -q "$bin" ulai@127.0.0.1:/tmp/ulai
guest 'cd /tmp && chmod +x ulai && ./ulai doctor > human.txt; echo "human_rc=$?"; ./ulai doctor --json > doctor.json; echo "json_rc=$?"' \
	| tee "$out/$distro.rc"
{
	guest 'id; uname -srm; grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release'
	guest 'ls -d /tmp/ulai-doctor-* 2>/dev/null || echo "no probe leftovers"'
} >"$out/$distro.system.txt"
guest 'cat /tmp/human.txt' >"$out/$distro.human.txt"
guest 'cat /tmp/doctor.json' >"$out/$distro.json"
echo "results in $out/$distro.*" >&2
