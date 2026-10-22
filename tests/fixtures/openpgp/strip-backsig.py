#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The ULAI contributors
#
# SPDX-License-Identifier: CC0-1.0

"""Remove the embedded back-signature (subpacket 32, unhashed area) from every
v4 subkey binding signature (0x18) in a binary OpenPGP key. The binding still
verifies, because GnuPG puts the back-signature in the unhashed area; only the
back-signature is missing. Reads binary key on stdin, writes armored key."""
import base64, sys

def packets(data):
    i = 0
    while i < len(data):
        h = data[i]; assert h & 0x80, "not an OpenPGP packet"
        if h & 0x40:  # new format
            tag = h & 0x3F; l0 = data[i + 1]
            if l0 < 192: n, hl = l0, 2
            elif l0 < 224: n, hl = ((l0 - 192) << 8) + data[i + 2] + 192, 3
            elif l0 == 255: n, hl = int.from_bytes(data[i + 2:i + 6], "big"), 6
            else: raise SystemExit("partial lengths not supported")
        else:  # old format
            tag = (h >> 2) & 0x0F; lt = h & 3
            ln = {0: 1, 1: 2, 2: 4}[lt]
            n, hl = int.from_bytes(data[i + 1:i + 1 + ln], "big"), 1 + ln
        yield tag, data[i + hl:i + hl + n]
        i += hl + n

def subpackets(area):
    i = 0
    while i < len(area):
        l0 = area[i]
        if l0 < 192: n, hl = l0, 1
        elif l0 < 255: n, hl = ((l0 - 192) << 8) + area[i + 1] + 192, 2
        else: n, hl = int.from_bytes(area[i + 1:i + 5], "big"), 5
        yield area[i:i + hl + n], area[i + hl]
        i += hl + n

def header(tag, n):
    if n < 192: return bytes([0xC0 | tag, n])
    if n < 8384: n -= 192; return bytes([0xC0 | tag, (n >> 8) + 192, n & 0xFF])
    return bytes([0xC0 | tag, 255]) + n.to_bytes(4, "big")

def crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= 0x1864CFB
    return crc & 0xFFFFFF

out = b""; stripped = 0
for tag, body in packets(sys.stdin.buffer.read()):
    if tag == 2 and body[0] == 4 and body[1] == 0x18:
        hl = int.from_bytes(body[4:6], "big")
        u0 = 6 + hl
        ul = int.from_bytes(body[u0:u0 + 2], "big")
        unhashed = body[u0 + 2:u0 + 2 + ul]
        kept = b"".join(sp for sp, t in subpackets(unhashed) if (t & 0x7F) != 32)
        stripped += len(unhashed) != len(kept)
        body = body[:u0] + len(kept).to_bytes(2, "big") + kept + body[u0 + 2 + ul:]
    out += header(tag, len(body)) + body
assert stripped, "no back-signature found to strip"
b64 = base64.b64encode(out).decode()
print("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
print("\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)))
print("=" + base64.b64encode(crc24(out).to_bytes(3, "big")).decode())
print("-----END PGP PUBLIC KEY BLOCK-----")
