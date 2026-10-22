<!--
SPDX-FileCopyrightText: 2026 The ULAI contributors

SPDX-License-Identifier: CC0-1.0
-->

# OpenPGP policy fixtures

Throwaway keys and signatures made with **GnuPG**, not with rPGP, so that
`ulai-core`'s verifier is tested against data it did not produce itself
(SPEC §3.2). Only public keys and signatures are kept; the private keys never
leave a temporary GnuPG home that `make.sh` deletes on exit.

- Regenerate: `tests/fixtures/openpgp/make.sh`. Keys are random, so the files
  change on every run; the expected outcomes in `cases.tsv` do not.
- Made with: gpg (GnuPG) 2.4.9, on Arch Linux (kernel 7.2.9-arch1-1),
  2026-10-22.
- Time-based cases use `--faked-system-time` from 2020-01-01T00:00:00Z.
- `subkey-no-backsig` is `subkey-signs` with the embedded back-signature
  (subpacket 32, which GnuPG puts in the *unhashed* area of the 0x18 binding)
  removed by `strip-backsig.py`. The binding itself still verifies.
- Every file was checked at packet level with `gpg --list-packets` to have the
  property its name claims (for example, digest algorithm 2 in the
  `sha1-selfsig` self-signature, a 0x20 revocation in `primary-revoked`).

| Case | Expected | Why |
|---|---|---|
| `rsa3072-text-sha512` | valid | upstream appimagetool shape |
| `rsa3072-binary-sha256` | valid | go-appimage shape |
| `ed25519-text-sha512` | valid | legacy EdDSA Ed25519 key |
| `rsa1024` | unsupported | RSA-1024 |
| `sha1-data` | unsupported | Sha1 |
| `sha1-selfsig` | unsupported | Sha1 |
| `subkey-signs` | valid | signing subkey with back-signature |
| `subkey-no-backsig` | invalid | back-signature |
| `primary-revoked` | invalid | revoked |
| `subkey-revoked` | invalid | subkey has been revoked |
| `expired-before-signing` | invalid | had expired when the signature was made |
| `expired-since` | valid+warning | expired since |
| `no-sign-flag` | invalid | not allowed to sign |
| `two-keys` | corrupt | exactly one primary key |
| `wrong-key` | invalid | not in the supplied key |

Not covered yet: v5 (LibrePGP) keys, because GnuPG 2.4.9 no longer makes them,
and v6 / RFC 9580 keys. Both need another independent source.

## SHA-256 of each file

```
286b3aedf746b486acc271a5b46d93e3dd1b1e30096e44ecd967a4cd650516da  cases.tsv
f1fc103d73562fd9cff5f013efbd94de9475d378adca46d11b3c4138bdeeb2ae  ed25519-text-sha512.key.asc
1aefcb60f041f511b162b0d7663ce00a44f97365333d6f3b4d1942bcc2f96487  ed25519-text-sha512.sig.asc
079a6cc81ddd5934849b4f127a163f77bb2ca7280800a78bb8c94df04385a416  expired-before-signing.key.asc
c50c23515e83334c42e5e9cdd88e8374b243c65fc18a6491a46d399eb7ca0e3d  expired-before-signing.sig.asc
c0e59eba3e9ddc063f89d3c7fedfa2d554d87febf73263a73e8cc22510de6fde  expired-since.key.asc
64f06a044c9abb6c9fbb4eb2708089964a8a7147f4978c82d8d97368b9998a2f  expired-since.sig.asc
5931520ad13c019180d8bebdeccc0f402f3725fbe52b686fbb727aeaa23e6da0  msg
c1e764fa846a4134188f31c6cf3084cf59186e5c5d55d62dbaa215c4f9401a24  no-sign-flag.key.asc
5eae1b3eb9b356876fa05c939d8e41e60cadf8b0edc2ae7f6e067926cd4dffb5  no-sign-flag.sig.asc
69ce2aa13229a4e45cf808356e0496e86ab8b9a4ee5e24fa4bf3f519ddf43931  primary-revoked.key.asc
77b4c4a5ff120729b95f811674cc7506169542bb1625e3b1499d540aaa923799  primary-revoked.sig.asc
fc322a5c0b2dabe58803645bbf02b7e17302208df70c8ab6c48465cbccd360f9  rsa1024.key.asc
aaa95089530204115bf207f68feb14f3d15c7c8ab760df5af2e93484730de9b9  rsa1024.sig.asc
6e287ae72550fc6a60f694b52406b456797562c5d66fd86ed784268750ac4dca  rsa3072-binary-sha256.key.asc
a66d654bc4925e14f2bc9882cc6a347a68d9a1cd1468f3b0e945ba6272260cc1  rsa3072-binary-sha256.sig.asc
6e287ae72550fc6a60f694b52406b456797562c5d66fd86ed784268750ac4dca  rsa3072-text-sha512.key.asc
a35c8bc6b582fd2d466bd64e19b622b57d2272be5e1d8153b510805c46794040  rsa3072-text-sha512.sig.asc
6e287ae72550fc6a60f694b52406b456797562c5d66fd86ed784268750ac4dca  sha1-data.key.asc
54b763f0aa031748fb3e8906c810d8bf63e69af1e8f72961f57617ac186d3c42  sha1-data.sig.asc
e2c48322cd7acfdfa8df875fce9aa474dc3dd302e9cf62ce34374f31f3ccc4c5  sha1-selfsig.key.asc
d88e792c42715dcb726ecd6d3989b85aed1af1e8946013a879b6b229fd724caa  sha1-selfsig.sig.asc
d5007e60b9fe932620c87e10f98f46ae39200a283e935aa3a1c9c67a64ffcaa3  subkey-no-backsig.key.asc
a8bb78eb0fae845d1e83783e7466c1623edf6d7a52b09123658e5b48b61bb97e  subkey-no-backsig.sig.asc
8e30cfda949a294062c5fdd519908632da1230ff49b3b1c4c51a6f722f418b9d  subkey-revoked.key.asc
6decfdcd92def56e9629d7e2a644fb0645857d38dde31d935179abb50a92fcd1  subkey-revoked.sig.asc
c20847217cc715c39eae8cd2cb3deefd9614672e4617da7a9d5e999d839341e7  subkey-signs.key.asc
a8bb78eb0fae845d1e83783e7466c1623edf6d7a52b09123658e5b48b61bb97e  subkey-signs.sig.asc
a60aedf8fe7f0026a08874f53ae65c81798a6e564496b7aed7c6b31e6e71dd23  two-keys.key.asc
a66d654bc4925e14f2bc9882cc6a347a68d9a1cd1468f3b0e945ba6272260cc1  two-keys.sig.asc
f1fc103d73562fd9cff5f013efbd94de9475d378adca46d11b3c4138bdeeb2ae  wrong-key.key.asc
a66d654bc4925e14f2bc9882cc6a347a68d9a1cd1468f3b0e945ba6272260cc1  wrong-key.sig.asc
```
