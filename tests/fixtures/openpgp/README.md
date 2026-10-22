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
| `bidi-uid` | valid | user id with bidi controls; must be escaped when shown |
| `two-keys` | corrupt | exactly one primary key |
| `wrong-key` | invalid | not in the supplied key |

## Independent v6 material

- `rfc9580/`: the test vectors of RFC 9580, Appendix A, copied verbatim (the
  armored blocks; `a6-cleartext.txt` is the A.6 cleartext after
  dash-unescaping, `a2-msg.txt` is the A.2 input "OpenPGP").
  - A.3 + A.6: v6 Ed25519 certificate and text signature. Valid; the
    fingerprint matches the one printed in the RFC.
  - A.1 + A.2: a bare v4 Ed25519Legacy key packet without a self-signature.
    ULAI rejects it ("the key has no self-signature").
  - Licence: the RFC's boilerplate places Code Components under the Revised
    BSD licence (IETF Trust Legal Provisions §4.e), so these are annotated
    BSD-3-Clause. Whether test vectors count as Code Components is not stated
    explicitly in the RFC.
- `sequoia/`: a v6 key and detached signature over `msg` made by Sequoia
  (`sq 1.3.1`, sequoia-openpgp 2.1.0) in a disposable Ubuntu 26.04 VM on
  2026-10-22; commands in `sequoia/commands.txt`. A certification-only
  primary key with an Ed25519 signing subkey, so it also exercises v6
  back-signatures.
- v5 (LibrePGP): GnuPG 2.4.9 no longer makes v5 keys and Sequoia never did, so
  the v5 test patches the version byte of GnuPG-made packets. ULAI decides
  "unsupported" before any cryptography, so this tests the policy, not v5
  parsing.

## SHA-256 of each file

```
ef46654359be26a7e4ed2d9031e11751f53cc72b82356f6b436dbc76527f1240  bidi-uid.key.asc
1d0e6f590ecd8808e6bcd84c6ad2c920618f0282b518f194e7f5ab3268e600d4  bidi-uid.sig.asc
4f2409e51b510d380746990f064493e93ef31fab08ec285a639bfafb46664cc2  cases.tsv
f60a3a690e589457e7853be6a65085d7f81de74f3ff100e27c29dace2c2e954e  ed25519-text-sha512.key.asc
fc10fc62c81766ad0a9b89f0603b64d020204f811d0baf8d0c3197ec0c1c5d64  ed25519-text-sha512.sig.asc
71ec73181b5ffd601501a9a44f673f9d95bda938e07957098adcf300326c9a6e  expired-before-signing.key.asc
0bfd4e3a9885f09caca14e346f153da7d14444759fa5b9547e78c37d27a271b9  expired-before-signing.sig.asc
9155e8c54166dd66ad89dd5e3187e18690814e07153b9bce558720ccffddf569  expired-since.key.asc
cdc519e27f8f0e4d2e73c0a381f9882f54d9a13fc25f963e92ffb1471d4a23bd  expired-since.sig.asc
5931520ad13c019180d8bebdeccc0f402f3725fbe52b686fbb727aeaa23e6da0  msg
a37871e15155489d8838b8c741e2030e36dcba8635143a202133144948b96af6  no-sign-flag.key.asc
584993ecf2d4c07fc4b340e6d653f4856a533ffa40bae7496da138e2f54b6591  no-sign-flag.sig.asc
35ebb97bce4478aaeddf59c8f35de4a136836760bd2c86dc7fa6ef87fecedb35  primary-revoked.key.asc
a2a25b63d301b54ec98212c5a2a5b5d9a2c7e3cdb9d453c0065b67ca80b8c4aa  primary-revoked.sig.asc
94fe8cedba419cd9e4b645923eb46a0c017b86e05d15a5a0bd13893fb4697d6a  rsa1024.key.asc
a235ef4e662d46affbc5ab33e9b4a4140c5c6995867ad64f047f46646ca5374c  rsa1024.sig.asc
bc7393e1aa1814447f4f8d520a2973046247288248f55be75bebbe6ac627cdad  rsa3072-binary-sha256.key.asc
f28dbad0da19c831c721788a17fd1065a6926166d7b6d60a88ecbe975ea477de  rsa3072-binary-sha256.key.gpg
68f56da5f5037c00ea1d34b0f3d002c4e9c34d1f99bd88bc1c73cc9458b708f4  rsa3072-binary-sha256.sig.asc
cc6e099c2121b87a9e088e0732885eea098ac798b2ebc95689aaf1d6df4e59c1  rsa3072-binary-sha256.sig.gpg
bc7393e1aa1814447f4f8d520a2973046247288248f55be75bebbe6ac627cdad  rsa3072-text-sha512.key.asc
8b4aff593edb81340d4a490960a781edb2df9ea7436ed26589a6b7048ca4b851  rsa3072-text-sha512.sig.asc
bc7393e1aa1814447f4f8d520a2973046247288248f55be75bebbe6ac627cdad  sha1-data.key.asc
0b1d57157580d552a72104c9e0fb80cc6040d21eca97beb942f658d44fedc969  sha1-data.sig.asc
2285f3bea1180c7acabadb2eea86d5b4d90d919b618af6619fbb3a2430f6a2b6  sha1-selfsig.key.asc
d920e624118c7f2413cb09953261a8ebab061a09e3bc5aad1b912dea3eecd4d9  sha1-selfsig.sig.asc
61495d44994accbfccfbc3acea540eeae573c2ba9636376703ab1d4ba65f3dd2  subkey-no-backsig.key.asc
c6da4f74de4b8eb15456c2b15270ce73284cdae48a1c7a4d39be73a1d0f5defc  subkey-no-backsig.sig.asc
23de208263a3cb4f5910bed869a5021d7843aebfb5bfc541b191adb5434e8e21  subkey-revoked.key.asc
3e575ae51e5460de4e3c17f31bfe8d0e05233c3fc6968baf2c64eaff673acbf4  subkey-revoked.sig.asc
4a7ee2488bcfa7478e1df52dc32a7cec8aa59d6661e5216213a9c0c7683b9128  subkey-signs.key.asc
c6da4f74de4b8eb15456c2b15270ce73284cdae48a1c7a4d39be73a1d0f5defc  subkey-signs.sig.asc
e41d13859abc98944b833396a3b7338e61001711e931d41c18f00016354a1359  two-keys.key.asc
68f56da5f5037c00ea1d34b0f3d002c4e9c34d1f99bd88bc1c73cc9458b708f4  two-keys.sig.asc
f60a3a690e589457e7853be6a65085d7f81de74f3ff100e27c29dace2c2e954e  wrong-key.key.asc
68f56da5f5037c00ea1d34b0f3d002c4e9c34d1f99bd88bc1c73cc9458b708f4  wrong-key.sig.asc
```
