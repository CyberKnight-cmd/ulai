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
- `crit-notation-selfsig`: GnuPG refuses to sign with a key whose only
  self-signature carries an unknown critical notation. So the data is
  signed first, then a second user id is added with
  `--cert-notation '!critical@fixtures.ulai.invalid=1'`, and only that user
  id is exported (`--export-filter keep-uid=...`). GnuPG has no way to
  re-bind an existing subkey with a notation, so the binding case is signed
  with rPGP in `crates/ulai-core/src/signature/tests_rules.rs`, from a key
  generated in the test.
- The future-dated rule (SPEC §3.2) is tested with these fixtures and a
  clock set to before their creation times, so no extra files are needed.
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
| `notation-noncritical` | valid | non-critical notation is ignored |
| `crit-notation-data` | invalid | critical notation |
| `crit-notation-selfsig` | invalid | critical notation |
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
  - Licence: BSD-3-Clause, "2024 IETF Trust and the persons identified as
    the document authors" (the RFC's Code Components licence, IETF Trust
    Legal Provisions §4.e). Annotated in `REUSE.toml`; text in
    `LICENSES/BSD-3-Clause.txt`.
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
9c9cb1c2be6ee95e69f69307fea90b80b30af49b372f43dd10ebe1c6e4779fd6  bidi-uid.key.asc
9388067dd6c8878a91f33a416fee6cdf1e8e795b00af1adbf805d4d3b385cf45  bidi-uid.sig.asc
872193aa49bd33f068faa2a148e0b88a54376cbe03db6af8a0eda40a9dde93f6  cases.tsv
69c02b5b67eb67ce617b5ebb43127cb8c04258fb2ada1fd9b93ea53ecf582aa9  crit-notation-data.key.asc
1864069f02fea7246e9df745291f21f44e2596c2210f76f8fabd77bd58d577f7  crit-notation-data.sig.asc
4bb5619f625793d406dba63313f812e6666607187abaf2a9bbe7e962ce3a8e2f  crit-notation-selfsig.key.asc
8a536805f776d44f01e79116aec2bc3597d8b9009ddfffd33f3648766462ec60  crit-notation-selfsig.sig.asc
9e890b4373c7bf6aa8ac73afae1b94518f34b6a2c26e447cf0c1e8d4549a8f5b  ed25519-text-sha512.key.asc
750a32c4a7f914a6ce7228baf69e80f120e4d7bb3f7d3d4167497c0e74ce7eb8  ed25519-text-sha512.sig.asc
d7f196495f00a16587cfda4c77c378d00cbc9e80bbc38e221bfbcf0fad0a8d72  expired-before-signing.key.asc
f2312445f62bb71950994d713f0c8b4784159a5d138fd370c09889fdebb4c940  expired-before-signing.sig.asc
c51f989e7339b7680e33b486c3d9f8b5bd884e954c20a9d73a8b89ec29ec3ec9  expired-since.key.asc
bdfea5cf93d2079e9828a5eca43a521d38ee2e396a7c05469ef84dd7774716f8  expired-since.sig.asc
5931520ad13c019180d8bebdeccc0f402f3725fbe52b686fbb727aeaa23e6da0  msg
6cc138ef8a1633ebe6ca5c70d08cf4e8f82691226226e2f1b5afa71f3b7a6750  no-sign-flag.key.asc
2c223761bcb99ab213d880e77ae37f354ef93b017dda7cc441e257982d544356  no-sign-flag.sig.asc
69c02b5b67eb67ce617b5ebb43127cb8c04258fb2ada1fd9b93ea53ecf582aa9  notation-noncritical.key.asc
596f95d8002c70871ad7dcc60f1615adeabceb78f6436eef1a01df7f6ec5fbae  notation-noncritical.sig.asc
684e713a6fb504a61e17c25a7e105a6057e119b3f707b8518e9afe75c02d285f  primary-revoked.key.asc
5adc8ec794e1f66d1479b1603a8b09e71ae8b6d7361e5d0e6da9b6eb579ab0ed  primary-revoked.sig.asc
4009d6bc2e81d51fcce1ffd364f26f7158d327d5bedb3a429704cf6defba0dd2  rsa1024.key.asc
89550d9e11d1156713adc52f646721a3ee1266e1f62caee69ae048807ad76d74  rsa1024.sig.asc
69c02b5b67eb67ce617b5ebb43127cb8c04258fb2ada1fd9b93ea53ecf582aa9  rsa3072-binary-sha256.key.asc
1b0f6731e088429d7ac5fb55b46e09ab70ea1430a8bf9ae0dc119cd82aa39c1e  rsa3072-binary-sha256.key.gpg
b3ecfffc13a092e0b7dad057bbff92e31267cb0b381e95f0339026272cc6918b  rsa3072-binary-sha256.sig.asc
753235c27e7c0623b316bc73b7b463826a54aa5cf6319d4803f05b8dcd4bbc5c  rsa3072-binary-sha256.sig.gpg
69c02b5b67eb67ce617b5ebb43127cb8c04258fb2ada1fd9b93ea53ecf582aa9  rsa3072-text-sha512.key.asc
57e5a557eb71c68fb241aad0d4a1eab85da67a429688e828c6429866591337ec  rsa3072-text-sha512.sig.asc
69c02b5b67eb67ce617b5ebb43127cb8c04258fb2ada1fd9b93ea53ecf582aa9  sha1-data.key.asc
36d1aa8d4abfb066dc083bd8d90f9ed08b3008d1ed22f5533cbdbbdf54eb5112  sha1-data.sig.asc
2548205e845bae021cb01cc01c0bc7b18bf3511c82e994876ef49b911aca5ebd  sha1-selfsig.key.asc
de61732aec21be5c9bbefb532d555e82b6e95fdd3808383772b76f1b8099d5d8  sha1-selfsig.sig.asc
a641e8aa006d6cc81268a4ba5b58a8d90aef4c20e55f0843a0a026538b9aa4fa  subkey-no-backsig.key.asc
ff55eb276c3429fc23b093b5216160877f14eee537d9d7cdb6e23cbb864f520a  subkey-no-backsig.sig.asc
47b9c459b9df67b6fc10ff2afe565f4d5f23605a64a041accf6e5a2bfbbbb6c3  subkey-revoked.key.asc
6967fcaa9c44cd8db62a06b62a281b746b67fb5bf63b04fdc816b428c0f85839  subkey-revoked.sig.asc
689f5a20d167daf7d067ef6805403dcb96fe855307038130a2ce27590072ebcf  subkey-signs.key.asc
ff55eb276c3429fc23b093b5216160877f14eee537d9d7cdb6e23cbb864f520a  subkey-signs.sig.asc
978370af515c0c6354d6ed3db84e895c1439ac2311508606e0701bb82c266220  two-keys.key.asc
b3ecfffc13a092e0b7dad057bbff92e31267cb0b381e95f0339026272cc6918b  two-keys.sig.asc
9e890b4373c7bf6aa8ac73afae1b94518f34b6a2c26e447cf0c1e8d4549a8f5b  wrong-key.key.asc
b3ecfffc13a092e0b7dad057bbff92e31267cb0b381e95f0339026272cc6918b  wrong-key.sig.asc
```
