<!--
SPDX-FileCopyrightText: 2026 The ULAI contributors

SPDX-License-Identifier: MIT
-->

# ULAI JSON Schemas

Machine-readable schemas for the ULAI file format, published so that other
projects can implement it (ADR-015). Everything in this directory is under the
MIT licence, unlike the ULAI tools, which are GPL-3.0-or-later.

- `manifest-0.1.schema.json`: the app manifest at `/.ulai/manifest.json`
  (SPEC §4), JSON Schema draft 2020-12. It is deliberately a little *looser*
  than `ulai validate`: a regex cannot express "must not overlap the
  protected set" (SPEC §6.3) or reject every `.`/`..` path component. A test
  in `ulai-core` checks that the schema accepts everything ULAI accepts.
