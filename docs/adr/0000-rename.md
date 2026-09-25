<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0000: The project is named Nikasha (the spec says "Pramaan")

- **Status:** accepted
- **Date:** 2026-09-23

## Context

[`SPEC.md`](https://github.com/rakshit-737/nikasha/blob/main/SPEC.md) was written under the working name **Pramaan** (प्रमाण, "proof").
Before the first commit, the maintainer renamed the project **Nikasha** (निकष,
"touchstone": the stone against which gold is rubbed to test its purity). The M0 check
found that `pramaan` clashes with an existing, government-backed tool
(ONDC-Official/pramaan), while `nikasha` is free on PyPI, npm and crates.io.

## Decision

`SPEC.md` stays unedited as the historical specification. Wherever it says:

| Spec | Read as |
|---|---|
| Pramaan / `pramaan` (package, CLI, PyPI, GHCR image) | Nikasha / `nikasha` |
| PramaanBench | NikashaBench |
| `pramaan.toml` | `nikasha.toml` |
| `PRAMAAN_*` environment variables | `NIKASHA_*` |
| "The Pramaan Authors" | "The Nikasha Authors" |
| `pramaan:<verdict>` labels | `nikasha:<verdict>` |

The tagline "Proof, not prose." is unchanged.

## Consequences

Contributors must apply this mapping when reading the spec. `CLAUDE.md` repeats it for
AI-assisted sessions.
