<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# CLAUDE.md: project memory for Nikasha

**Nikasha** checks the factual claims in a vulnerability report against the source code at
the exact version the report names. It optionally reproduces the crash in a hardened
container, and outputs an evidence-backed verdict (REPRODUCED / GROUNDED / MIXED /
UNGROUNDED / INSUFFICIENT) plus neutral questions for the reporter. Tagline: *Proof, not
prose.*

## Read first

- **`SPEC.md` is the single source of truth, but it uses the old name "Pramaan".** Read it
  through the rename map in `docs/adr/0000-rename.md`: `pramaan` → `nikasha`,
  PramaanBench → NikashaBench, `PRAMAAN_*` → `NIKASHA_*`, `pramaan.toml` → `nikasha.toml`.
- Where the spec was overridden, the ADR wins:
  - `docs/adr/0002-dependencies.md`: no httpx (stdlib urllib instead); mcp 2.x
    `MCPServer`; tree-sitter 0.26 `Query`/`QueryCursor`.
  - `docs/adr/0003-differentiation-vs-slopcheck.md`: claim scoping, polarity, refutation
    gating, and the **M3.5 gate**.
  - `docs/research/2026-09-23-m0-verification.md`: git and container flag corrections.
- **`PROGRESS.md`** gives the current milestone, what is done, what is next, and open
  questions. Update it at every milestone.
- **Resume ritual:** read this file and `PROGRESS.md`, then run `make lint type test` and
  confirm green before changing anything.

## Principles (condensed P1–P8; non-negotiable)

1. **Evidence, not AI detection.** Wording targets claims, never people.
2. **Deterministic core.** Byte-identical JSON for identical inputs, with no LLM needed.
   The LLM is optional, off by default, and never decisive.
3. **Confidential by default.** Offline unless `--online`, no telemetry, cloud LLMs only
   with `llm.allow_cloud = true`.
4. **Conservative about "fabricated".** False UNGROUNDED on genuine reports must be ≤1%.
   When in doubt, say MIXED or INSUFFICIENT and ask.
5. **PoCs are hostile.** Only in the sandbox, only with `--repro`, never on the host.
6. **Every line is explainable.** Evidence carries repo, ref, commit, path, lines and the
   command with output hashes.
7. **Treat input as an attack:** XSS, ReDoS, path traversal, git config tricks, prompt
   injection.
8. **Useful to reporters too** (`nikasha lint`).

When principles conflict, safety wins: P4 comes before P5, then P3, then the rest. Ask the
user.

## Make targets

`make setup` · `make lint` (ruff, format check, codespell, `uvx reuse lint`, placeholder
grep) · `make fmt` · `make type` (mypy --strict) · `make test` (fast suite) ·
`make test-all`. The targets `bench`, `docs`, `screenshots`, `demo` and `release-check`
are stubs until their milestones.

## Package map (`src/nikasha/`; target layout in SPEC §6)

| Package | Role | Status |
|---|---|---|
| `cli.py` | typer app | `version`, `doctor` |
| `doctor.py` | environment self-check | done (M0) |
| `config.py` | cache and config dirs (0700) | done (M0) |
| `errors.py` | `NikashaError` hierarchy | done (M0) |
| `code/gitio.py` | **the only git runner** | hardened base (M0); extended in M2 |
| `repro/sandbox.py` | **the only container-engine runner** | detection (M0); runs in M5 |
| `model/`, `ingest/`, `extract/` | models, intake, claim extraction | M1 |
| `resolve/`, `code/*` | refs, tags, index, tree-sitter, timeline | M2 |
| `checks/`, `fuse/`, `render/` | C01–C21, fusion, outputs | M3, M4 |
| `bench/` | NikashaBench | M3.5, M6 |
| `integrations/`, `llm/` | Action, MCP, web UI, LLM | M7 |

## Conventions

- Python ≥3.11, `from __future__ import annotations`, `mypy --strict` clean, ruff clean.
  Line length 100.
- Every file starts with an SPDX header (code Apache-2.0, docs CC-BY-4.0). `reuse lint`
  must pass.
- Errors: raise `NikashaError` subclasses for expected failures. The CLI maps them to
  exit code 1.
- **Determinism rules:**
  - frozen pydantic models (`extra="forbid"`);
  - IDs are `sha256(kind + canonical)[:12]`;
  - sorted JSON keys and stable ordering;
  - no wall clock, randomness or environment dependence in checks or fusion;
  - timings live in a separate field.
- Commits: Conventional Commits, **always `git commit -s`** (DCO), checked by
  `scripts/check_commit_msg.py`. The repo-local identity is
  `Rakshit Rameshbabu <rakshitoffl@gmail.com>`.
- Dependencies: add each one in the milestone that needs it, with a row in ADR 0002.

## Security rules

- git **only** through `nikasha.code.gitio.run_git`, and container engines **only** through
  `nikasha.repro.sandbox`. Ruff's banned API and `tests/unit/test_process_boundary.py`
  enforce this.
- Git: plumbing only, never `checkout`. Pass `--no-ext-diff` and `--no-textconv` on
  `log` and `show`.
- PoCs only in the sandbox. Use the per-engine flags (podman needs
  `--read-only-tmpfs=false`).
- Escape everything in HTML and Markdown. Never mark input-derived content safe.
- Workflows: never interpolate `${{ github.event.* }}` text into `run:`; pass it through
  `env:`. Pin actions by commit SHA resolved with `gh api` (peel annotated tags). Use
  minimal `permissions:` and `persist-credentials: false`.
- Never commit secrets, embargoed text, or third-party report text. Bench manifests hold
  IDs and labels only.

## Step-by-step guides

See `CONTRIBUTING.md` for adding a check, a trace format, a recipe or a language.

## Test markers

The default run excludes `sandbox`, `network` and `slow`. Use `-m sandbox` (container
engine; CI on ubuntu), `-m network` (nightly), `-m slow`.

## Environment notes (this checkout)

- The working tree is on an NTFS (`fuseblk`) volume. git has `core.fileMode=false`, so set
  exec bits with `git update-index --chmod=+x`.
- Caches live in `~/.cache/nikasha` (native filesystem).
- `START_HERE.md` is personal and excluded through `.git/info/exclude`. Never commit it.

## Working agreement

- Plan, then approval, then **one milestone at a time**.
- End every milestone with: done / numbers / next / questions.
- Ask before any public or irreversible action (repo settings, releases, PyPI, GHCR).
- Never weaken tests or thresholds to pass. Report the real numbers.
