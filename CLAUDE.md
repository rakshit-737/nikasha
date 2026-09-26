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
  - `docs/adr/0006-repository-access.md`: full clones (not `blob:none`), **no `git archive`**,
    hardened git arguments.
  - `docs/adr/0004-timeline.md`: the lazy timeline strategy is the default, with measured
    numbers.
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
| `cli.py` | typer app | `version`, `doctor`, `extract`, `index`, `timeline`, `trace` |
| `doctor.py` | environment self-check | done (M0) |
| `config.py` | cache and config dirs (0700) | done (M0) |
| `errors.py` | `NikashaError` hierarchy | done (M0) |
| `code/gitio.py` | **the only git runner**; `GitRepo` (tags, ls-tree, cat-file batch, grep, pickaxe, `export_tree`) | done (M2) |
| `repro/sandbox.py` | **the only container-engine runner** | detection (M0); runs in M5 |
| `model/` | frozen pydantic models; `ids.py` content IDs; `result.py` JSON | done (M1) |
| `ingest/` | text / Markdown / HTML → `Report` with `SourceMap`; attachments | done (M1; email etc. M7) |
| `extract/` | registry + one module per claim kind; `pipeline.py` merges, scopes, orders | done (M1) |
| `extract/traces/` | one parser per trace format on `common.py` | 12/12 formats (ADR 0005, 0009) |
| `render/extract_view.py` | `nikasha extract` view | done (M1) |
| `resolve/` | `refs.py` tag parsing and `ReleaseList`; `repo.py` clone cache; `target.py` repo and commit resolution; `products.py` loads `data/known_projects.yaml` | done (M2) |
| `code/` | `languages`, `parser` (+ `symbols`, `calls`, `macros`, `preproc`, `queries/*.scm`) → `facts.FileFacts`; `index.py` SQLite by blob; `timeline.py`; `callgraph.py`; `trace_forensics.py`; `generated.py`; `literal.py` (capped `git grep -F`); `pathtrie`, `bktree`, `fingerprint` | done (M2) |
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

## Extraction rules worth knowing (M1)

- Claim IDs come from *content* (`registry.make_claim`); symbols merge by name and files by path;
  mentions inside trace or patch claims are dropped (`pipeline.drop_contained`).
- Every claim has a `provenance` (`extract/scope.py`), and only `project_attributed`,
  non-negated claims may ever be refuted (ADR 0003). Negation lives in `extract/polarity.py`.
- HTML comments in Markdown are not report content (issue templates are full of them).
- Every regex must be linear-time: use possessive or bounded quantifiers.
  `tests/unit/extract/test_regex_linear.py` checks every module-level pattern automatically.
- Use `spans.IntervalIndex` for overlap and containment checks; linear scans went quadratic on
  1 MB reports.
- Trace fixtures are real output only: `scripts/capture_trace_fixtures.py`, run in the pinned
  `docker/capture` image. Memory-error traces come only from vulnlab (ADR 0005).

## Code intelligence rules worth knowing (M2)

- Every revision taken from a report goes through `gitio.safe_rev` and follows
  `--end-of-options`. Option-looking text is refused everywhere except true data positions
  (`grep`'s pattern after `-e`, and pathspecs after `--`). `archive`, `checkout` and other
  porcelain are not in the allowlist. `tests/security/test_git_hazards.py` (20 canary
  hooks) must stay green.
- `parser.parse_file` never raises. It caps file size, parse time (read-callback cut-off)
  and error-tree width, and marks such files `parsed_ok=False`. Do not use tree-sitter's
  `progress_callback` (segfaults in 0.26.0) or chained `node.start_point.row` (use
  `start_point[0]`).
- C/C++ files with syntax errors are re-parsed with attribute-like macros blanked
  (`code/preproc.py`, same offsets); the result is kept only if it has fewer errors.
- Absence is never certain when a mention sits in a partially parsed file:
  `Timeline.uncertain_releases` (about 0.4% of C definitions are lost to body-level `#if`).
- Generated and release-only files (`known_projects.yaml` globs plus the sibling-template
  rule in `code/generated.py`) are never judged. Missing-in-tree is not "fabricated" until
  history says so: a timed-out pickaxe means `history_complete=False` (P4).
- `known_projects.yaml` is the single product list; `extract/products.py` derives from it.
- Tag matching: `refs.main_line_families()` keeps variant lines (tiny-curl,
  OpenSSL-fips) out of neighbours and windows.

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
