<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Nikasha

**Proof, not prose.**

Nikasha (निकष, *touchstone*: the stone used to assay gold) checks which claims in a
vulnerability report are supported by source code at the exact version the report names,
and can reproduce the crash in a hardened sandbox. It runs offline against a git
repository, is deterministic (the same report and commit produce byte-identical JSON,
with no LLM involved), and emits line-by-line evidence (repository, commit, file, lines,
and hashed command outputs where commands ran).

It judges claims, never people: unsupported claims become neutral follow-up questions for
reporters. Nikasha is a grounding/reproduction tool, not an AI/slop detector
([ADR 0012](docs/adr/0012-reposition-after-m35.md)).

> [!IMPORTANT]
> **Status: first release (`0.1.0`).** Screenshots on this page are real runs against the
> bundled **vulnlab demo** (a fictional C library with a deliberately introduced heap
> overflow). The only numbers on real reports are the transparent M3.5 gate below: one
> corpus (curl), 175 reports, no calibration yet.

## Try it in 60 seconds

```sh
git clone https://github.com/rakshit-737/nikasha && cd nikasha
uv tool install .          # or: pipx install .   (or: uv sync && uv run nikasha ...)
nikasha doctor             # Python, git, cache directory, container engines; no network
python scripts/build_vulnlab.py ~/vulnlab.git
nikasha check examples/reports/fabricated_hdr_overflow.md --repo ~/vulnlab.git
```

Expected first result: `UNGROUNDED` (exit 20) on the intentionally fabricated fixture.

<details>
<summary>More quickstart commands (explain, markdown/html/json outputs)</summary>

```sh
nikasha check examples/reports/genuine_hdr_overflow.md --repo ~/vulnlab.git --explain
nikasha check examples/reports/mixed_wrong_version.md  --repo ~/vulnlab.git --format markdown -o reply.md
nikasha check examples/reports/genuine_hdr_overflow.md --repo ~/vulnlab.git --format html -o report.html
nikasha check examples/reports/genuine_hdr_overflow.md --repo ~/vulnlab.git --format json -o result.json
nikasha explain result.json
```

`--format` accepts `terminal` (default), `json`, `markdown`, or `html`.
`--explain` appends the full log-odds ledger. `--quiet` prints only the verdict line.
`--ascii` avoids non-ASCII symbols on legacy consoles. `https://` repositories are cloned
only with `--online`; local paths never touch the network.
Markdown output stays under GitHub's comment limit and escapes report/code-derived text.
HTML output is a self-contained report that makes no network request, enforced by CSP with
its single inline script pinned by hash.
</details>

Optional extras add integrations: `web` (local UI), `mcp` (MCP server), `llm`
(Anthropic/OpenAI clients for `--llm`), and `bench` (NikashaBench plots):
`uv tool install '.[web,mcp]'`.

`scripts/build_vulnlab.py` replays a fixed commit plan into a new bare repository with
`git fast-import`, so tags `v1.0.0` to `v1.3.0` resolve to the same commit SHAs on every
machine ([`examples/vulnlab/README.md`](examples/vulnlab/README.md)).

<figure>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/terminal-check-ungrounded-dark.svg">
  <img alt="nikasha check on the fabricated_hdr_overflow demo fixture: verdict UNGROUNDED, grounding 0/100, the evidence table, and six questions for the reporter" src="docs/assets/terminal-check-ungrounded-light.svg" width="100%">
</picture>
</figure>

## At a glance

| What you get | Why it matters |
|---|---|
| Deterministic verdicts and evidence | Repeatable checks suitable for CI and review workflows |
| Version-accurate grounding | Claims are tested at the report's named tag/commit, not just HEAD |
| Conservative refutation gate | "Fabricated" is intentionally hard to assert; uncertainty stays explicit |
| Sandbox-first reproduction model | PoCs are treated as hostile and never run on host by default |
| Reporter-friendly outputs | Neutral questions and explainable ledgers instead of accusations |

## Verdicts and exit codes

| Verdict | Meaning | Exit code |
|---|---|---|
| **REPRODUCED** | The proof of concept ran in the sandbox and produced the claimed crash signature. `nikasha check` has no `--repro` option yet, so a `check` run cannot reach this verdict today; the sandbox itself (`nikasha repro`, M5) is verified in CI. | 0 |
| **GROUNDED** | A high grounding score and no substantial refutation anywhere. | 0 |
| **MIXED** | Evidence on both sides, or findings that fit a *different* version than the report names (a wrong version header is a question, never an accusation). | 10 |
| **UNGROUNDED** | The hardest verdict to reach: a low score *and* a core file, symbol, quoted line, snippet or option that never existed in the repository's history, corroborated by a second independent group of evidence (or strong refutations from three independent groups). | 20 |
| **INSUFFICIENT** | Too little to check: no resolvable version, fewer than two checkable claims with no trace, snippet, patch or PoC, or too little total evidence weight. | 30 |

Errors exit 1. `--fail-on VERDICT` moves the non-zero line for CI.

<details>
<summary>More screenshots from the demo fixtures</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/terminal-check-grounded-dark.svg">
  <img alt="nikasha check on the genuine_hdr_overflow demo fixture: verdict GROUNDED, grounding 100/100, one question for the reporter" src="docs/assets/terminal-check-grounded-light.svg" width="100%">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/terminal-check-mixed-dark.svg">
  <img alt="nikasha check on the mixed_wrong_version demo fixture: verdict MIXED, grounding 100/100, three questions for the reporter" src="docs/assets/terminal-check-mixed-light.svg" width="100%">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/terminal-extract-dark.svg">
  <img alt="nikasha extract on the fabricated_hdr_overflow demo fixture: the report with each claim highlighted by kind, then the claim list with role and scope" src="docs/assets/terminal-extract-light.svg" width="100%">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/terminal-explain-dark.svg">
  <img alt="nikasha check --explain on the fabricated_hdr_overflow demo fixture: the verdict, then the ledger with every strength, damping weight, contribution and running total, ending in UNGROUNDED with high confidence" src="docs/assets/terminal-explain-light.svg" width="100%">
</picture>
</details>

## What it checks

Pipeline: ingest → extract → resolve → code intelligence → checks → fusion → render
([ADR 0001](docs/adr/0001-architecture.md)).

- Intake reads Markdown, text, and HTML with exact source maps.
- Extraction emits 12 claim kinds.
- Resolution pins to a tag/commit and never silently guesses.
- Tree-sitter parses C, C++, Python, JavaScript, TypeScript/TSX, Go, Rust, Java, PHP,
  and Ruby.
- Nine trace formats are parsed (ASan, UBSan, valgrind, gdb, Python, Java, Go, Rust,
  Node), each tested on real captured output.

The 19 deterministic checks (C01–C18 and C21) are catalogued in
[`docs/checks.md`](docs/checks.md):

| Group | Checks | Core question |
|---|---|---|
| version | C01, C16 | Does the named version resolve? Does the affected range fit symbol timelines across releases? |
| locus | C02, C03, C14 | Do cited file/symbol/option exist now, and did they ever exist historically? |
| lines | C04, C05 | Is the line in file, and in the claimed function? |
| code quotes | C06, C07 | Does a quoted line/snippet map to real code (winnowing fingerprints)? |
| trace | C08, C09, C10 | Do frames fit code, can callers reach callees, which release fits best? |
| trace meta | C11 | Is sanitizer output internally consistent (frames, PIDs, addresses, arithmetic, SUMMARY)? |
| patch | C12 | Does the diff apply here, or is it already applied? |
| refs, meta, behavior | C15, C17, C18 | Do cited commits/links/CVE/CWE/CVSS and call claims check out? |
| info | C13, C21 | What later commits touch locus, and what report prerequisites are missing? |

Two checks are intentionally outside that deterministic count:

- **C19 (reproduction):** scores sandboxed PoC runs; `nikasha check` does not start the
  sandbox yet.
- **C20 (`LLM_REVIEW`):** inert unless `--llm` or `nikasha.toml` names a model. Its
  strength is capped at |0.5| in `lr_defaults.yaml` (below verdict thresholds), and
  unreachable models fail at strength 0 (no refutation).

## Why the verdict is trustworthy

Every finding carries a natural-log likelihood ratio from
[`lr_defaults.yaml`](src/nikasha/checks/lr_defaults.yaml) (no float literal strengths),
then each evidence group is damped by rank (1, 1/2, 1/4, …) to avoid correlated evidence
swamping independent findings.

Verdicts are chosen by an ordered ladder (SPEC §14.3,
[`fuse/verdict.py`](src/nikasha/fuse/verdict.py)): reproduced crash; insufficient evidence;
strict UNGROUNDED gate; version-mismatch cap at MIXED; high-score GROUNDED with no
substantial refutation; otherwise MIXED/INSUFFICIENT.

Before any refutation counts, [ADR 0003](docs/adr/0003-differentiation-vs-slopcheck.md)
requires project-attributed, non-negated claims. Findings about reporter PoC code or
third-party APIs may be displayed, but contribute zero refutation strength.

## Principles

1. **Evidence, not AI detection.** Wording targets claims, never people.
2. **Deterministic core.** Byte-identical JSON for identical inputs; optional LLM,
   off-by-default and never decisive.
3. **Confidential by default.** Offline unless `--online`; no telemetry; cloud models only
   with `llm.allow_cloud = true`.
4. **Conservative about "fabricated".** Target ≤1% false UNGROUNDED on genuine reports;
   default to MIXED/INSUFFICIENT when uncertain.
5. **PoCs are hostile.** Run only in sandbox, never on host.
6. **Every line is explainable.** Repository, commit, path, lines, and command evidence.
7. **Input is an attack.** Report text/repos/traces are treated as hostile.
8. **Useful to reporters too.** `nikasha lint` helps before submission.

When principles conflict, safety wins: P4 first, then P5, then P3.

## Real-world gate (M3.5, 2026-09-26): transparent outcomes and caveats

175 labelled curl reports from slopcheck's index (126 confirmed genuine, 49 from curl's
AI-slop list), each checked at the version named in the report. Full detail in
[`PROGRESS.md`](PROGRESS.md) and
[ADR 0012](docs/adr/0012-reposition-after-m35.md).

- **No false UNGROUNDED:** 0/126 genuine reports. Wilson 95% upper bound is 2.96%, so this
  does **not** yet prove the ≤1% target.
- **Refutations did not separate slop from genuine reports.** At least one REFUTES finding
  on 20.6% of genuine and 20.4% of slop reports (J≈0). Nikasha never said UNGROUNDED on
  this corpus; MIXED appeared similarly in both groups.
- **Support carried the signal.** GROUNDED on 25% of genuine vs 10% of slop. Best observed
  grounding-score threshold reaches J 0.249 vs 0.103 for seeded random, but was chosen
  post hoc (optimistic).
- **Still open:** hand-checked precision of 40 random refutations.

So Nikasha is positioned as a **grounding and reproduction** tool. Refutations remain gated
and conservative, rendered as questions, not as a fabrication detector. No thresholds or
strengths were changed after the gate.

## Roadmap status

| Milestone | Status |
|---|---|
| M0 Bootstrap · M1 Models, intake, extraction · M2 Resolution and code intelligence · M3 Checks, fusion, CLI outputs · M4 HTML report | **done** (measurements in [`PROGRESS.md`](PROGRESS.md) and [ADR 0004](docs/adr/0004-timeline.md)) |
| M3.5 Early real-world gate (curl corpus vs. slopcheck) | **measured**: P4 held (0/126), no separation from refutations; decision: reposition ([ADR 0012](docs/adr/0012-reposition-after-m35.md)); 40-refutation hand-check open |
| M5 Sandbox reproduction | **sandbox CI green with the real recipe image**; curl/sqlite/libxml2 recipes unverified end-to-end |
| M6 NikashaBench and calibration | **machinery done**; next: supporting-evidence recall, reproduction rate, refutation precision (ADR 0012) |
| M7 Integrations | **done** (a GitHub Action, `nikasha lint`, the MCP server, the web UI, the optional model layer; network paths tested with stubs only) |
| M8 Launch polish and v0.1.0 | **done**: v0.1.0 released 2026-09-26 on PyPI, GHCR and GitHub Releases |
| M9 Stretch | not started |

## Commands and docs

- Primary CLI: `nikasha check`; support commands: `extract`, `index`, `timeline`, `trace`,
  `lint`, `cve`, `repro`, `recipes`, `bench`, `mcp`, `serve`, `h1`, `gh-advisories`.
- [`examples/vulnlab/README.md`](examples/vulnlab/README.md): deterministic demo repo details.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): setup, standards, and extension guides.
- [`SECURITY.md`](SECURITY.md): private reporting scope. [`SUPPORT.md`](SUPPORT.md): help.
- [`docs/checks.md`](docs/checks.md): checks catalogue. [`docs/action.md`](docs/action.md):
  GitHub Action.
- [`docs/adr/`](docs/adr/): decisions including
  [rename](docs/adr/0000-rename.md) (`SPEC.md` still says "Pramaan"),
  [dependencies](docs/adr/0002-dependencies.md),
  [repository access](docs/adr/0006-repository-access.md), and
  [fusion decisions](docs/adr/0007-fusion-decisions.md).
- [`PROGRESS.md`](PROGRESS.md), [`CHANGELOG.md`](CHANGELOG.md), [`SPEC.md`](SPEC.md).

## License

Code is licensed under [Apache-2.0](LICENSE); documentation under
[CC-BY-4.0](LICENSES/CC-BY-4.0.txt). See [`REUSE.toml`](REUSE.toml) for per-file details.
