<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Progress

The living build log. Milestones follow SPEC §22, plus **M3.5** from ADR 0003.

| Milestone | Status |
|---|---|
| M0 Bootstrap | **done**: repo live at https://github.com/rakshit-737/nikasha |
| M1 Models, intake, extraction (+ claim scoping, polarity) | **done** (LSan/MSan/TSan parsers deferred, ADR 0005) |
| M2 Resolution and code intelligence | not started |
| M3 Checks, fusion, CLI outputs | not started |
| M3.5 Early real-world gate (curl corpus vs. slopcheck) | not started |
| M4 HTML report and media v1 | not started |
| M5 Sandbox reproduction | not started |
| M6 NikashaBench | not started |
| M7 Integrations | not started |
| M8 Launch polish and v0.1.0 | not started |
| M9 Stretch | not started |

## M0: Bootstrap (2026-09-23)

### Done

- Verification of SPEC §0 and Appendix A.2 against current sources, recorded in
  `docs/research/2026-09-23-m0-verification.md`.
- Direct competitor found (slopcheck, with a published negative result). The maintainer
  chose "differentiate and gate early" (ADR 0003).
- Project renamed Pramaan → Nikasha (ADR 0000). `nikasha` is free on PyPI.
- Decisions:
  - repo `rakshit-737/nikasha`, public;
  - author Rakshit Rameshbabu <rakshitoffl@gmail.com>;
  - DCO sign-off required;
  - the working tree stays on the NTFS volume.
- Scaffold:
  - uv, hatchling, `src/` layout, Python ≥3.11, `uv.lock`;
  - `nikasha version`, `nikasha doctor`;
  - the hardened `gitio` base, container-engine detection, the process-boundary test.
- Legal: Apache-2.0 `LICENSE`, `NOTICE`, `LICENSES/`, `REUSE.toml`, `CITATION.cff`.
- Community: Code of Conduct (Contributor Covenant 3.0), CONTRIBUTING, SECURITY, SUPPORT,
  GOVERNANCE, CHANGELOG.
- `.github/`:
  - workflows: CI (lint, 3 OSes × 4 Pythons, gitleaks, DCO), CodeQL (python and
    actions), dependency review, Scorecard;
  - 6 issue forms plus `config.yml`, a PR template, CODEOWNERS, dependabot (uv and
    actions), release-notes categories, a label file.
- ADRs 0000–0003, `CLAUDE.md`.

### Published (2026-09-23, with the maintainer's approval)

- Created the public repo `rakshit-737/nikasha` (wiki off) and pushed.
- Settings applied and verified through the API:
  - Discussions on;
  - squash-merge only, with head branches deleted after merge;
  - private vulnerability reporting on;
  - secret scanning and push protection on;
  - Dependabot alerts and security updates on;
  - 13 labels from `.github/labels.yml`.
- The community profile is at 100%.
- At the maintainer's request, the history was rebuilt as one signed-off commit per
  file, and force-pushed once.
- Fixes after the first CI run:
  - a Windows test assumed a lowercase `git.exe` (the runner has `git.EXE`);
  - gitleaks-action v3 cannot scan a push that starts at the root commit (`<root>^`), so
    CI now runs the gitleaks v8.30.1 image, pinned by digest, over the full history.

### Open questions for the maintainer

- Ruleset on `main`: should there be an admin bypass while you are the only maintainer?
  (Decide before M8; the spec asks.)

## M1: Models, intake, extraction (2026-09-23)

### Done
- Models (SPEC §7): frozen pydantic models, content-derived IDs, deterministic JSON, and
  `schema/result-v1.json`, which is generated and drift-checked.
- Intake: text, Markdown and HTML with an exact source map; attachments with caps and safe
  opt-in archive extraction.
- Extraction: 11 extractors, plus the pipeline (merge, containment, scope, polarity, roles,
  500-claim cap), and `nikasha extract` (a highlighted view, and `--json`).
- ADR 0003 countermeasures:
  - claim provenance;
  - negation detection;
  - strict line binding;
  - no symbol claims from PoC code;
  - external-API and product/program attribution;
  - HTML comments ignored.
- Traces: 9 parsers (ASan, UBSan, valgrind, gdb, Python, Java, Go, Rust, Node), checked
  against 27 real fixtures captured in a sandboxed container
  (`scripts/capture_trace_fixtures.py`).
- vulnlab: deterministic history (5 tags, pinned SHAs) and 5 fixture reports. The genuine
  and mixed reports embed the real ASan trace.

### Numbers
- 1795 tests (including slow tests).
- Coverage: 95% overall, 96% on the core packages (gate: 85%), 99% on trace parsers.
- 79 regex patterns tested for linear time.
- Extraction on a 1 MB report takes 0.94 s including intake (budget: under 1 s; measured on
  a 16-core laptop, Fedora 44, repo on an NTFS volume).

### Decisions (maintainer)
- **Trace fixture scope (ADR 0005):** memory-error traces come only from the vulnlab bug;
  everything else is benign. **LSan, MSan and TSan have no fixtures, so their parsers are
  deferred.**
- The real-corpus extraction smoke test planned for M1 moves to M3.5. It needs the
  HackerOne terms check first.

### Open questions for the maintainer
- LSan, MSan and TSan: should they be captured later (e.g. from a real, already-fixed bug in
  a public project at a pinned tag), or left out of v0.1.0?

## Carry-overs to later milestones

- **M2:** check `GIT_NO_LAZY_FETCH` in the git docs before relying on it. Build the git
  hazard canary test.
- **M3:** C11 must accept modern ASan wording ("N bytes after"; a SUMMARY naming
  `__asan_memcpy` plus the module) as well as the older form (ADR 0005). Make the top
  application frame of a trace a core claim.
- **M3.5:** run the extraction smoke test on the real corpus. Check HackerOne's terms for the disclosed-report `.json` endpoint before
  fetching the corpus.
- **M5:** engine-specific sandbox flags (see the verification report, §6).
- **M8:**
  - choose Zensical or Material for the docs (ADR);
  - `date-released` in `CITATION.cff` at v0.1.0;
  - add the docker ecosystem to Dependabot;
  - use `actions/attest` rather than `attest-build-provenance`;
  - re-verify every §0 fact for the README; drop or re-source the Alpha-Omega claim.
