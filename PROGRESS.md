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
| M2 Resolution and code intelligence | **done** (numbers in ADR 0004) |
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
  a public project at a pinned tag), or left out of v0.1.0? *Decided in M2: captured in M5.*

## M2: Resolution and code intelligence (2026-09-23)

### Done
- **Git layer** (`code/gitio.py`, ADR 0006): `GitRepo` over plumbing only, with a persistent
  `cat-file --batch`. Revisions from report text are validated (`safe_rev`) and placed after
  `--end-of-options`. Option-looking text is refused except in true data positions (`grep`'s
  pattern after `-e`, pathspecs after `--`). `core.bare=true`, no `ext::` or `git://`, and
  `GIT_NO_LAZY_FETCH=1` offline. **`git archive` is gone:** the canary test showed a
  repository's own `tar.tar.command` runs through it. `export_tree` replaces it for M5.
- **Resolution** (`resolve/`): tag parsing and release ordering, tested on real tag lists
  from 9 projects; main-line detection keeps tiny-curl and OpenSSL-fips apart; full bare
  clones of `https://` repositories, fetched only with `--online`; target resolution from
  flags, intake metadata, permalinks, product names and claimed versions, never guessing
  silently. `data/known_projects.yaml` is the single product list.
- **Parsing** (`code/parser.py` and friends): tree-sitter for 10 languages (11 grammars with
  TSX): definitions with qualified names, calls, macros, address-taken functions. Hostile
  input is capped by size, time and error-tree width, and never raises. **New:** C/C++
  attribute macros between type and name (`static void LIBXML_ATTR_FORMAT(3,0) f(…)`) are
  read as whitespace when that reduces parse errors; libxml2 definition recall went from
  95.8% to 99.6%.
- **Index, timeline, call graph, trace forensics, generated files, literal search**, and the
  `index`, `timeline` and `trace` commands.
- **P4 safeguards:** a timed-out or shallow history search marks the timeline incomplete;
  a release where the name only appears in files that did not parse cleanly is *uncertain*,
  never absent; generated and release-only files are never judged, also under absolute
  build paths (`/src/lib/parse.c` next to `lib/parse.y` was missed before M2 closed).

### Numbers
- **Tests:** 2,564, all passing (1,795 at the end of M1). Coverage: 95% overall and 96% on
  the core packages (gate: 85%); the M2 modules are at 85–98%.
- **Linear-time regexes:** 154 patterns checked (79 at M1), now including `code/` and
  `resolve/`.
- **Release tags:** 3,772 real tags from 9 projects parse and order as expected.
- **Git hazards:** 20 execution hooks wired to a canary; no Nikasha code path fires any
  of them.
- **Indexing one tree** (SPEC target: curl HEAD under 30 s): curl 2.6 s, SQLite 4.3 s,
  libxml2 1.7 s cold; 0.01 s warm.
- **Timelines** (lazy, the default): curl, 206 releases, 8–33 s cold and 4–14 s warm; SQLite,
  375 releases, 22–35 s cold and 14 s warm. The full strategy needs 312 s (curl) or 260 s
  (SQLite) up front, then 3–15 s per query. The history search alone costs 5.0 s (curl)
  and 13.6 s (SQLite) against a 20 s budget.
- **Parser definition recall on real C** (against a column-0 baseline): curl 99.6%,
  SQLite 99.9%, libxml2 99.6% (95.8% before the attribute-macro fix).
- **Bugs found while running M2 against real repositories and new tests:** the quadratic
  `file_at` (70 s → 8.5 s on 20 curl releases); attribute macros read as function names;
  option-looking search text refused by the git guard; generated files missed under
  absolute build paths. Each now has a regression test.
- Machine: 16-core laptop, Fedora 44, Python 3.12.14, git 2.55.0; clones on btrfs, working
  tree on NTFS.

### Decisions (made under "decide and continue")
- **Timeline default: lazy** (ADR 0004).
- **LSan, MSan and TSan: deferred to M5.** They will be captured in the sandbox from real,
  already-fixed bugs in public projects at pinned tags, which answers the M1 open question
  without writing new crash programs.
- **Winnowing across a whole commit** (rank candidate files for a quoted snippet) moves to
  M3, where C07 is its only user; the primitives and their guarantee test are done.
- **SQLite amalgamation mapping** (`sqlite3.c:<line>` → `src/<file>.c`) needs the network
  module, so it moves to M3 with the `--online` fetch. Offline, `sqlite3.c` is already
  recognised as generated and never refuted.

### Open questions for the maintainer
- None blocking. The M3.5 gate still needs the HackerOne-terms check before any corpus is
  fetched.

## Carry-overs to later milestones

- **M3:**
  - C03 must treat `Timeline.uncertain_releases` and `history_complete=False` as "cannot
    refute"; C08 must not count third-party frames (it needs module or history info to tell
    them from fabricated ones).
  - Snippet provenance across a commit (C07): literal search for candidates, then
    winnowing and alignment.
  - SQLite amalgamation mapping with `--online` (SPEC §11.5 SHOULD); verify the
    `Begin file` banner regex against a real amalgamation first.
  - C11 must accept modern ASan wording ("N bytes after"; a SUMMARY naming
    `__asan_memcpy` plus the module) as well as the older form (ADR 0005).
  - Make the top application frame of a trace a core claim.
- **M3.5:** run the extraction smoke test on the real corpus. Check HackerOne's terms for
  the disclosed-report `.json` endpoint before fetching the corpus.
- **M5:** engine-specific sandbox flags (see the verification report, §6). Materialise
  build trees with `GitRepo.export_tree`, never `git archive`. Capture LSan, MSan and TSan
  fixtures from real, already-fixed public bugs.
- **M8:**
  - choose Zensical or Material for the docs (ADR);
  - `date-released` in `CITATION.cff` at v0.1.0;
  - add the docker ecosystem to Dependabot;
  - use `actions/attest` rather than `attest-build-provenance`;
  - re-verify every §0 fact for the README; drop or re-source the Alpha-Omega claim.
