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
| M3 Checks, fusion, CLI outputs | **done** (numbers below) |
| M3.5 Early real-world gate (curl corpus vs. slopcheck) | **measured 2026-09-26: no separation; P4 held (0/126)**; decision (b) reposition around grounding and reproduction (ADR 0012); 40-refutation hand-check still open |
| M4 HTML report and media v1 | **done** (PNG captures need Playwright; CI is the source of truth) |
| M5 Sandbox reproduction | **sandbox CI green with the real recipe image** (run 36129155719: Fedora `c-toolchain.Dockerfile` built, 21 passed); curl/sqlite/libxml2 recipes still unverified end to end |
| M6 NikashaBench | **machinery done** (S5/S6 offline); real splits wait on M3.5 corpus access |
| M7 Integrations | **done** (network paths tested with stubs only; see below) |
| M8 Launch polish and v0.1.0 | **done**: v0.1.0 released 2026-09-26 (PyPI, GHCR amd64/arm64, GitHub Release); `pip install nikasha` verified |
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

## M3: Checks, fusion, CLI outputs (2026-09-23)

### Done
- **Check framework** (`checks/base.py`): the `Check` protocol, auto-registration of every
  `cNN_*` module, a shared `CheckContext` (tree, paths, facts, timelines, BK-tree,
  permalinks) so twenty checks do not each re-read the repository, and per-check time
  bounds. Three rules are enforced *there* rather than in each check: the ADR 0003
  refutation gate, content-derived evidence IDs with stable ordering, and "a check that
  overruns or raises yields ERROR, never a refutation".
- **19 checks: C01–C18 and C21.** (C19 needs the sandbox, M5; C20 is the optional LLM, M7.)
  Every strength comes from `lr_defaults.yaml` — no float literal is ever used as a
  strength, so the whole scoring model is auditable and calibratable in one file.
- **Fusion** (`fuse/`): per-group damping (1, ½, ¼, …), `lambda`, the grounding score, and
  the SPEC §14.3 verdict ladder with configurable thresholds.
- **Questions** (`fuse/questions/`, jinja2): 22 templates keyed by (check, outcome), at
  most six, ordered by how much each would change the verdict.
- **Outputs**: terminal (rich), Markdown (under GitHub's 65,536-character comment cap,
  everything escaped) and JSON; `nikasha check` and `nikasha explain`.
- **`docs/checks.md` is generated** from the registry; `--check` fails when it is stale.

### Numbers
- **Tests: 3,493 passing**, 31 skipped, 1 xfail (a recorded SPEC divergence, below).
  2,564 at the end of M2. Coverage 93% overall, **95% on the core packages** (gate 85%).
- **Verdicts on the five vulnlab fixtures, offline — all five as intended:**

  | Fixture | Verdict | Score |
  |---|---|---|
  | `fabricated_hdr_overflow` | UNGROUNDED | 0/100, high |
  | `genuine_hdr_overflow` | GROUNDED | 100/100, high |
  | `mixed_wrong_version` | MIXED | 100/100, high |
  | `already_fixed` | MIXED | 82/100, low |
  | `vague` | INSUFFICIENT | 50/100, low |

- **One full check: 6.2 s** on the fabricated fixture (11 claims, 24 evidence items, 6
  questions), of which 5.9 s is the checks themselves and 4.2 s is C10 alone — it scores
  frame consistency across a window of releases, and is the obvious optimisation target.
- **Linear-time regexes: 1,449 patterns** now checked, because `nikasha.checks` was added
  to the sweep (154 at M2). That is how the ReDoS below was found.
- Machine: Windows 11, Python 3.12.13, repo on NTFS.

### Bugs found and fixed while building M3
- **A ReDoS in M1 intake code** (`ingest/blocks.py`): `^\s+at …` under `re.MULTILINE` is
  quadratic, because `\s` matches newlines and `^` retries at every line start. 16k
  newlines took 0.43 s and grew with the square of the input; now 0.0003 s. Found only
  because the checks package was added to the linear-time sweep.
- **ANSI escape injection into the terminal** through `ResolvedTarget.method`, which
  quotes the report text it resolved from (P7).
- `--ascii` was not ASCII (separator, ellipsis and panel borders).
- A report with no resolvable version raised an error instead of returning INSUFFICIENT.
- The runner skipped any check with no applicable claim, so a report with *zero* claims
  never reached C21 — exactly the case that drives INSUFFICIENT. Fixed with an opt-in
  `runs_on_empty`.
- Fusion could not identify a zero-strength outcome (C12 "already applied"), so
  `already_fixed.md` came out GROUNDED instead of MIXED. Every check now records the
  strengths key it used in `details["outcome"]`.

### Open questions for the maintainer
1. **C02 and C08 both judge trace frame paths, in different groups** (`locus` and `trace`),
   so §14.1 damping cannot cancel the overlap and one fabricated path can satisfy rule 3a's
   "two independent groups" on its own. SPEC specifies both behaviours; the interaction is
   what needs a decision. This is a P4 risk and belongs in the M3.5 measurement.
2. **Rule 3a counts groups over *all* refutations, not the strong ones**, so a single −0.3
   finding in a second group is enough corroboration beside a core refutation. Literal to
   SPEC, but the weakest link in the P4 chain.
3. **Rule 1 hard-codes `confidence="high"`** for REPRODUCED, which SPEC §14.3's confidence
   formula would call medium. Recorded as a strict xfail. Decide at M5, when C19 lands.
4. **Four checks asked for strength keys that do not exist** (C03 `absent_in_sampled_supporting`,
   C06 `elsewhere_in_repo` and `absent_in_sampled_releases`, C07 `absent_in_sampled`). Today
   those P4 downgrades collapse to NEUTRAL 0.0, discarding real signal. Adding them changes
   the scoring model, so it is a calibration decision (§14.2), not one to make by hand.
5. **No `CommandRecord` is emitted anywhere**, although P6 asks for the command with output
   hashes. Four checks flagged the same blocker: `GitResult.argv` carries absolute cache
   paths (a P3 leak into rendered reports) and `duration_ms` would break byte-identical
   JSON. It needs one shared helper with a redacted argv and the duration kept out of the
   identity payload.

## M3.5: Early real-world gate (2026-09-26)

### Done

- ADR 0011: public HackerOne report access allowed under conditions (disclosed reports
  only, >=2 s between requests, one connection, honest User-Agent, cache only in the
  gitignored `bench/cache/`, purge on objection, re-check terms per refresh). Terms page
  and robots.txt (sitemap only, no `Disallow`) re-checked 2026-09-26.
- `nikasha.bench.h1corpus` (online-only, rate-limited, capped, resumable, stores title and
  body only), `nikasha bench fetch-h1`, `bench run --h1-cache`, `nikasha bench gate`
  (`nikasha.bench.gate`). Tests use a stubbed transport and clock.
- Manifests S1 (49 slop) and S2 (126 resolved) from slopcheck's curl index (MIT,
  commit d5b6965), IDs, URLs and labels only. The 382 unlabelled reports are left out,
  as slopcheck's corpus card says they are not negatives.
- Full corpus run, no subset: 175/175 fetched, 0 dropped; 175 cases, 0 errors, 96 min
  on this laptop, against a full curl clone. Each report is checked at the version it
  names (Nikasha's own resolution; no `--ref` forced).

### Numbers (`bench/results/2026-09-26/gate.json`, not committed)

| metric | Nikasha | slopcheck |
|---|--:|--:|
| flag rate (>=1 REFUTES) genuine / slop | 20.6% / 20.4% | 29.4% / 28.6% |
| J of that flag | -0.002 | about -0.008 |
| false UNGROUNDED on genuine | **0/126** (Wilson 95% upper 2.96%) | n/a |
| recall UNGROUNDED on slop | 0/49 | n/a |
| recall UNGROUNDED or MIXED on slop | 20.4% (10/49) | n/a |
| MIXED or UNGROUNDED on genuine | 22.2% (28/126) | n/a |
| J (UNGROUNDED or MIXED) | -0.018 | n/a |
| best J, score threshold sweep | 0.249 | 0.083 |
| median best J, seeded random score | 0.103 | 0.092 |

Verdicts: genuine GROUNDED 32, MIXED 28, INSUFFICIENT 66; slop GROUNDED 5, MIXED 10,
INSUFFICIENT 34.

### Reading

- **P4 held:** no genuine report was called UNGROUNDED. With n=126 the Wilson upper
  bound (2.96%) cannot yet show the rate is under 1%.
- **The verdict layer does not separate slop from genuine.** Nikasha never says
  UNGROUNDED on this corpus, and MIXED is as common on genuine reports as on slop. The
  refutation flag is no better than slopcheck's (J about 0).
- The only signal is the fused score: the best threshold J (0.249) is above the random
  control (0.103). It comes mostly from GROUNDED being more common on genuine reports
  (25%) than on slop (10%), i.e. *support* separates, refutation does not. The sweep
  picks its threshold after the fact, like slopcheck's, so it is optimistic.
- Ablation: no single check changes false UNGROUNDED (all 0). Removing C02 lowers slop
  UNGROUNDED-or-MIXED recall to 14.3%; C03 and C04 to 18.4%.
- Not done: the hand-checked precision of 40 random REFUTES findings (ADR 0003) needs a
  human reviewer. No threshold was changed.

### Decision (2026-09-26)

- The maintainer chose option **(b), reposition** (ADR 0012): Nikasha leads with grounding
  (which claims the code supports, at which version, with evidence) and sandbox
  reproduction. Refutations stay gated and conservative and are presented as questions and
  leads, never as a fabrication detector. UNGROUNDED keeps only its existing strict rule.
  No threshold, strength or scoring change until calibration on more data (M6).
- README, `docs/index.md` and `docs/concepts.md` reworded; a short "Real-world results
  (M3.5)" section publishes the numbers above with their caveats.

### Next / questions for the maintainer

- **Still open:** hand-check 40 random REFUTES findings for per-finding precision.
  `scripts/handcheck_sample.py` (seeded, deterministic) writes a blind worksheet (no
  genuine/slop label) to `bench/cache/handcheck-2026-09-26.md` (gitignored). The run has
  59 REFUTES findings, so the sample is a full 40. `results.jsonl` stores only check,
  group, outcome and strength per finding, so the worksheet says where to look
  (`nikasha check` on the report) for the claim, summary and location.
- M6: measure supporting-evidence recall, reproduction rate and refutation precision
  (ADR 0012).

## M4: HTML report and media (2026-09-24)

### Done
- The self-contained report (SPEC §15.2): CSP `default-src 'none'` with the one script pinned
  by sha256, an escaping contract with no "mark safe" helper, excerpts read at render time,
  eleven discovered components, a two-column band, light/dark/print themes.
- `make screenshots`: ten terminal SVGs from real runs; HTML PNGs skip with instructions
  when Playwright is absent (it needs a browser download).
- pygments added (planned in ADR 0002); `cvss` deliberately not adopted (ADR 0002).

### Numbers
- **Tests: 4,143 passing** (3,493 at M3). Core coverage unchanged at 95%.
- Pages: fabricated 238 KB, genuine 265 KB, vague 19 KB; a 300-claim stress result 945 KB
  against the 1.5 MB budget. Deterministic, CSP hash verified from the rendered document.
- The security suite mutation-tested 22 injected vulnerabilities: all caught, 0 false positives.

### Found and fixed
- Two "wrong escaper for the sink" cases (meta description, an SVG aria-label), both
  unreachable today, both fixed.
- The `data:` download link was verified in headless Chrome under the real CSP: the file
  downloads byte-identical to the embedded JSON.

### Open
- *Closed 2026-09-26:* C08 emits `checks: {file, function, line}` per frame and the trace table
  reads it (prose is only a fallback); C03's `uncertain` branch carries `defined_in`.
- *Closed 2026-09-26:* the version-fit view reads C10's `ratios_in_release_order`, so order
  survives a JSON round trip.
- PNG captures and the web-UI capture need Playwright (network); `screenshots.yml` owns them.

## M7: Integrations (2026-09-24)

### Done
- `nikasha lint` (reporter pre-submit mode, P8), `nikasha cve` (CVE JSON 5.x intake),
  `nikasha h1` and `nikasha gh-advisories` (read-only, `--online` only), `.eml` intake,
  the GitHub Action with an example workflow, the MCP server (`nikasha mcp`), the hardened
  local web UI (`nikasha serve`), the optional LLM layer with its guard and C20, and
  `nikasha.toml` settings wired into `check` (`--config`, `--llm`).
- The `[mcp]`, `[web]` and `[llm]` extras, which had been empty stubs since M0 (ADR 0002).
- README v1 and the CONTRIBUTING guides, each fact-checked claim by claim against the tree.
- Every integration was built, then reviewed adversarially by a separate agent, then fixed.

### Security fixes found by the M7 reviews
- Web UI: the report iframe's sandbox was void (`allow-scripts allow-same-origin` on the UI's
  own origin); a chunked POST bypassed the upload cap; UNC repository paths made Windows
  offer NTLM credentials to an arbitrary host.
- LLM guard: a run of 5+ brackets re-formed the untrusted-text delimiter; the Ollama provider
  honoured `HTTP_PROXY` and followed redirects, so a prompt could leave the machine.
- Intake: bounce and receipt parts stored the sender's identity (SPEC §7); credentials were
  forwarded on redirect; pre-signed attachment URLs leaked into printed output.
- Settings: an ignore glob from `nikasha.toml` could hang the matcher (now linear).
- CVE intake: a record could vouch for itself by citing its own ID.
- CommandRecord: an unmeasured duration was printed as "0 ms" (P6); it is now `None`.

### Numbers
- **Tests: 5,105 passing** before the last fixes (4,143 at M4); final count in the commit.

### Open
- Network paths (`--online` for cve, h1, gh-advisories; the cloud LLM SDKs) are tested with
  stubbed transports only. Nothing here has talked to the real services.
- The Action pins `actions/checkout` and `actions/setup-python` by SHAs written offline;
  re-verify them with `gh api` before M8 (CLAUDE.md).
- `[questions]` and `[ignore]` in `nikasha.toml` are consumed by `check` (ignored paths are
  never judged).
- A line-level review of M3/M4 hit the session limit mid-run: 124 findings across C01-C09
  were raised but never verified (27 high, 1 critical, mostly P4 conservatism), and the other
  29 review targets were never examined. Both are now closed (see "Reviews closed" below).

## Reviews closed (2026-09-25)

- The 124 C01-C09 findings were each verified and fixed or rejected, then re-reviewed
  independently; three fixes the re-review rejected (C01, C04, C05) were redone (`03ddd47`).
- Every module never reviewed before (C11, C13-C18, C20, C21, fusion, renderers, gitio) got a
  line-level adversarial review, probe-confirmed fixes and an independent re-review; all six
  groups approved. Most fixes remove false refutations (P4), e.g. C11 no longer calls
  genuine ASan output self-contradictory for past-the-end accesses, paths with spaces,
  disclosed stack cuts or `<empty stack>`; C14 treats a failed history search as incomplete.

## M5: Sandbox reproduction (2026-09-25)

### Done
- `nikasha repro` and `nikasha recipes` (list, show, validate); recipe schema
  `schema/recipe-v1.json` agreeing field by field with the pydantic model; recipes for
  vulnlab, curl, libxml2 and sqlite; `docker/recipes/c-toolchain.Dockerfile`.
- Build in the sandbox, then run the PoC in a second hardened container. Container output is
  hostile: symlinks, devices and FIFOs in `/out` are refused, files are opened with
  `O_NOFOLLOW` and lose setuid bits, scratch is removed even when uid 65534 locked it
  (scrub container), and PoC stderr is shown with every control and bidi character escaped.
- Signature matching and C19. Frames under `/poc/` never count as application frames;
  c_harness output is not attested, so it yields at most `harness_unverified` (never
  REPRODUCED); matching work is capped. `CheckContext.repro` carries a `ReproRun`.
- `.github/workflows/sandbox.yml` runs `pytest -m "sandbox and not network"` on ubuntu.
- ADR 0010: tmpfs mounts use `mode=1777` (found on the first real engine run).

### Numbers
- Sandbox suite on Docker 29.3.1 here: see the commit; unit tests for `repro/` and C19: 211.

### Open
- The real recipe image (Fedora) could not be built here: the network proxy refuses the
  Fedora registries. Local sandbox runs used a stand-in image (gcc/clang on Debian/Ubuntu).
  M5 is done only when `sandbox.yml` is green in CI with the real image.
  *Resolved 2026-09-26 from CI logs:* `sandbox.yml` builds
  `docker/recipes/c-toolchain.Dockerfile` (FROM `fedora:44@sha256:b4488a77…`) as
  `nikasha/recipe-c:1` in its own step, and the tests reuse it. Main run 36129155719
  (2026-09-25): 21 passed, 1 skipped, the skip being `tests/unit/integrations/test_web.py`
  (fastapi not installed in that job; not a sandbox test). No sandbox test was skipped.
- Every run kind declares `attested_output` (default false); only vulnlab `file_input` is
  attested, so scriptable targets (sqlite, curl, libxml2 cli/file_input) can never yield
  REPRODUCED. The recipe loader refuses a sanitizer build without `abort_on_error=1`.
- The curl, sqlite and libxml2 recipes are unverified end to end: the stand-in image has no
  tclsh, and gitlab.gnome.org is blocked from this environment.
- C19 scores a timeout as `no_crash` (-0.5, per SPEC §12). For a report that claims a hang,
  a timeout is a reproduction: maintainer decision.
- Copies out of `/out` are capped at 1 GiB and 10,000 entries.

## M6: NikashaBench (2026-09-25)

### Done
- `nikasha bench` (run, calibrate), manifests for S1-S3, S5 and S6, mutation
  operators, metrics and charts; `bench/README.md` and `DATASET_CARD.md`.
- Results are reproducible: the same case run twice gives the same record (tested), and C10
  gives identical evidence for identical input. The root cause
  of the earlier drift was C10's evidence ID, which depended on how far a timed scan got.
- Generated results under `bench/results/*/` are gitignored.

### Open
- S1-S3 (real reports) wait on M3.5 corpus access and the HackerOne terms decision.
- `bench calibrate` writes `calibration-vN.yaml` (never overwriting); `bench run` draws a
  reliability diagram and takes `--repro` (§17.3). No manifest names a PoC yet, so the repro
  subset is empty until PoC fixtures are added.
- C10 scans a fixed number of releases (64); the wall clock is only a safety net, and when it
  fires C10 gives one fixed NEUTRAL `scan_timed_out` regardless of progress.

## M8: Launch tooling (2026-09-25)

### Done
- `release.yml` (PyPI via trusted publishing, GHCR image, attestations), `docs.yml`
  (Zensical, `--strict`, deploys only when `vars.PAGES_ENABLED == 'true'`), `screenshots.yml`.
  Every action is pinned to a peeled commit SHA. The artifacts published are exactly the
  ones `scripts/release_check.py` inspected. Pre-releases are never tagged `latest`.
- `scripts/release_check.py` passes on a real build (the sdist now includes `schema/`).
- Docs site pages, `docs/THREAT_MODEL.md`, ADR 0008 (Zensical). `make docs` builds strictly.

### Needs the maintainer
- Create the PyPI trusted publisher and the `pypi` and `ghcr` environments with required
  reviewers; enable Pages and set `PAGES_ENABLED`; allow Actions to open PRs for
  `screenshots.yml`. Then tag v0.1.0.

## LSan, MSan, TSan parsers (2026-09-25)

- Parsers exist and are tested against realistic lines, but stay unregistered (ADR 0009):
  no real fixture has been captured. `scripts/capture_sanitizer_fixtures.py` uses the real
  sandbox API and validates output before writing anything, but its `BUGS` catalogue is
  empty on purpose: each entry (public repo, vulnerable and fixed tags, fix SHA, trigger)
  must be verified by a person. SPEC §9.5 asks for three per format.

## Items 4-8 after v0.1.0 (2026-09-26)

- **M6 data.** S3: all six SQLite CVEs from the JFrog post are REJECTED and blanked in
  cvelistV5, so they are excluded and documented (`excluded:` in the manifest, SPEC §17.2).
  S4: excluded, the dataset repository has no license. S1/S2 cannot grow from public data
  (the slop list has 49 IDs; every HackerOne-linked record in curl's `vuln.json` is in S2).
  Calibration kept the defaults: 49 fabricated reports is below the 50-per-class rule.
  *Open for the maintainer:* may S3 use a CVE record's pre-rejection text from cvelistV5's
  git history?
- **Repro subset.** Two S6 cases carry a PoC (`examples/vulnlab/pocs/hdr_overflow.txt`):
  genuine at v1.2.0 (expected REPRODUCED) and already-fixed at v1.3.0 (expected no crash).
  `tests/sandbox/test_bench_repro_subset.py` checks both in the Sandbox CI job.
- **LSan/MSan/TSan.** The capture catalogue lists nine already-fixed public bugs (three per
  format: zstd, lz4, jq, zlib, xz and others), each fix SHA checked upstream. Capture runs
  only in CI (`sanitizer-fixtures.yml`, manual dispatch); parsers stay unregistered until
  real fixtures are committed (ADR 0009).
- **SQLite amalgamation (§11.5).** `code/amalgamation.py` maps `sqlite3.c:<line>` back to
  the source file with `--online`; checked against the real 3.45.1 amalgamation (255,680
  lines; 98.5% of mapped lines identical to the `version-3.45.1` tag). In C05 a mismatch
  after mapping is only NEUTRAL (P4).
- **M7 network paths.** Run live against cvelistV5 and the GitHub API; five bugs fixed
  (e.g. empty CVE ranges such as CVE-2023-38545's `8.4.0 <= v < 8.4.0` are skipped, and
  `changes[]` ranges such as Log4j's are split rather than collapsed). Live network tests
  in `tests/integration/test_m7_network.py` run in Nightly. Not verified: the HackerOne API
  (needs credentials), anonymous GitHub at scale, cloud LLM providers (no keys).

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
  - *2026-09-25:* all of the above are done and tested except the SQLite amalgamation
    mapping, which needs `--online` verification.
- **M3.5:** run the extraction smoke test on the real corpus. Check HackerOne's terms for
  the disclosed-report `.json` endpoint before fetching the corpus.
- **M5:** engine-specific sandbox flags (see the verification report, §6). Materialise
  build trees with `GitRepo.export_tree`, never `git archive`. Capture LSan, MSan and TSan
  fixtures from real, already-fixed public bugs.
- **M8:**
  - choose Zensical or Material for the docs (ADR);
  - `date-released` in `CITATION.cff` at v0.1.0;
  - add the docker ecosystem to Dependabot;
  - *2026-09-25:* a nightly workflow runs the `network` and `sandbox and network` suites;
  - use `actions/attest` rather than `attest-build-provenance`;
  - re-verify every §0 fact for the README; drop or re-source the Alpha-Omega claim.
