<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing to Nikasha

Thanks for helping. Nikasha's credibility rests on being **correct, deterministic and
conservative**, so the bar for tests is high. The good news is that the process is
mechanical, and this file walks through every step of it.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Python ≥ 3.11, [uv](https://docs.astral.sh/uv/), git and `make`. The sandbox
tests also need podman or docker.

```bash
git clone https://github.com/rakshit-737/nikasha && cd nikasha
make setup          # uv sync --all-groups, then the pre-commit and commit-msg hooks
make lint type test # the gates every PR must pass
```

| Target | What it does |
|---|---|
| `make setup` | `uv sync --all-groups`, then `pre-commit install` for the `pre-commit` and `commit-msg` hook types |
| `make lint` | The placeholder check on `README.md` and `docs/`, `ruff check` and `ruff format --check` on `src tests scripts`, `codespell`, and `reuse lint` (run through `uvx --from reuse==6.2.0`) |
| `make fmt` | `ruff format`, then `ruff check --fix` |
| `make type` | `mypy` in strict mode over `src/` (the configuration is in `pyproject.toml`) |
| `make test` | The fast suite (`-m "not sandbox and not network and not slow"`, set in `pyproject.toml`) with coverage, then a coverage gate of at least 85% on `extract/`, `code/`, `ingest/` and `model/` |
| `make test-all` | Every test (`pytest -m ""`), including the sandbox, network and slow suites |
| `make screenshots` | `scripts/make_screenshots.py`: regenerates every README image from a real run. The terminal SVGs need nothing extra; the HTML captures are skipped with a message unless Playwright is installed |

`bench`, `docs`, `demo` and `release-check` are stubs that print which milestone brings
them and exit 1 (see [`PROGRESS.md`](PROGRESS.md)).

The pre-commit hooks run most of what `make lint` and `make type` run (ruff format,
ruff check with fixes, codespell, mypy on `src/`), plus a `commit-msg` hook that runs
`scripts/check_commit_msg.py` on every commit message. `reuse lint` and the placeholder
check run only from `make lint`; no hook covers them.

### Test markers

Three markers are declared in `pyproject.toml`, and the default run excludes all of them:

- `sandbox`: needs a container engine (`-m sandbox`);
- `network`: needs network access (`-m network`);
- `slow`: long-running (`-m slow`).

CI runs the fast suite on ubuntu, macOS and Windows for Python 3.11, 3.12, 3.13 and 3.14,
and the lint job runs `make lint` and `make type` on ubuntu. The intended home of the
`sandbox` suite is a CI job on ubuntu, and of the `network` suite a nightly job (SPEC
§13.6 and the marker text in `pyproject.toml`), but no workflow under `.github/workflows/`
runs either marker yet: the four workflows there are `ci.yml`, `codeql.yml`,
`dependency-review.yml` and `scorecard.yml`, and `ci.yml` runs plain `uv run pytest --cov`
with the default marker expression. Run those suites locally with `-m sandbox` or
`-m network`.

### Notes for Windows

- `reuse` 6.2.0 detects file encodings through one of three Python modules: `python-magic`
  (a binding to libmagic, which its hint about installing `file` refers to; it is skipped
  outright on Windows), `charset-normalizer` or `chardet`. A bare `uvx` environment ships
  neither of the last two, so the `reuse lint` step of `make lint` stops with
  `NoEncodingModuleError`. Having the `file` command on `PATH` (Git for Windows provides
  one) does not help, because `reuse` never calls it. Run the step with the extra instead:

  ```bash
  uvx --from "reuse[charset-normalizer]==6.2.0" reuse lint
  ```

  The rest of `make lint` (ruff, codespell, the placeholder check) works unchanged.
- git on Windows usually has `core.fileMode=false`, so a script's executable bit is set
  with `git update-index --chmod=+x path/to/script.py`, not with the filesystem.

## Standards

- **Typing:** `mypy --strict` must be clean on `src/` (`make type` is a PR gate). No `Any`
  without a comment explaining why.
- **Style:** `ruff format` and `ruff check` (line length 100, rules in `pyproject.toml`).
  Keep functions small and algorithms simple and explainable; document complexity in
  docstrings. Every module that carries annotations starts with
  `from __future__ import annotations` (small modules without any, such as `errors.py`,
  `version.py` and most package `__init__.py` files, do not).
- **Determinism:** the same inputs must give byte-identical JSON, timings excepted.
  - Sort every collection you output.
  - Derive IDs from content (`sha256(kind + canonical fields)[:12]`).
  - Checks must never read the wall clock or depend on the environment.
- **Process boundary:** git runs only through `nikasha.code.gitio`, container engines
  only through `nikasha.repro.sandbox`. `tests/unit/test_process_boundary.py` scans the
  source tree for any other `subprocess`, `os.system`, `os.spawn*` or similar call, and
  ruff's banned-API rule (`TID251`) refuses `subprocess` imports outside those two
  modules. Nothing is fetched from the network without `--online` (P3).
- **Every regex is linear-time.** `tests/unit/extract/test_regex_linear.py` imports every
  module under `nikasha.extract`, `nikasha.extract.traces`, `nikasha.ingest`,
  `nikasha.code`, `nikasha.resolve` and `nikasha.checks`, collects every module-level
  compiled pattern (text or bytes), and runs each against hypothesis-generated seeds
  repeated to about 40,000 characters plus eight fixed hostile shapes, with a budget of
  0.5 s per run. A new module in those packages is covered automatically; a pattern that
  must live elsewhere needs its own test. Use bounded (`{0,300}`) or possessive
  (`{0,4000}+`) quantifiers rather than `.*` and `\s+`, and remember that `\s` matches
  newlines: `^\s+` under `re.MULTILINE` was a real ReDoS in this codebase.
- **Escaping:** everything that reaches HTML or Markdown output is escaped. Nothing
  derived from input is ever marked "safe".
- **Wording:** refer to claims, never to people. No "AI-written" heuristics, ever.
- **Licensing:** every source file starts with SPDX headers:

  ```python
  # SPDX-FileCopyrightText: 2026 The Nikasha Authors
  # SPDX-License-Identifier: Apache-2.0
  ```

  Documentation is CC-BY-4.0. `reuse lint` must pass.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(extract): …`,
  `fix(checks): …`, `docs: …`, `test: …`, `ci: …`, `chore: …`.
- **Sign off every commit** under the [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s`. This adds `Signed-off-by: Your Name <you@example.com>`, certifying
  that you have the right to submit the change under the project's licence.
- `scripts/check_commit_msg.py` enforces both, locally as the `commit-msg` hook and in CI
  once per commit of a pull request (bot commits are skipped there). It accepts:
  - a header `type(scope)!: subject`, where `type` is one of `build`, `chore`, `ci`,
    `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style` or `test`; the scope is
    optional and matches `[a-z0-9._/-]+`; the `!` is optional; the subject is at most 99
    characters;
  - a `Signed-off-by: Name <email>` trailer somewhere in the message;
  - lines starting with `#` are ignored, and messages starting with `Merge `, `Revert "`,
    `fixup! ` or `squash! ` are exempt.

  Its tests are in `tests/unit/test_commit_msg.py`.
- Keep pull requests focused. Add tests first for parsers and checks. Update
  `CHANGELOG.md` under *Unreleased*. If you changed the terminal or HTML output,
  regenerate the screenshots with `make screenshots`; never hand-edit them. The pull
  request template has the full checklist.
- **Never commit** secrets, personal data, embargoed report text, or third-party report
  text whose licence isn't clear. Benchmark manifests hold IDs and labels only.

## Step-by-step guides

The package layout is described in [`CLAUDE.md`](CLAUDE.md) and [`SPEC.md`](SPEC.md) §6.
Every guide below describes the code as it is in the tree today; where a milestone has not
landed yet, the guide says so instead of inventing a format.

### Adding a check

A check answers one factual question about a report's claims against the repository at
the resolved commit and returns `Evidence` (SPEC §12). Read
`src/nikasha/checks/base.py` first, then `c04_line_in_bounds.py`, which is the smallest
complete example.

1. **Pick the ID, the group and the claim kinds.** IDs C01–C21 are assigned in SPEC §12
   (C19 is reserved for sandbox reproduction in M5); a new check takes the next number.
   `applies_to` is a `frozenset` of claim kinds from `model/claims.py`: `version`,
   `symbol`, `file`, `line`, `trace`, `snippet`, `patch`, `poc`, `reference`, `option`,
   `impact`, `behavior`. The group matters for scoring: fusion damps evidence *within* a
   group (weights 1, ½, ¼, …, `fuse/scoring.py`), so put a finding that overlaps another
   check's in the same group, or leave it to that check. C04 returns nothing for a path
   that does not resolve, because that is C02's finding. The groups in use are the ones
   listed in `docs/checks.md`, which is generated from the registry.

2. **Add the strengths to `src/nikasha/checks/lr_defaults.yaml`**, one key per outcome
   under the check's ID, on the scale in that file's header: refutations strong −3.0,
   moderate −1.2, weak −0.4; support weak +0.4, moderate +1.0, strong +2.0; decisive
   +6.0. Those are priors until calibration (SPEC §14.2) replaces them, and they are never
   tuned to make a fixture pass. A check never writes a float literal as a strength:
   `Strengths.get(check_id, outcome)` raises `StrengthsError` for a key that is not in the
   table, and the check's `__init__` takes an optional `Strengths` (defaulting to
   `default_strengths()`) so tests can substitute a table.

3. **Write the tests first**, in `tests/unit/checks/test_cNN_<name>.py`. Every check test
   runs against the real vulnlab history, built once per session by
   `scripts/build_vulnlab.py` (five tags, `v1.0.0` to `v1.3.0`), never against mocks. The
   fixtures come from `tests/unit/checks/conftest.py`:

   - `make_ctx(claims=[...], tag="v1.3.0", report=..., online=False)` builds a
     `CheckContext` at a tag; the default tag is `v1.2.0`, the release the demo bug is
     reported against;
   - `ctx` is a context at `v1.2.0` with no claims.

   Everything a test imports by name lives in `tests/unit/checks/check_helpers.py`, not in
   `conftest.py`: pytest imports every `conftest.py` as the bare module `conftest`, so two
   directories that each do `from conftest import ...` resolve to whichever one loaded
   first. `check_helpers.claim(LineClaim, path="src/util.c", line=10)` builds a claim with
   a content-derived ID, `provenance="project_attributed"`, `negated=False` and
   `role="supporting"` by default, so a test that says nothing else exercises the
   *refutable* path. Cover:

   - every outcome, including NEUTRAL for claims the check must not judge;
   - the ADR 0003 gate, as separate tests: one passing `provenance="reporter_artifact"`
     (or `third_party`, `unscoped`) and one passing `negated=True`, each asserting that the
     evidence came back NEUTRAL with strength 0.0, `details["gated"]` naming the one
     reason, and `details["withheld_strength"]` carrying the strength it would have had
     (`TestRefutationGate` in `test_c04_line_in_bounds.py` is the model);
   - determinism: two runs on the same input give the same evidence IDs and the same
     `model_dump()`;
   - the runner: `run_checks(ctx, checks=[YourCheck()])` returns one `CheckRun` with
     `error is None`.

   ```python
   from check_helpers import MakeContext, claim
   from nikasha.checks.c04_line_in_bounds import LineInBounds
   from nikasha.model.claims import LineClaim

   def test_line_past_the_end_refutes(make_ctx: MakeContext) -> None:
       c = claim(LineClaim, path="src/util.c", line=9999)
       ctx = make_ctx(claims=[c])
       (evidence,) = LineInBounds().run(ctx, [c])
       assert evidence.outcome == "REFUTES"
       assert evidence.details["outcome"] == "past_end"
   ```

4. **Implement `src/nikasha/checks/cNN_<name>.py`.** The module name must match
   `^c\d{2}_[a-z0-9_]+$`: `nikasha.checks.load_checks()` imports every such module in
   sorted order, so a check registers itself by existing. The class:

   ```python
   @register
   class LineInBounds(BaseCheck):
       id = "C04"
       name = "LINE_IN_BOUNDS"
       group = "lines"
       applies_to: frozenset[ClaimKind] = frozenset({"line"})
       description = "Checks that a cited line number exists in the file at the resolved commit."
   ```

   `register` instantiates the class at import time and raises `ValueError` on an empty
   or duplicate `id`. `description` is the sentence that appears in `docs/checks.md`.
   `run(ctx, claims)` receives only the claims whose kind is in `applies_to`, in report
   order, and returns a list of `Evidence`. A check with no applicable claim is skipped
   unless it sets `runs_on_empty = True`; only a check that reports on the *absence* of
   claims needs that (C21 does, because an empty report is exactly the case it describes).

5. **Build evidence only with `make_evidence`.** It applies the ADR 0003 gate so no
   check can forget it: a `REFUTES` outcome survives only when **every** cited claim is
   `project_attributed` and not negated (`is_refutable`); otherwise the outcome becomes
   `NEUTRAL` with strength 0.0, `details["gated"]` lists the reasons (`negated` or the
   provenance), `details["withheld_strength"]` keeps the number, and the summary gets the
   gate note appended. A `NEUTRAL` outcome with a non-zero strength is zeroed the same
   way. The evidence ID is derived from the check ID, the sorted claim IDs, the outcome,
   the strength (rounded to 6 places), the summary, the details and the locations, and
   never from `commands`, so attaching a command record cannot move an ID.

   Conventions every check follows:

   - `strength=self.strengths.get(CHECK_ID, key)` and `details={"outcome": key, ...}` with
     the **same key**. `fuse/verdict.py::outcome_key` reads `details["outcome"]` to tell
     which outcome fired; its fallback (matching the strength against the table) is
     ambiguous for zero-strength outcomes, which is how an "already applied" patch once
     turned a MIXED report into GROUNDED.
   - Put the concrete facts in `details` (the real line count, the release names, the
     suggestions), because the question templates and the HTML report read them.
   - `locations=[ctx.location(path, start_line, end_line, excerpt=...)]` gives a
     `CodeLocation` at the exact commit with an upstream permalink (for github.com and
     gitlab.com repositories; `None` elsewhere).
   - When the check ran git, attach `commands=[...]` built with
     `nikasha.code.gitio.command_record(result)`: it redacts absolute paths in the argv,
     stores sha256 hashes of stdout and stderr rather than the bytes, and keeps
     `duration_ms` at 0 so two runs on the same input stay byte-identical (P6, ADR 0007
     decision 4).
   - Outcomes are `SUPPORTS`, `REFUTES`, `NEUTRAL` or `ERROR`. Raise `CheckError` (or
     anything) for a failure that must not become a refutation: `run_checks` turns it into
     one `ERROR` item with strength 0 and records the message in `CheckRun.error`.

6. **Use the shared context instead of re-reading the repository.** `CheckContext`
   caches the tree paths, a `PathTrie` (`ctx.resolve_path` tries the exact path, then a
   suffix match), parsed `FileFacts` (`ctx.facts`), line counts (`ctx.line_count`), the
   symbol names and a BK-tree for "did you mean" (`ctx.suggest_symbols`), and per-symbol
   release timelines (`ctx.timeline(name)`). `ctx.commit`, `ctx.ref_name` and
   `ctx.repo_url` are the resolved target. Every check gets a deadline (10 s by default);
   a loop over releases or history must poll `ctx.expired()` and stop with what it has.
   `ctx.llm` is `None` in every offline run; only the optional model review (C20) reads
   it, and nothing it says is ever decisive (P2).

7. **Respect P4: absence is never proof.** These rules are not optional:

   - a timed-out or shallow history search sets `Timeline.history_complete = False`;
     never emit a "never existed" outcome then. Downgrade to the sampled-releases outcome
     and say in the summary that history was incomplete (C03 is the model);
   - a release in `Timeline.uncertain_releases` had the name only in files that did not
     parse cleanly; report *uncertain*, not absent;
   - `ctx.generated(path)` is not `None` for generated and release-only files (SPEC
     §11.5); return NEUTRAL with `details["outcome"] = "generated"` and the reason, and
     never judge the file;
   - a finding another check owns is that check's, not a second refutation.

8. **Add a question template for each refuting outcome**:
   `src/nikasha/fuse/questions/<ID>.<outcome>.j2`, one file and no code. Templates render
   with `StrictUndefined`, so every variable they use must be in `details`. The tone tests
   in `tests/unit/fuse/test_questions.py` render every template and scan both the source
   and the output for the words a neutral question must not contain (SPEC §14.4 and
   Appendix D: neutral and specific, no accusations, nothing about how the report was
   written, and the closing line is appended automatically).

9. **Regenerate the catalogue**: `uv run python scripts/gen_checks_doc.py` rewrites
   `docs/checks.md` from the registry and the strengths table; `--check` exits 1 when the
   committed file is stale, and the pull-request checklist asks for it. If the outcome
   belongs in `fuse/verdict.py`'s `VERSION_MISMATCH` or `NEVER_EXISTED` sets, or changes
   a verdict rule in any other way, write an ADR: those sets decide which refutations can
   open the UNGROUNDED door. Add a line to `CHANGELOG.md`.

10. **Check the demo verdicts.** NikashaBench and calibration arrive in M6 and the M3.5
    real-world gate has not run yet, so there is no real-corpus number to protect. What
    exists is the vulnlab demo: build the repository with
    `uv run python scripts/build_vulnlab.py <dest>` and run
    `uv run nikasha check examples/reports/<fixture>.md --repo <dest>` for the five fixture
    reports. `PROGRESS.md` records the verdicts they are expected to produce
    (`fabricated_hdr_overflow` UNGROUNDED, `genuine_hdr_overflow` GROUNDED,
    `mixed_wrong_version` MIXED, `already_fixed` MIXED, `vague` INSUFFICIENT). A new check
    must not move a genuine fixture towards UNGROUNDED.

### Adding a trace format

Trace parsers live in `src/nikasha/extract/traces/`, one module per format, on top of
`common.py` (SPEC §9.5). Nine formats exist today (ASan, UBSan, valgrind, gdb, Python,
Java, Go, Rust, Node). LSan, MSan and TSan are declared in the `TraceFormat` literal but
have no parser, because no real fixtures exist yet; they are planned for M5, captured from
real, already-fixed public bugs (ADR 0005, `PROGRESS.md`).

1. **Capture real fixtures first: at least three, never hand-written or edited**
   (ADR 0005). `scripts/capture_trace_fixtures.py` is the only way fixtures are made. It
   builds the pinned toolchain image from `docker/capture/Containerfile`, runs every
   capture under rootless podman with `--network none`, `--read-only`, `--userns=keep-id`,
   `--cap-drop ALL` and `--security-opt no-new-privileges`, writes the unedited output to
   `tests/fixtures/traces/<format>/NN-<name>.txt`, and regenerates that directory's
   `README.md` with the capture date, image ID, base image digest, tool versions and the
   exact command for every fixture. To add a format:
   - put a small program that fails in an ordinary way under
     `tests/fixtures/traces/programs/<format>/`. Memory-error traces come **only** from the
     deliberate vulnlab bug; everything else is a benign error such as an exception, a
     failed assert or arithmetic undefined behaviour;
   - add the toolchain to `docker/capture/Containerfile` and a version command to
     `_VERSION_CMDS`;
   - add one `Capture(fmt, name, what, script, stream=..., group=...)` row per fixture to
     `CAPTURES`;
   - run `python scripts/capture_trace_fixtures.py --only <format>` (`--no-build` reuses
     the image). This needs podman on the machine; nothing runs on the host (P5).

   Fixtures are snapshots: addresses and build IDs change on every capture, so tests
   assert the parts that are stable (functions, files, lines, sizes, messages).

2. **Name the format.** `TraceFormat` in `src/nikasha/model/claims.py` is the literal of
   accepted format names. A brand-new format adds a value there, and then
   `uv run python scripts/gen_schema.py` regenerates `schema/result-v1.json`
   (`tests/unit/test_schema.py` fails while it is stale).

3. **Write the parser tests** in `tests/unit/traces/test_trace_<format>.py`, modelled on
   `test_trace_go.py`: load each fixture, assert the trace's `[start, end)` offsets, the
   `bug_type`, `message` and `thread`, the frames' functions, paths and lines, which
   frames are marked `is_runtime`, and that the same text embedded in a Markdown report
   (`ingest_string` then `extract_claims`) yields a `TraceClaim`. Path normalization is
   tested once for every format, in `tests/unit/traces/test_trace_common.py`. Add
   the two hypothesis tests every parser has: `@given(st.text())` and a shuffled mix of
   fixture lines and random text, both asserting that `parse` returns without raising.

4. **Implement `src/nikasha/extract/traces/<format>.py`** with `common.py`:

   ```python
   @register
   class GoPanicParser:
       format: TraceFormat = "go"

       def parse(self, text: str) -> list[ParsedTrace]:
           return run_guarded(_parse, text)
   ```

   - `run_guarded` caps the text at `MAX_TRACE_TEXT` (1,000,000 characters) and turns
     `ValueError`, `IndexError` and `OverflowError` into an empty result, so the "never
     raises on malformed input" contract holds even when a parser slips;
   - `split_lines` gives every line with its exact offsets (it splits on `\n` only, so
     offsets map back to the source); `split_location` splits `path:line[:col]` from the
     right so drive letters survive; `parse_int` accepts at most 18 ASCII digits;
   - `make_frame(index=..., raw=..., function=..., path=..., line=..., module=...)`
     normalizes the path (`normalize_path`: backslashes, drive letters, `./`, `/./`,
     `/proc/self/cwd/`) and classifies runtime frames with `is_runtime_frame`; pass
     `is_runtime=` explicitly when the format has its own notion of runtime code, as the
     Go parser does for GOROOT paths. Native formats use `is_native_runtime_frame`, which
     also knows libc entry points and glibc internals;
   - be permissive: unknown lines are skipped, never fatal, and the parser returns every
     trace of its format in the text;
   - `register` raises on a duplicate `format`.

   Then import the module in `src/nikasha/extract/traces/__init__.py`, whose explicit
   import list is what registers the parsers. `parse_traces` runs every registered parser
   and, when two claim overlapping text, keeps the one covering more of it.

5. **Keep every pattern linear.** Module-level compiled patterns in this package are
   swept automatically by `tests/unit/extract/test_regex_linear.py`; use bounded or
   possessive quantifiers, as the existing parsers do.

### Adding a language

Parsing is tree-sitter through the per-language grammar wheels (SPEC §11.2, ADR 0002).
Ten languages ship today (C, C++, Python, JavaScript, TypeScript with TSX, Go, Rust, Java,
PHP, Ruby). Adding one touches these places, in order:

1. **The grammar wheel.** Add `tree-sitter-<lang>` to `dependencies` in `pyproject.toml`
   with a lower bound, run `uv lock`, and add it to the grammar row of the runtime table
   in `docs/adr/0002-dependencies.md` with the version you verified and its licence.
   Grammars must ship as wheels for Linux, macOS and Windows and work fully offline;
   `tree-sitter-language-pack` is rejected because it downloads parsers on first use (P3).
   The `tree-sitter` runtime is 0.26: use `Query(language, source)` and
   `QueryCursor(query).matches(node)`, index `node.start_point[0]`, and never use
   `progress_callback` (it segfaults; `code/parser.py` explains the workarounds).

2. **Detection** in `src/nikasha/code/languages.py`: a `Lang` member, its extensions in
   `EXTENSIONS`, and a marker in `_SHEBANGS` if the language has extension-less scripts.
   Add the cases to `tests/unit/code/test_languages.py`.

3. **The grammar binding** in `src/nikasha/code/parser.py`: import the wheel and add
   `Lang.X: tree_sitter_x.language` to `_GRAMMARS`. The query file name is derived from
   the enum value (`_QUERY_FILES`); TSX is the one exception, sharing `typescript.scm`.

4. **The query** `src/nikasha/code/queries/<lang>.scm`, following the capture conventions
   documented at the top of `c.scm`: `@def.<kind>[.<flag>]` on the definition node with
   `@name` (or `@declarator`) for its name, `@scope` for a qualifying scope, `@call` with
   `@fn` for calls resolved in Python, `@call.direct` / `@call.indirect` with `@callee`,
   `@ref` / `@ref.init` for address-taken candidates and `@proto` for prototypes.
   `python.scm` is three patterns long and a good starting point.

5. **Name qualification** in `src/nikasha/code/symbols.py`: add a `LangRules` entry to
   `RULES` (the separator, which definition kinds qualify what they contain, which ones
   make their functions methods, and whether generics are stripped). `RULES[lang]` is
   indexed directly, so a language without an entry fails at the first parse.

6. **Golden tests.** Add a small fixture written for this project, or one with a
   compatible licence, as `tests/fixtures/code/<lang>/sample.<ext>`, and
   `tests/unit/code/test_parser_<lang>.py` using the helpers in
   `tests/unit/code/code_helpers.py` (`parse_fixture`, `symbols`, `calls`, `flags`,
   `assert_clean`): assert the exact list of definitions with kinds, qualified names and
   line ranges, the call sites with their callers, and that the fixture parses with zero
   error nodes. In `tests/unit/code/test_parser_robustness.py`, the garbage-input test
   (empty, NUL bytes, invalid UTF-8, random bytes, a very long line, unterminated
   constructs) is parametrized over every `Lang`, and the grammar-and-query loading test
   loops over every `Lang` internally, so both cover the new language without changes;
   the pathological-tree cases there
   (megabytes of open brackets) name their languages explicitly, and a grammar whose error
   recovery behaves differently deserves a row of its own. `parse_file` must keep never
   raising: it caps file size at 2 MiB, parse time at 10 s through a read callback, and
   the width of error-recovery trees, and marks such files `parsed_ok=False` with a note.

7. **External API names.** Symbols on the lists in `src/nikasha/extract/external_apis.py`
   are marked external: checks treat them as NEUTRAL and they never support a refutation
   (SPEC §9.3). Add the language's standard library and platform names there, so a report
   that mentions them is not judged as if the project defined them.

### Adding a reproduction recipe

**The sandbox lands in M5, which has not started.** Today `src/nikasha/repro/sandbox.py`
only detects and probes container engines for `nikasha doctor`; there is no `recipes/`
directory, no `schema/recipe-v1.json`, no `docker/recipes/` and no `nikasha recipes`
command, and REPRODUCED cannot occur. Until M5 lands, please open an issue or a discussion
rather than a pull request for a recipe.

What is already decided, so a proposal can be written against it:

- SPEC §13.2 shows the intended recipe shape: `id`, `title`, `match` (products and a tag
  pattern), `image` (a Dockerfile and tag), `build` (env, steps, outputs, timeout), `run`
  (kinds such as `cli`, `file_input` and `c_harness`, env, timeout) and `limits`. It will
  be validated against `schema/recipe-v1.json` once M5 defines it. The recipes SPEC
  lists for v0.1.0 are vulnlab, curl and sqlite (MUST) and libxml2 (SHOULD).
- Builds run with `--network none`, so every toolchain dependency is baked into the image
  at image-build time (SPEC §13.3).
- Trees are materialised with `GitRepo.export_tree` (`ls-tree` plus `cat-file`), **never**
  with `git archive`, which runs a command from the repository's own config
  (ADR 0006). This overrides SPEC §13.3's wording.
- PoCs run only in the sandbox, only with an explicit opt-in, never on the host (P5), with
  the hardened flags of SPEC §13.4 and the per-engine corrections in
  `docs/research/2026-09-23-m0-verification.md` §6 (for example podman needs
  `--read-only-tmpfs=false`, and `--runtime` is a global podman flag but a `run` flag on
  docker).
- Recipe and sandbox tests will carry the `sandbox` marker; their intended home is a CI
  job on ubuntu (SPEC §13.6), which no workflow provides yet (see *Test markers* above).
  SPEC §13.6 lists the safety tests: no engine means refusal, no egress, a contained fork
  bomb, a read-only rootfs, uid 65534, and timeouts that leave no container behind.
