<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing to Nikasha

Thanks for helping. Nikasha's credibility rests on being **correct, deterministic and
conservative**, so the bar for tests is high. The good news is that the process is
mechanical.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Python ≥ 3.11, [uv](https://docs.astral.sh/uv/), git and `make`. The sandbox
tests also need podman or docker.

```bash
git clone https://github.com/rakshit-737/nikasha && cd nikasha
make setup          # uv sync + pre-commit hooks
make lint type test # the gates every PR must pass
```

| Target | What it does |
|---|---|
| `make setup` | Create the environment (`uv sync`) and install the pre-commit hooks |
| `make lint` | `ruff check`, `ruff format --check`, codespell, `reuse lint`, the placeholder check |
| `make fmt` | Auto-format and auto-fix |
| `make type` | `mypy --strict` on `src/` |
| `make test` | Fast tests (`not sandbox and not network and not slow`) with coverage |
| `make test-all` | Every test, including the sandbox, network and slow suites |

The other targets (`bench`, `docs`, `screenshots`, `demo`, `release-check`) become
available in the milestones listed in [`PROGRESS.md`](PROGRESS.md).

## Standards

- **Typing:** `mypy --strict` is clean on `src/`. No `Any` without a comment explaining
  why.
- **Style:** `ruff format` and `ruff check`. Keep functions small and algorithms simple
  and explainable; document complexity in docstrings.
- **Determinism:** the same inputs must give byte-identical JSON, timings excepted.
  - Sort every collection you output.
  - Derive IDs from content (`sha256(kind + canonical fields)[:12]`).
  - Checks must never read the wall clock or depend on the environment.
- **Process boundary:** git runs only through `nikasha.code.gitio`, container engines
  only through `nikasha.repro.sandbox`, and network access only in `--online` mode
  through the single network module. A test enforces this.
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
  that you have the right to submit the change under the project's licence. A CI check
  enforces it on pull requests.
- Keep pull requests focused. Add tests first for parsers and checks. Update
  `CHANGELOG.md` under *Unreleased*. If you changed the terminal or HTML output,
  regenerate the screenshots with `make screenshots`; never hand-edit them.
- **Never commit** secrets, personal data, embargoed report text, or third-party report
  text whose licence isn't clear. Benchmark manifests hold IDs and labels only.

## Step-by-step guides

The package layout is described in [`CLAUDE.md`](CLAUDE.md) and [`SPEC.md`](SPEC.md) §6.

### Adding a check

1. Pick the next free ID and a group (SPEC §12). Write down in the PR description every
   outcome and its strength as a natural-log likelihood ratio.
2. Write the tests first in `tests/unit/checks/test_cNN_<name>.py`. Cover **every**
   outcome, including NEUTRAL for claims the check must not judge: claims that are
   negated, belong to a third party, are the reporter's own artefacts, or point at
   generated files.
3. Implement `src/nikasha/checks/cNN_<name>.py`. It must be deterministic, time-bounded
   and registered.
4. Refutations must cite a code location at the exact ref, with its permalink and the
   command record.
5. Add a question template for each refuting outcome (neutral tone; see SPEC Appendix D).
6. Regenerate `docs/checks.md` (`scripts/gen_checks_doc.py`) and add an ADR if the check
   changes verdict behaviour.
7. Run the benchmark. A new check must not raise the false-UNGROUNDED rate on genuine
   reports.

### Adding a trace format

1. Collect at least **three real** traces, produced by actually running the tool, and
   record how each was produced in `tests/fixtures/traces/<format>/README.md`.
2. Write parser tests: frames, runtime-frame marking, path normalization, and the
   metadata fields.
3. Implement `src/nikasha/extract/traces/<format>.py` using the shared `Frame`
   normalizer. Be permissive: unknown lines are skipped, never fatal.
4. Add a hypothesis test proving the parser never crashes and stays linear-time on
   adversarial input.

### Adding a reproduction recipe

1. Add `recipes/<id>.yaml` and validate it with `nikasha recipes validate`.
2. Add a toolchain `docker/recipes/<name>.Dockerfile` if needed. Every build dependency
   is baked in at image-build time, because builds run with `--network none`.
3. Pin the tag window the recipe is known to build, and test at least one real,
   public, already-fixed bug that reproduces (`-m sandbox`).

### Adding a language

1. Add the tree-sitter grammar wheel as a dependency and justify it in
   `docs/adr/0002-dependencies.md`. Grammars that download at runtime are not
   acceptable: Nikasha must work offline.
2. Add `src/nikasha/code/queries/<lang>.scm` for definitions and calls, plus extension
   and shebang detection.
3. Add golden parsing tests from a small real-world file with a compatible licence, and
   external-API lists so standard-library names are treated as NEUTRAL.
