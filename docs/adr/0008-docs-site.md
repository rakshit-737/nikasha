<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0008: Zensical builds the documentation site

- **Status:** accepted
- **Date:** 2026-09-24

## Context

SPEC §21.6 asks for a documentation site with search, dark mode, code copy buttons and
mermaid diagrams, built by a generator chosen in an ADR. It names two candidates: Material
for MkDocs, reported to be in maintenance mode, and Zensical, its announced successor from
the same team. Both were checked on 2026-09-24 on this machine (Windows 11, uv 0.12).

## What was verified

| Question | Material for MkDocs | Zensical |
|---|---|---|
| Latest release on PyPI | `mkdocs-material` 9.7.7, uploaded 2026-07-17 | `zensical` 0.0.64, uploaded 2026-09-22 |
| Underlying engine | MkDocs 1.6.1, whose last release was 2024-08-30; the only newer MkDocs is `2.0.dev6`, a development line | its own (Rust core, Python front end); reads `zensical.toml` and also `mkdocs.yml` |
| Installs and runs with `uvx` | yes: `uvx --with mkdocs-material mkdocs --version` printed `mkdocs, version 1.6.1` | yes: `uvx zensical --version` printed `0.0.64` |
| Licence (PyPI classifier) | MIT | MIT |
| Search, dark mode, code copy, mermaid | yes (theme features, `pymdownx.superfences` custom fence) | yes: `zensical new` scaffolds `content.code.copy`, a light/dark/system palette, search and a `mermaid` custom fence |
| Development status | maintenance | `Development Status :: 3 - Alpha` |

## Verification

On 2026-09-24, `uvx zensical==0.0.64 build` built the site with one warning:
`docs/adr/0000-rename.md` linked `../../SPEC.md`, which is outside `docs/`, and
`uvx zensical==0.0.64 build --strict` aborted on it (`RuntimeError: Aborted because
--strict flag is set`). On 2026-09-25 that link was changed to point at `SPEC.md` on
GitHub, and `uvx zensical==0.0.64 build --strict` then finished with exit code 0 and
"No issues found" (Linux, uv 0.12). The docs workflow builds with `--strict`, so a broken
link fails CI.

## Decision

**Use Zensical, configured by `zensical.toml` at the repository root.**

Material for MkDocs rests on an MkDocs 1.x line that has not released in two years, while
the maintained line is still a development series, so choosing it now means planning a
migration on day one. Zensical is maintained by the same team, keeps the Material look and
Markdown extensions (the docs already use plain CommonMark plus admonitions and mermaid),
and can read an `mkdocs.yml` if a fallback is ever needed. Its alpha status is the cost:
the pinned version is recorded below and bumped deliberately.

## Consequences

- A new dev dependency, `zensical` (pinned `==0.0.64`), belongs in the `docs` dependency
  group of `pyproject.toml` with a row in ADR 0002. Until then the site builds with
  `uvx zensical==0.0.64 build`.
- `make docs` should run `uv run zensical build --strict` (the Makefile target is still a
  stub; wiring it is a separate change).
- `.github/workflows/docs.yml` builds the site strictly on every push and pull request, and deploys it from `main` with
  `actions/upload-pages-artifact` and `actions/deploy-pages`. Deployment stays inert until
  the maintainer enables Pages (`gh api -X POST repos/{owner}/{repo}/pages -f
  build_type=workflow`), and sets the repository variable `PAGES_ENABLED=true`; the deploy job is skipped
  until then. Both are repository-setting changes that need their approval.
- If Zensical breaks the build in a way a pin cannot fix, the fallback is Material for
  MkDocs with an equivalent `mkdocs.yml`; that switch needs a new ADR.
