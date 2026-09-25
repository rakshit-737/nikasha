<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0002: Dependencies

- **Status:** accepted (living document: every added dependency gets a row here)
- **Date:** 2026-09-23

## Policy

- Keep the runtime dependency list small, and add each dependency in the milestone that
  first uses it.
- Every runtime dependency must work **fully offline** (P3), ship wheels for Linux, macOS
  and Windows on CPython 3.11–3.14, and have a permissive licence compatible with
  Apache-2.0.
- `uv.lock` pins exact versions. `pyproject.toml` states lower bounds.

## Runtime dependencies

| Package | Since | Why | Verified (2026-09-23) |
|---|---|---|---|
| `typer` | M0 | CLI with `--help` everywhere | 0.27.2, Python ≥3.10 |
| `rich` | M0 | Terminal UI; `Console(record=True).save_svg()` for README screenshots | 15.0.0; `save_svg(path, *, title, theme, …)`; light themes `DEFAULT_TERMINAL_THEME` and `NIGHT_OWLISH`; the exported SVG references the Fira Code font from cdnjs (it falls back to monospace when that is blocked) |
| `pydantic` | M0 | Frozen data models and JSON Schema generation | 2.13.5; `ConfigDict(frozen=True, extra="forbid")` makes `model_json_schema()` emit `additionalProperties: false` |
| `platformdirs` | M0 | Cache and config locations | 4.11.x |
| `markdown-it-py` | M1 | Code fences with line maps; the token `.map` is `[start, end)`, counted from 0 | 4.2.0, MIT |
| `unidiff` | M1 | Parsing patches | 1.0.1, MIT |
| `tree-sitter` | M2 | Parsing (SPEC §11.2). **`Language.query()` has been removed.** We use `Query(language, source)` with `QueryCursor(query).matches(node)`. `Language.name` is `None` for ABI-14 grammars, so languages are keyed by our own enum. **Two bugs in 0.26.0, both reproduced on this machine:** `progress_callback` segfaults on first use (exit 139 with `Parser.parse` and a read callback), so the parse time budget is enforced by a read callback that stops supplying input; and chained `node.start_point.row` returned wrong values in one of two identical runs, so the code only ever indexes `start_point[0]`. | 0.26.0, MIT |
| `tree-sitter-{c,cpp,python,javascript,typescript,go,rust,java,php,ruby}` | M2 | Per-language grammar wheels (abi3, all platforms). **We do not use `tree-sitter-language-pack` ≥ 1.0**: its docs say it "downloads each parser on first use", which breaks offline operation (P3). TypeScript exposes `language_typescript()` and `language_tsx()`; PHP exposes `language_php()` and `language_php_only()` (we use `language_php`, which handles `<?php` tags). The cpp, typescript, java and ruby grammars have had no release since 2024. | c 0.24.2, cpp 0.23.4, python 0.25.0, javascript 0.25.0, typescript 0.23.2, go 0.25.0, rust 0.24.2, java 0.23.5, php 0.24.1, ruby 0.23.1; all MIT |
| `rapidfuzz` | M2 | Levenshtein distance for the "did you mean" BK-tree (the tree itself is our own code). rapidfuzz needs Python ≥3.11, which sets our floor. | 3.14.6, MIT |
| `pyyaml` | M2 | Reads the packaged `known_projects.yaml`, with `yaml.safe_load` only; YAML errors become `NikashaError`. | 6.0.3, MIT; `types-pyyaml` in the dev group for mypy |
| `jinja2` | M3 | The reporter-question templates (`fuse/questions/*.j2`, SPEC §14.4). Loaded with `StrictUndefined` so a template referencing a detail a check does not record fails in tests instead of silently rendering "None". `autoescape` is **off** here because questions are plain text; the HTML report (M4) will use a separate autoescaping environment. | 3.1.6, BSD-3-Clause |

## Planned (added in the milestone named; versions re-checked then)

| Package | Milestone | Why / decision |
|---|---|---|
| `pygments` | M4 | Pre-rendered highlighting in the HTML report (output escaped) |
| ~~`cvss` ≥ 3.6~~ | ~~M3~~ | **Not adopted (M3).** C17 needs one base-score formula on a string we have already parsed, so the dependency buys little and costs a supply-chain surface on the path that reads attacker-controlled report text (P7). `checks/c17_impact_consistency.py` implements the CVSS v3.1 §7.1 base formula (v3.0 shares it), including the `roundup` procedure and the changed-scope weights, and is tested against 11 published vectors (Heartbleed 7.5, Log4Shell 10.0, reflected XSS 6.1, and the spec's own 7.5 example). **v4.0 is deliberately not scored** — its macrovector lookup cannot be written by hand with confidence, so a v4.0 vector is NEUTRAL, never reported as a malformed vector (P4). Revisit if v4.0 scoring becomes a requirement. |

### Deviation from SPEC §5: no `httpx`

`httpx` has had no release since 0.28.1 (2024-12-06). Pydantic now maintains a successor,
`httpx2`, and the MCP SDK 2.x depends on `httpx2`. Online mode only needs a handful of
GET and POST requests with JSON, so Nikasha uses **stdlib `urllib.request`** behind a single
network module. That module enforces timeouts, response-size caps, `https`-only URLs and
logs every URL into `result.environment.fetched_urls`. This removes a dependency and
avoids shipping both `httpx` and `httpx2`.

## Optional extras

`pyproject.toml` has carried empty `[project.optional-dependencies]` stubs since M0. They
were filled with `uv add --optional` in M7. The M4 commit message that claims to add them
is wrong: a hand edit guarded on the section *existing* found the empty stub, skipped,
and the lock never learned about the extras until M7.

| Extra | Contents | Notes |
|---|---|---|
| `[mcp]` | `mcp` ≥ 2.2, < 3 (**added M7**: mcp 2.2.0, MIT) | **The SDK is now 2.x, and FastMCP was renamed:** `from mcp.server import MCPServer`, then `MCPServer("nikasha")`, `@server.tool()`, `server.run()` (stdio by default). The standalone `fastmcp` package is not used. |
| `[web]` | `fastapi`, `uvicorn`, `python-multipart` (**added M7**: fastapi 0.141.1, uvicorn 0.53.0, python-multipart 0.0.32; all MIT/BSD) | Local web UI (M7) |
| `[llm]` | `anthropic`, `openai`; Ollama over plain HTTP (**added M7**: anthropic 1.8.0, openai 3.19.2; MIT and Apache-2.0) | Off by default; no hard-coded model IDs |
| `[bench]` | `numpy`, `scikit-learn`, `matplotlib` (**added M6**: numpy 2.5.3, scikit-learn 1.9.1, matplotlib 3.11.2; BSD-3-Clause, BSD-3-Clause, matplotlib licence (PSF-style)) | Calibration and charts only; the core never imports them |

## Development tools

`pytest`, `pytest-cov`, `hypothesis`, `mypy` (2.x), `ruff`, `packaging`, `pre-commit` and
`codespell` are in the `dev` dependency group. **`reuse`** (6.2.0, which implements REUSE
3.3 and `REUSE.toml`) is run through `uvx` rather than installed into the project
environment, because it publishes a single cp310 wheel. `playwright`, `pip-licenses` and
`cyclonedx-bom` arrive with the milestones that use them (M4 and M8).
