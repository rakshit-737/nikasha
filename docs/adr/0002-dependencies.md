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

## Planned (added in the milestone named; versions re-checked then)

| Package | Milestone | Why / decision |
|---|---|---|
| `tree-sitter` ≥ 0.26 | M2 | Parsing. **`Language.query()` has been removed.** Use `Query(language, source)` with `QueryCursor(query).captures(node)`, which returns `dict[str, list[Node]]`, and `.matches(node)`. `Language.name` is `None` for ABI-14 grammars, so we key languages by our own enum. |
| `tree-sitter-{c,cpp,python,javascript,typescript,go,rust,java,php,ruby}` | M2 | Per-language grammar wheels (abi3, all platforms). **We do not use `tree-sitter-language-pack` ≥ 1.0**: its docs say it "downloads each parser on first use", which breaks offline operation (P3). TypeScript exposes `language_typescript()` and `language_tsx()`; PHP exposes `language_php()` and `language_php_only()`. Note that the cpp, typescript, java and ruby grammars have had no release since 2024. |
| `markdown-it-py` ≥ 4 | M1 | Code fences with line maps; the token `.map` is `[start, end)`, counted from 0 |
| `unidiff` ≥ 1.0 | M1 | Parsing patches |
| `rapidfuzz` | M2 | Edit-distance primitives. The BK-tree is our own code. rapidfuzz needs Python ≥3.11, which sets our floor. |
| `pygments` | M4 | Pre-rendered highlighting in the HTML report (output escaped) |
| `jinja2` | M3 | Templates with autoescape on |
| `cvss` ≥ 3.6 | M3 | CVSS v3 and v4 (`CVSS3`, `CVSS4`). The spec's example vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` computes to 7.5, confirmed. |

### Deviation from SPEC §5: no `httpx`

`httpx` has had no release since 0.28.1 (2024-12-06). Pydantic now maintains a successor,
`httpx2`, and the MCP SDK 2.x depends on `httpx2`. Online mode only needs a handful of
GET and POST requests with JSON, so Nikasha uses **stdlib `urllib.request`** behind a single
network module. That module enforces timeouts, response-size caps, `https`-only URLs and
logs every URL into `result.environment.fetched_urls`. This removes a dependency and
avoids shipping both `httpx` and `httpx2`.

## Optional extras (planned)

| Extra | Contents | Notes |
|---|---|---|
| `[mcp]` | `mcp` ≥ 2.2, < 3 | **The SDK is now 2.x, and FastMCP was renamed:** `from mcp.server import MCPServer`, then `MCPServer("nikasha")`, `@server.tool()`, `server.run()` (stdio by default). The standalone `fastmcp` package is not used. |
| `[web]` | `fastapi`, `uvicorn` | Local web UI (M7) |
| `[llm]` | `anthropic`, `openai`; Ollama over plain HTTP | Off by default; no hard-coded model IDs |
| `[bench]` | `numpy`, `scikit-learn`, `matplotlib` | Calibration and charts only; the core never imports them |

## Development tools

`pytest`, `pytest-cov`, `hypothesis`, `mypy` (2.x), `ruff`, `packaging`, `pre-commit` and
`codespell` are in the `dev` dependency group. **`reuse`** (6.2.0, which implements REUSE
3.3 and `REUSE.toml`) is run through `uvx` rather than installed into the project
environment, because it publishes a single cp310 wheel. `playwright`, `pip-licenses` and
`cyclonedx-bom` arrive with the milestones that use them (M4 and M8).
