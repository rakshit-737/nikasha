<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# The MCP server (`nikasha mcp`)

`nikasha mcp` exposes Nikasha's checks to an MCP client over standard input and output
(SPEC §16.3). A client such as Claude Code or Claude Desktop starts the server as a child
process and calls its tools; nothing listens on a network port, and nothing leaves the
machine unless you start the server with `--online`.

The tools answer with evidence about the **claims** in a report, checked against the
source code at the exact version the report names. They never describe the person who
wrote the report (principle P1), and the same input always produces the same result (P2).

## Install

The server needs the `[mcp]` extra (the official `mcp` package, 2.x):

```bash
uv sync --extra mcp            # inside a checkout
pip install "nikasha[mcp]"     # or, as a tool
```

Without the extra, `nikasha mcp` exits with `install nikasha[mcp]`; every other command
keeps working.

## Run

```bash
nikasha mcp             # offline: local repositories and the clone cache only (default)
nikasha mcp --online    # allow git clone and fetch for https:// repositories
```

`--online` is the only network switch. A tool call cannot turn an offline server online:
`check_report(online=true)` on a server started without `--online` is refused with a
message that says how to start it. Cached clones live under `~/.cache/nikasha/repos`
(owner-only permissions); warm the cache once with
`nikasha index --repo https://github.com/OWNER/REPO --online` and the server can then work
offline for that repository.

The `reproduce` tool is registered only when the environment variable
`NIKASHA_MCP_ALLOW_REPRO=1` is set when the server starts. In this build it answers
`not available in this build` and runs nothing: sandbox reproduction arrives with
milestone M5, and even then a proof of concept only ever runs inside the hardened
container (P5), never on the host.

## Claude Code

Register the server once with the `claude` CLI. From a checkout, let `uv` provide the
environment:

```bash
claude mcp add nikasha -- uv run --directory /path/to/nikasha --extra mcp nikasha mcp
```

If Nikasha is installed on your `PATH` (for example with `pipx install "nikasha[mcp]"`):

```bash
claude mcp add nikasha -- nikasha mcp
```

Add `--online` after `mcp` to allow network access, and use the CLI's environment option
(`-e NAME=value` at the time of writing) to set `NIKASHA_MCP_ALLOW_REPRO=1` if you want the
`reproduce` tool listed. `claude mcp list` shows the registered servers and
`claude mcp remove nikasha` removes this one.

The `claude mcp add` syntax, its scope flags (`--scope user|project|local`) and its option
names change between releases: check `claude mcp add --help` and the current Claude Code
documentation before copying the commands above.

## Claude Desktop

Claude Desktop reads its servers from `claude_desktop_config.json`:

| Platform | Location (at the time of writing) |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Add a `nikasha` entry under `mcpServers`. Desktop apps start the command with a minimal
environment, so use an absolute path to `uv` (or to the `nikasha` executable):

```json
{
  "mcpServers": {
    "nikasha": {
      "command": "/absolute/path/to/uv",
      "args": ["run", "--directory", "/path/to/nikasha", "--extra", "mcp", "nikasha", "mcp"]
    }
  }
}
```

To allow network access append `"--online"` to `args`; to list the `reproduce` tool add
`"env": {"NIKASHA_MCP_ALLOW_REPRO": "1"}` to the entry. Restart Claude Desktop after
editing the file; the server appears in the tools menu of a new conversation.

The file location and the exact schema are Anthropic's to change: confirm both in the
current Claude Desktop documentation (Settings, Developer) before editing.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `check_report` | `report_text`, `repo`, `version?`, `online=false` | The verdict (REPRODUCED, GROUNDED, MIXED, UNGROUNDED or INSUFFICIENT) with its score and confidence, the resolved target, the claims found, one line per evidence item, questions for the reporter, and a `result_id` |
| `check_trace` | `trace_text`, `repo`, `version` | For every application frame: file exists, line in bounds, line inside the named function; for every consecutive pair of frames: whether the call edge exists in the call graph; a consistency ratio |
| `symbol_timeline` | `repo`, `symbol` | The releases that define the symbol (as ranges and release by release), whether the name ever appeared in git history, and "did you mean" names when nothing defines it |
| `explain` | `result_id` | Everything behind an earlier `check_report`: the log-odds ledger (every strength, weight and contribution), every claim, every evidence item with its code locations and the commands that produced it |
| `reproduce` | `repo`, `version`, `poc_text?` | Only with `NIKASHA_MCP_ALLOW_REPRO=1`; answers `not available in this build` |

Every tool returns a JSON object whose first field, `summary`, is one line a client can
show as is, for example:

```text
GROUNDED (100/100, confidence high) at v1.2.0: 15 claims, 20 supported, 0 refuted, 1 question for the reporter.
1 trace at v1.2.0 (f8fdd434bbc5): 4 of 4 checkable frames consistent; 3 of 3 call edges found in the call graph.
util_copy_value is defined in v1.1.0 to v1.3.0 (4 of 5 releases).
```

`report_text` accepts Markdown, plain text or HTML; the format is detected from the
content, exactly as for `nikasha check -`. `repo` is a local path (a checkout, a `.git`
directory or a bare repository) or an `https://` URL. `version` is a release such as
`8.5.0` or a tag such as `curl-8_5_0`; when it is omitted, `check_report` uses the version
the report names, and a report that names none gets an INSUFFICIENT verdict with a
question rather than an error.

`check_trace` and `symbol_timeline` follow the server's `--online` flag. `check_report`
takes its own `online` argument, honoured only when the server allows the network.

Results are kept **in memory only**, keyed by a content ID (the SHA-256 of the result's
own JSON, without timings, cut to 12 hex digits), so `explain` works for the last 32
results of the session and nothing pasted into a client is written to disk beyond a
private temporary file that lives only for the duration of one check. Restarting the
server forgets every result.

## Hardening

Every argument an MCP client sends is treated as hostile (P7), with the same rules the CLI
applies to text taken from a report:

- `repo` must be a local path or an `https://` URL. `http://`, `ssh://`, `file://`,
  `git@host:` and `ext::` forms are refused before anything looks at them, URL path
  components are validated, and option-looking values are rejected.
- `version` and `symbol` go through the same validation as every revision taken from a
  report (`nikasha.code.gitio.safe_rev`): no leading `-`, no control characters, at most
  256 characters. Git only ever sees them after `--end-of-options`.
- `report_text`, `trace_text` and `poc_text` are capped like CLI input (20 MiB before
  decoding, 2,000,000 characters after normalization).
- A `result_id` must be exactly the 12 hex digits a check tool returned.
- Expected failures (a repository that is not cached, a version that matches no tag, a
  refused argument) come back as tool errors with an actionable message, not as protocol
  errors or tracebacks.
- Git runs only through Nikasha's hardened wrapper (plumbing only, hooks and external
  drivers disabled), and no container engine is ever invoked by this server.

## Troubleshooting

- **`install nikasha[mcp]`**: the extra is missing from the environment the client
  starts; with `uv`, pass `--extra mcp` to `uv run` as shown above.
- **`... is not in the cache. Nikasha works offline by default`**: warm the clone cache
  once with `nikasha index --repo URL --online`, or start the server with `--online`.
- **The client shows no tools**: run `nikasha mcp` by hand in a terminal; it should wait
  silently on standard input (press Ctrl-C to stop). If it prints an error instead, that
  error is what the client hit. Standard output belongs to the protocol, so the server
  never prints anything of its own there.
- **Slow first call on a large repository**: the first check indexes the tree at the
  requested commit; later calls reuse the per-blob index under `~/.cache/nikasha/index`.
