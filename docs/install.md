<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Install

Nikasha needs **Python 3.11 or newer** and **git**. You need a container engine (rootless
podman or docker) only to reproduce a proof of concept in the sandbox with `--repro`.

## From a checkout

Nikasha has not been released yet and is not on PyPI. Install it from a clone with
[uv](https://docs.astral.sh/uv/) or pipx:

```sh
git clone https://github.com/rakshit-737/nikasha
cd nikasha
uv tool install .      # or: pipx install .
```

To work on Nikasha itself, run `make setup`. It creates the environment with every
dependency group and installs the pre-commit hooks. Then run commands with
`uv run nikasha ...`.

## Check the environment

```sh
nikasha version
nikasha doctor
```

`doctor` reports the Python version, git, the cache directory and any container engine it
finds. It makes no network requests.

## Where things are stored

Clones and indexes live in the cache directory (`~/.cache/nikasha` on Linux), which is
created with mode `0700`. Nikasha sends nothing anywhere: it stays offline unless you pass
`--online`, and it has no telemetry.

## Optional extras

- A local model through Ollama, or a cloud model if you give explicit consent, for the
  optional advisory check. See [LLM](llm.md).
- The MCP server and the local web UI. See [MCP](mcp.md) and [Web UI](web-ui.md).
