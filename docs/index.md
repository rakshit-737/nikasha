<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Nikasha

**Proof, not prose.** Nikasha checks the factual claims in a vulnerability report against
the source code at the exact version the report names. It returns a verdict backed by
evidence and a set of neutral questions for the reporter.

Nikasha reads the report and extracts what it claims: files, symbols, line numbers, quoted
code, stack traces, patches, versions and references. It then pins the claimed version to
a tag or commit and checks each claim against the repository's history, using git plumbing
and tree-sitter. Every finding carries the repository, commit, path, lines, and the command
that produced it.

| Verdict | Meaning |
|---|---|
| **REPRODUCED** | The proof of concept crashed as claimed inside the hardened sandbox. |
| **GROUNDED** | The claims match the code, and nothing substantially refutes them. |
| **MIXED** | There is evidence on both sides, or the claims fit a different version. |
| **UNGROUNDED** | Core claims never existed in the project's history, and independent evidence agrees. |
| **INSUFFICIENT** | There is too little to check. |

!!! note "Not an AI detector"
    Nikasha judges claims. It never judges people or writing style. A GROUNDED verdict
    does not mean a report is valid, and an UNGROUNDED verdict comes with questions, not
    accusations. See [Concepts](concepts.md).

## Where to go next

- [Install](install.md) the command-line tool.
- Run the offline demo in the [Quickstart](quickstart.md).
- See how claims become a verdict in [Concepts](concepts.md).
- Look up any check in the [Checks reference](checks.md).
- Configure a project with [`nikasha.toml`](configuration.md).
- Run it in CI with the [GitHub Action](action.md), from an assistant through the
  [MCP server](mcp.md), or in a browser with the [local web UI](web-ui.md).
- Read what it defends against in the [Threat model](THREAT_MODEL.md).
