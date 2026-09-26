<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Nikasha

**Proof, not prose.** Nikasha shows which claims in a vulnerability report the source code
supports, at the exact version the report names, with the evidence for each one. With
`--repro` it can also reproduce the claimed crash in a hardened sandbox. Claims the code does
not support become neutral questions for the reporter.

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

## Real-world results (M3.5)

On 175 labelled curl reports (126 confirmed genuine, 49 from curl's AI-slop list), each
checked at the version it names:

- 0 of 126 genuine reports were called UNGROUNDED (Wilson 95% upper bound 2.96%, so the
  ≤1% target is not yet shown).
- Refutations did **not** separate slop from genuine reports (at least one REFUTES on
  20.6% of genuine and 20.4% of slop reports).
- Support carried the only signal: GROUNDED on 25% of genuine against 10% of slop. The best
  after-the-fact threshold on the score reaches Youden J 0.249 against 0.103 for a random
  score, which is optimistic.

That is why Nikasha leads with grounding and reproduction, and treats refutations as
questions rather than as a fabrication detector
([ADR 0012](adr/0012-reposition-after-m35.md)). One project, one corpus, no calibration yet.

## Where to go next

- [Install](install.md) the command-line tool.
- Run the offline demo in the [Quickstart](quickstart.md).
- See how claims become a verdict in [Concepts](concepts.md).
- Look up any check in the [Checks reference](checks.md).
- Configure a project with [`nikasha.toml`](configuration.md).
- Run it in CI with the [GitHub Action](action.md), from an assistant through the
  [MCP server](mcp.md), or in a browser with the [local web UI](web-ui.md).
- Read what it defends against in the [Threat model](THREAT_MODEL.md).
