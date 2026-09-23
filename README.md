<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Nikasha

**Proof, not prose.**

Nikasha (निकष, *touchstone*: the stone used to assay gold) checks the factual claims in a
vulnerability report against the real source code at the exact version the report names.
It builds an evidence dossier that anyone can re-run, and can optionally reproduce the
crash in a locked-down container.

> **Status: pre-alpha, under active construction.** Nothing here is ready to use yet.
> Development follows the milestones in [`PROGRESS.md`](PROGRESS.md), and every
> accuracy number will be published only after it has been measured.

## What it will do

Given a report (Markdown, text, HTML, email, a HackerOne report or a CVE record) and the
project's git repository, Nikasha:

- resolves the version the report names to a tag or commit;
- checks whether the cited files, functions, line numbers, quoted code, options and
  commits exist *at that version*, and in which releases they do exist;
- checks stack traces for internal consistency (sanitizer arithmetic, frame order) and
  against the project's call graph;
- tests whether a proposed patch applies, or has already been applied;
- optionally rebuilds the project with sanitizers and runs the proof of concept inside a
  network-less, rootless container;
- fuses all of that into a verdict with the evidence behind it (**REPRODUCED**,
  **GROUNDED**, **MIXED**, **UNGROUNDED** or **INSUFFICIENT**), and drafts neutral,
  specific questions for the reporter.

It never judges *how* a report was written. There is no "AI detection". It checks claims
against code.

## Honest context

A static "does this function exist?" check alone is not enough. The
[slopcheck](https://github.com/GaganGanesh98/SlopCheck) project measured it on 557
publicly disclosed curl reports and published a careful negative result: checked against
a single ref, static contradictions did not separate genuine reports from fabricated
ones. Nikasha treats that result as the baseline to beat. It pins each report to the
version it names, separates project claims from the reporter's own PoC code and from
third-party APIs, handles negated statements, adds structural trace, call-graph and patch
checks, and adds sandboxed reproduction. Our own benchmark numbers will be published
next to slopcheck's, whatever they turn out to be.

## Principles

1. Evidence, not AI detection.
2. A deterministic core: the same inputs produce byte-identical results, with no LLM needed.
3. Confidential by default: offline unless you pass `--online`, and no telemetry.
4. Conservative about "fabricated": when in doubt, say MIXED or INSUFFICIENT and ask.
5. Proofs of concept run only in a hardened sandbox, never on the host.
6. Every verdict is explainable down to a file, a line and a command.
7. Report text and repositories are treated as hostile input.
8. Useful to honest reporters too (`nikasha lint`).

## License

Code is licensed under [Apache-2.0](LICENSE); documentation under
[CC-BY-4.0](LICENSES/CC-BY-4.0.txt). See [`REUSE.toml`](REUSE.toml) for per-file details.
