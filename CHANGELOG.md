<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- M3 checks, fusion and CLI outputs:
  - `nikasha check`: a report in, an evidence-backed verdict out (REPRODUCED / GROUNDED /
    MIXED / UNGROUNDED / INSUFFICIENT), entirely offline. Exit codes 0/10/20/30 let CI
    gate on the outcome, and `--fail-on` changes where that line sits.
  - Nineteen checks (C01–C18 and C21) covering versions, files, symbols, lines, quoted
    code, snippets, stack traces, call edges, sanitizer self-consistency, patches, fix
    status, options, references, version ranges, CVSS and API usage. Each one is
    deterministic, time-bounded and auto-registered.
  - A refutation gate enforced by the framework rather than by each check: only claims the
    reporter attributed to the project, and did not negate, can ever be contradicted
    (ADR 0003). A withheld refutation is still shown, with the strength it would have had.
  - Evidence fusion with per-group damping, so ten correlated findings cannot outweigh a
    few independent ones, and the SPEC §14.3 verdict ladder on top of it.
  - Neutral questions for the reporter, from templates keyed by check and outcome, capped
    at six and ordered by how much they would change the verdict.
  - `nikasha explain`: the log-odds ledger behind a verdict — every strength, damping
    weight, contribution and running total, and the rule that fired.
  - Terminal, Markdown and JSON output. The Markdown reply stays under GitHub's comment
    limit and escapes everything that came from the report or from repository code.
  - `docs/checks.md`, generated from the registry by `scripts/gen_checks_doc.py`.

### Fixed

- **A ReDoS in report intake.** The Java stack-frame pattern used `\s+` under
  `re.MULTILINE`, so the newline class and the per-line `^` anchor combined into a
  quadratic scan of any report body: 16k newlines took 0.43 s, and the cost grew with the
  square of the input. The indent is now bounded horizontal whitespace (0.0003 s for the
  same input). Reachable from untrusted input, so it is a security fix (P7).
- An ANSI escape carried in a resolved target (its `method` quotes the report text it
  resolved from) reached the terminal verbatim; target fields are now stripped of
  non-printable characters like every other input-derived string.
- `--ascii` now really produces ASCII: the separator, the ellipsis and the panel borders
  fell back only for the status marks before.
- A report naming no resolvable version is INSUFFICIENT with a question, rather than an
  error.

- M2 resolution and code intelligence:
  - Target resolution: which repository and exact commit a report is about, from
    `--repo`/`--ref`/`--version`, permalinks, product names and claimed versions. It never
    guesses silently; ambiguity is recorded as alternatives and warnings.
  - Release tags: a tag parser and release list, tested against real tag lists from nine
    projects, that keeps variant lines (tiny-curl, OpenSSL-fips) apart from the main line.
  - Repository cache: full bare clones of `https://` repositories, fetched only with
    `--online` (ADR 0006).
  - Parsing for C, C++, Python, JavaScript, TypeScript/TSX, Go, Rust, Java, PHP and Ruby
    with tree-sitter: definitions, qualified names, call sites, macros and
    address-taken functions. Hostile input never crashes or hangs the parser. In C and C++,
    attribute macros between a function's type and its name (`static void
    LIBXML_ATTR_FORMAT(3,0) f(...)`) no longer hide the function.
  - A code index in SQLite keyed by blob, so unchanged files are parsed once across
    releases.
  - Symbol timelines across releases (lazy and full strategies, ADR 0004), with a
    time-bounded history search that marks the result incomplete rather than claiming a
    symbol never existed. A release where the name appears only in files that did not
    parse cleanly is marked uncertain, not absent.
  - Literal search: capped, fixed-string `git grep` with the exact command recorded as
    evidence.
  - A name-based call graph (direct, via macro, inlined, possibly indirect, none) and trace
    forensics: does each frame's file, line and function fit the code at a given commit?
  - Generated and release-only files (for example SQLite's `sqlite3.c`, or `parse.c` built
    from `parse.y`) are recognised and never judged, including when a trace cites them
    under an absolute build path.
  - `nikasha index`, `nikasha timeline` (with "did you mean" suggestions) and
    `nikasha trace`.

- M1 models, intake and extraction:
  - Frozen pydantic data models for reports, claims (12 kinds), evidence, verdicts and
    results, with content-derived IDs and deterministic JSON; `schema/result-v1.json` is
    generated from them and checked for drift.
  - Text, Markdown and HTML intake with an exact offset map back to the original input;
    safe attachment storage and opt-in archive extraction.
  - Deterministic claim extraction for versions, symbols, files and lines (including blob
    permalinks), snippets, patches, PoCs, references, options, impact and behaviour.
  - Claim scoping (provenance), negation detection and strict line binding, which address
    the failure modes slopcheck measured (ADR 0003).
  - Trace parsers for ASan, UBSan, valgrind, gdb, Python, Java, Go, Rust and Node, tested
    against real captured output (ADR 0005). LSan, MSan and TSan are not yet supported.
  - `nikasha extract`: a highlighted claim view, with `--json`.
  - vulnlab: a deterministic, fictional C library with a real heap overflow, and five fixture
    reports (genuine, fabricated, wrong version, already fixed, vague).
  - Every extraction regex is tested for linear time on hostile input.

- M0 bootstrap:
  - project scaffold (uv, hatchling, `src/` layout);
  - the `nikasha version` and `nikasha doctor` commands;
  - a hardened git wrapper and container-engine detection;
  - a process-boundary test;
  - licensing: Apache-2.0 for code, CC-BY-4.0 for docs, REUSE 3.3;
  - community files, CI, CodeQL, dependency review and OpenSSF Scorecard workflows;
  - ADRs 0000–0003 and the M0 verification report.

### Security

- The git layer now rejects argument injection through revisions from report text, never
  uses a worktree, refuses `ext::` and `git://` transports, and disables lazy fetching
  offline. A canary test wires 20 execution hooks into a repository and checks that no
  Nikasha code path triggers any of them.
- `git archive` is no longer used: a repository's own config can make it run a command
  (`tar.<format>.command`). Trees are materialised with `ls-tree` and `cat-file` instead.
