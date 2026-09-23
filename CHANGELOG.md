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
