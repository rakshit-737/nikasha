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
