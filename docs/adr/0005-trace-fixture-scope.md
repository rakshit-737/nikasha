<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0005: Where real trace fixtures come from

- **Status:** accepted
- **Date:** 2026-09-23

## Context

SPEC §9.5 requires at least three **real** fixtures per trace format, produced by actually
running the tools, with documented provenance. Hand-written or edited traces are forbidden.
During M1, an automated attempt to write small standalone crash programs (use-after-free,
data races, uninitialised reads and similar) was stopped by a safety classifier. The
maintainer then decided on a narrower scope.

## Decision

- **Memory-error traces come only from the deliberate vulnlab bug** (`examples/vulnlab`,
  v1.2.0 and v1.2.1): ASan (3), valgrind (3), and one gdb backtrace after glibc detects the heap
  corruption.
- **Every other fixture is a benign error from our own small programs**
  (`tests/fixtures/traces/programs/`):
  - UBSan: arithmetic undefined behaviour (signed overflow, shift exponent, division by zero);
  - gdb: SIGFPE and a failed `assert`;
  - Python, Java, Go, Rust and Node: ordinary exceptions and panics.
- All captures run through `scripts/capture_trace_fixtures.py` inside the pinned
  `docker/capture` image. The container runs rootless podman with `--network none`,
  `--read-only`, `--cap-drop ALL`, `no-new-privileges` and the host UID. Nothing runs on the
  host (P5).
- **LSan, MSan and TSan have no fixtures, so their parsers are not written yet.** A parser
  without real fixtures would be untested and could mis-read a report, which works against P4.
  Their gap is tracked in `PROGRESS.md` as an open question for the maintainer.

## Consequences

- 9 of the 12 required trace formats ship in M1. Reports containing LSan, MSan or TSan
  output still yield every other claim; their traces are simply not parsed.
- ASan fixtures show the *current* wording ("0 bytes **after** 64-byte region"; a SUMMARY
  naming `__asan_memcpy` and the module, not an app frame's file:line). The parser also
  accepts the older wording ("to the right of"). C11's consistency rules (M3) must accept
  both SUMMARY styles, and must not treat the modern style as a violation.
- Fixtures are snapshots. Addresses and build IDs change on every capture, so tests assert
  structure and values that are stable across captures (functions, files, lines, sizes).
