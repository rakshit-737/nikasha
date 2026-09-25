<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0009: LSan, MSan and TSan parsers ship unverified and unregistered

- **Status:** accepted
- **Date:** 2026-09-24
- **Amends:** ADR 0005 (fixture sources)

## Context

ADR 0005 deferred the LeakSanitizer, MemorySanitizer and ThreadSanitizer parsers because no
real fixtures existed, and trace fixtures must be real output only. In M2 the maintainer
decided that these fixtures come from **already-fixed bugs in public projects at pinned
tags**, captured in the sandbox (`PROGRESS.md`, M2 decisions). No fixture has been captured
yet.

## Decision

- **Fixture source (follows the M2 decision).** `scripts/capture_sanitizer_fixtures.py`
  captures only from entries of its `BUGS` catalogue. Each entry names a public repository,
  a vulnerable tag, a fixed tag, the full fix commit SHA and a public bug reference, and
  triggers the bug with an input already in the project's tree. No crash program is written
  and no compiler-rt regression program is used. `BUGS` is **empty**: entries must be
  checked by a person against upstream history before they are added, and nothing is
  guessed. While it is empty, the script stops and writes nothing.
- **Capture mechanics.** Each repository is cloned in full (ADR 0006) through
  `nikasha.resolve.repo`. Both tags and the fix commit are resolved, and the fix commit must
  lie between them. Both trees are written with `GitRepo.export_tree` (never `git archive`
  or `checkout`). Builds and runs happen only inside the `docker/capture` image through
  `sandbox.select_engine`, `ContainerSpec`, `Mount` and `run_container` (P5). A capture is
  kept only if, at the vulnerable tag, the build succeeded, the sanitizer header is present,
  the run neither timed out nor was truncated, and the exit code is the pinned sanitizer
  code; **and** the same build at the fixed tag produces no sanitizer report. TSan runs
  retry up to 10 times inside the container. Outputs are staged in a temporary directory
  and moved into `tests/fixtures/traces/` only after every selected bug passed, so a failed
  run leaves no partial fixture.
- **Provenance.** The README written next to the fixtures records repository, tags, commit
  SHAs, fix commit, reference, the pinned base-image digest, `clang --version` from inside
  the image, environment and script. The local image ID is **not** recorded yet, because
  `nikasha.repro.sandbox` has no image-ID query; the README says so.
- **Parsers.** `extract/traces/{lsan,msan,tsan}.py` are written on `common.py` and reuse
  the ASan frame and SUMMARY parsing, plus a shared label-driven scanner
  (`lsan.scan_labelled`). They follow the documented output formats and have **not been
  checked against real output**. (A review found that the first TSan frame regex never
  matched `(module+0xOFF)` and dropped every path and line; it was replaced by
  `_split_module_suffix`, with regression tests on documented frame lines.)
- **Not registered.** Because they are unverified, the modules do not use `@register`, and
  `extract/traces/__init__.py` does not import them. Reports that contain these traces are
  handled as before: every other claim is extracted, and those traces are not parsed. This
  keeps a possible misreading out of the verdict (P4).
- **Tests.**
  - Contract tests run in the default suite: empty input, garbage input, no crash on
    arbitrary text, linear time on hostile input, determinism, not registered, and the
    capture script's acceptance, fixed-tag, catalogue and argv-hardening rules.
    `test_regex_linear.py` also covers every module-level pattern.
  - `test_real_fixtures_parse` is in the default suite (it only reads committed files). It
    **skips** until `tests/fixtures/traces/{lsan,msan,tsan}/` holds captures, so today it
    checks nothing.
  - `test_capture_image_has_msan_runtime` is marked `sandbox` and `network` (it may build
    the Fedora image). The CI sandbox job runs `sandbox and not network`, so it does not run
    in CI. **Whether the Fedora capture image ships the MSan runtime is unverified**: on
    2026-09-25 the image could not be built in the development container, because the
    outbound proxy refuses the Fedora mirrors.

## Registering them later

Once hand-verified fixed bugs are catalogued, the capture has run and its fixtures are
committed, the fixture tests pass, and after any parser fixes the real output calls for:

1. add `@register` above `LsanParser`, `MsanParser` and `TsanParser`;
2. add `lsan, msan, tsan` to the import list in `extract/traces/__init__.py`, and update
   its comment;
3. drop `test_not_registered_by_default` from the three test files, and add value
   assertions (functions, files, lines) as the other formats' tests do;
4. update ADR 0005's consequences: 12 of 12 formats.

## Consequences

- There are still 9 of 12 parsed formats in the default pipeline until the steps above land.
- Until someone catalogues real fixed bugs, these parsers stay unverified; this ADR does not
  claim otherwise.
