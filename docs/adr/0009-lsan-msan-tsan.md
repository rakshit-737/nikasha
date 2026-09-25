<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0009: LSan, MSan and TSan parsers ship unverified and unregistered

- **Status:** accepted (fixture source: proposed, awaiting maintainer)
- **Date:** 2026-09-24
- **Amends:** ADR 0005 (fixture sources)

## Context

ADR 0005 deferred the LeakSanitizer, MemorySanitizer and ThreadSanitizer parsers because no
real fixtures existed, and trace fixtures must be real output only. In M2 the maintainer
decided that these fixtures will be captured in the sandbox from small public
reproductions at pinned tags (`PROGRESS.md`, M2 decisions). The machine that wrote the
parsers has no container engine, so the capture could not run there.

## Decision

- **Fixture source (open question, needs maintainer approval).** The M2 decision in
  `PROGRESS.md` says these fixtures come from *already-fixed bugs in public projects at
  pinned tags*. `scripts/capture_sanitizer_fixtures.py` instead builds compiler-rt's own
  upstream regression programs from `llvm-project` at `llvmorg-18.1.8`. Those are
  purpose-built leaks, races and uninitialised reads, **not** fixed bugs in real projects,
  so this **departs from the M2 decision**. The script refuses to run without
  `--maintainer-approved` until the maintainer either accepts this or names real fixed bugs
  to use instead (built from `GitRepo.export_tree`, ADR 0006).
- **Capture mechanics.** The repository is cloned in full (ADR 0006). Each program and the
  helper headers it includes (`tsan/test.h`, `sanitizer_common/print_address.h`) are read
  out of the tag with `GitRepo.read_file`, never with `git archive` or `checkout`, and keep
  their layout so `-I` resolves the upstream includes. Build flags, sanitizer options and
  arguments follow each test's upstream RUN line; TSan runs retry up to 10 times inside the
  container (upstream `%deflake`). Programs run only inside the `docker/capture` image
  through `sandbox.run_container` (P5). A capture is kept only if the sanitizer header is
  present, the run neither timed out nor was truncated, and the exit code is the pinned
  sanitizer code; outputs are moved into place only after every selected program passed.
  The README records tag, commit, base-image digest, `clang --version` from inside the
  image, environment and script. Paths, includes and RUN lines were checked against the
  tag on 2026-09-24.
- **Parsers.** `extract/traces/{lsan,msan,tsan}.py` are written on `common.py` and reuse
  the ASan frame and SUMMARY parsing, plus a shared label-driven scanner (`lsan.scan_labelled`).
  They follow the documented output formats and have **not been checked against real
  output**.
- **Not registered.** Because they are unverified, the modules do not use `@register`, and
  `extract/traces/__init__.py` does not import them. Reports that contain these traces are
  handled as before: every other claim is extracted, and those traces are not parsed. This
  keeps a possible misreading out of the verdict (P4).
- **Tests.**
  - Contract tests run in the default suite: empty input, garbage input, no crash on
    arbitrary text, linear time on hostile input, determinism, and not registered.
    `test_regex_linear.py` also covers every module-level pattern.
  - The fixture tests are marked `sandbox`. They skip with a stated reason until
    `tests/fixtures/traces/{lsan,msan,tsan}/` holds real captures.
  - **CI gap:** `.github/workflows/ci.yml` has no job running `pytest -m sandbox`, and
    nothing in CI runs the capture script. Until such a job exists, these tests (and
    `test_capture_image_has_msan_runtime`, which checks whether the Fedora image carries
    the MSan runtime; this is unknown until it runs) never run anywhere.

## Registering them later

Once the fixture-source question is settled, the capture has run and its fixtures are
committed, and the fixture tests pass, and after any parser
fixes the real output calls for:

1. add `@register` above `LsanParser`, `MsanParser` and `TsanParser`;
2. add `lsan, msan, tsan` to the import list in `extract/traces/__init__.py`, and update
   its comment;
3. drop `test_not_registered_by_default` from the three test files, and add value
   assertions (functions, files, lines) as the other formats' tests do;
4. remove `@pytest.mark.sandbox` from `test_real_fixtures_parse` in the three test files:
   it only reads committed files, so it belongs in the default suite;
5. update ADR 0005's consequences: 12 of 12 formats.

## Consequences

- There are still 9 of 12 parsed formats in the default pipeline until the steps above land.
- The capture uses the existing `sandbox.select_engine`, `image_exists`, `build_image` and
  `run_container`. The image ID is not recorded, because the sandbox exposes no image-ID
  query; the base digest and compiler version are recorded instead.
- Whether the Fedora capture image ships the MSan runtime is unknown until the sandbox test
  runs.
