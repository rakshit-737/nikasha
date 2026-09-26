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
  a vulnerable tag, a fixed tag, the full fix commit SHA and a public bug reference. It
  triggers the bug only through the project's own programs (its CLI or an example program
  in its tree), fed with the project's own files or a literal input of a few bytes. No
  crash program is written and no compiler-rt regression program is used. *Amended
  2026-09-26:* `BUGS` now holds three bugs per format, listed with their evidence under
  "Catalogued bugs" below. If `BUGS` has no entry for a format, the script stops and writes
  nothing.
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

## Catalogued bugs (2026-09-26)

Each row was checked against a full clone of the upstream repository on 2026-09-26. Both
tags exist, and the fix commit exists and is listed by `git rev-list <vulnerable>..<fixed>`
(the capture script checks the same thing again before it builds anything). The code the
fix changes was meant to be read at the vulnerable tag, to confirm the bug was in that
release and was not added and fixed between two releases. The first catalogue got this wrong
for one row (the zstd TSan bug, see "First capture run"); the capture's clean-at-fixed and
report-at-vulnerable checks are what actually confirm each row. Every project's licence allows building and
running it (BSD/GPLv2 dual, zlib, MIT, 0BSD or public domain).

| Format | Project | Vulnerable → fixed | Fix commit | Public reference | Trigger (project's own program) |
|---|---|---|---|---|---|
| LSan | zstd | `v1.1.3` → `v1.1.4` | `2bb6fc2a944d30d0ec3ec18d3db0fc462cf06ccf` | [zstd#546](https://github.com/facebook/zstd/pull/546) | `examples/simple_compression` on a file: the output file name is never freed |
| LSan | jq | `jq-1.7.1` → `jq-1.8.0` | `5bbd02f581dff4060815e4291b80a9316841195e` | [oss-fuzz 66061](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=66061) (the commit quotes the LSan report) | `jq -n '[] \| setpath([[1]]; 1)'`: `jv_setpath` never frees `subroot` when the set fails |
| LSan | zstd | `v1.4.1` → `v1.4.2` | `793b94b3541de7535787b5ddebc555bc63d9bef3` | [zstd#1701](https://github.com/facebook/zstd/pull/1701) | `zstd -r` on a directory holding a symlink: the skipped path is never freed |
| MSan | jq | `jq-1.7.1` → `jq-1.8.0` | `96d19ca2eef4bed201c5b1175ed013bc3122a001` | [jq#3316](https://github.com/jqlang/jq/issues/3316) (reported with an MSan trace) | `printf n \| jq .`: `check_literal` reads `tokenbuf[1]` |
| MSan | zlib | `v1.2.8` → `v1.2.9` | `c901a34c92c4aa74028f541a9773df726ce2b769` | [commit](https://github.com/madler/zlib/commit/c901a34c92c4aa74028f541a9773df726ce2b769) | `minigzip < /dev/null`: `deflate()` tests the never-set `next_in` from `gzclose_w()` (built at `-O0`, see below) |
| MSan | libjpeg-turbo | `2.0.90` → `2.1.0` | `b1079002ad451aab896617098b6bcbaae1d967e4` | [commit](https://github.com/libjpeg-turbo/libjpeg-turbo/commit/b1079002ad451aab896617098b6bcbaae1d967e4) ("Fix innocuous MSan error") | `cjpeg` on a 1×1 binary PGM (maxval 1, sample 8, written as literal bytes): `rescale[8]` was never written, and the sample reaches the encoder's own branches (pure C build, `-O0`) |
| TSan | libvpx | `v1.14.0` → `v1.14.1` | `4c80888a71829941c8a4218e61433e8443901dea` (1.14 cherry-pick of `756b29a7`) | [commit](https://github.com/webmproject/libvpx/commit/4c80888a71829941c8a4218e61433e8443901dea) ("Fix to race issue for multi-thread with pnsr_calc") | `vpxenc --codec=vp8 --threads=4 --psnr` on raw 1280×720 frames cut from the tree's sources (pure C `generic-gnu` build): the main thread reads the frame for PSNR while the loop-filter thread is still writing it |
| TSan | pigz | `v2.4` → `v2.5` | `1e847e68cc96f311b15bb091ce5b9b20d110e37f` | [commit](https://github.com/madler/pigz/commit/1e847e68cc96f311b15bb091ce5b9b20d110e37f) | `pigz -p 4` on repeated `pigz.c`: `get_space()` and `drop_space()` take the two locks in opposite orders (lock-order inversion) |
| TSan | xz | `v5.8.3` → `v5.8.4` | `c6e3aadbb510e44cecfe870408ecfea1d1ca792c` | [xz#243](https://github.com/tukaani-project/xz/pull/243) (the commit says TSan reported it) | `xz -T4 -d` on a multi-block file made by `xz -T2`: `progress_in` is written without the mutex |

Candidates that were looked at and rejected, so nobody repeats the work:

- zstd `48bca107`, `6c35fb2e`, `2a907bf4`, `49c6d492`, `d195eec9`, `de5e38a7` and lz4
  `84f978a2`, `854d13a1`: the bug was added and fixed between two releases, so no release
  tag is vulnerable.
- xz `7bd6d63b` and `4b9b8271` (`--files` leaks): at `v5.8.3` the name buffer is still
  reachable from a static pointer, so LSan reports nothing.
- lz4 `06a27a66`: the leak needs a file shorter than 19 bytes to reach `LZ4F_readOpen()`,
  and no in-tree program was confirmed to do that, so it was not pursued.
- curl `57446b67`: the MSan reports most likely came from missing `__isoc23_strtol`
  interceptors in an older toolchain, so they may not reproduce with the pinned clang.
- pigz `b88a0e9`: the `--list` race is on the file offset, not on memory, so TSan does not
  see it.

**First capture run (2026-09-26, CI, docker).** Four of nine captured. The five failures and
what changed:

- LSan lz4 `fe66e78b`: no report, and none is possible. The unclosed `FILE` stays reachable
  from glibc's `_IO_list_all`, so LeakSanitizer does not count it. Replaced by jq `5bbd02f5`.
- MSan jq: `automake` failed because `Makefile.am` names `modules/oniguruma` (a submodule,
  absent from an exported tree) in a conditional `SUBDIRS`. The build now creates the empty
  directory first; Oniguruma stays disabled. The LSan jq entry uses the same build.
- MSan xz: no report because MSan turns `check_printf` off by default, and the unwritten
  buffer is only read inside `printf("%s")`. The entry now sets `MSAN_OPTIONS=check_printf=1`.
- TSan zstd `7992942d`: the vulnerable code is **not** in `v1.3.5`. There the last-block
  stats do not set `job->consumed`; the fix's pre-image came from a commit made after
  `v1.3.5`, so the bug was added and fixed between releases (the earlier check was wrong).
  Replaced by pigz `33677270`, whose race needs no lucky timing: nothing orders the
  worker's read after `twist()` before the writer's `free(job)`.
- TSan xz: xz 5.8's CMake refuses `-fsanitize=` with Landlock on; it now passes
  `-DXZ_SANDBOX=no`, as its error message asks. (The race itself is a main-thread write of
  `coder->progress_in` without the mutex against the workers' locked writes, so it does
  not depend on `-v`.)

Rejected in this round: xz `be365b70` (`partial_update` race; `v5.8.1` → `v5.8.2`, but
`v5.8.2` still has the `progress_in` race, so the fixed tag would not be clean); zstd
`190a6209` (no release after the fix); lz4 `04374588` (multithreading was added after
`v1.9.4`); pigz `189866f3` (a same-thread use-after-free, which TSan does not report).

**Second capture run (2026-09-26, CI, docker).** The xz TSan entry captured (five of nine).
The four failures and what changed:

- LSan and MSan jq: still a build failure. The 4 KB log tail stopped in the middle of a
  parallel build, so the error itself was not shown. The likely cause: `make jq` does not
  build `BUILT_SOURCES`, so `src/builtin.inc` (included by `builtin.c`) was never
  generated. The shared jq build now runs the default target. A failed build now prints
  the log's error lines first, then its tail, so a third failure will show the error.
- MSan xz `eb2ef4c7`: still no report with `check_printf=1`. The unwritten buffer is only
  ever read inside libc's `printf`, never by a branch in xz, so the report depends on the
  printf interceptor, not on xz. Replaced by libjpeg-turbo `b1079002`, where the
  uninitialised value is used by branches inside the project.
- TSan pigz `33677270`: the fixed tag reported the `v2.4`-era lock-order inversion
  (`1e847e68`, fixed only in `v2.5`), so it was never clean. The race itself also turned
  out to be timing-dependent: the worker's `Trace()` is ordered before the writer's `free()`
  whenever the writer logs after it. Replaced by libvpx `4c80888a`. There, nothing orders
  the main thread's PSNR reads against the loop-filter thread's writes until the next
  frame's `sem_wait`. The image gains `perl-interpreter` and `diffutils` for libvpx's
  `configure`.

Checked for the replacements: both tags exist (`git ls-remote`). The fix commit is not
reachable from the vulnerable tag and is contained in the fixed tag (`gh api compare`, or
`git merge-base --is-ancestor` on a full clone). The vulnerable code was read at the
vulnerable tag: `get_scaled_gray_row()` indexes `rescale[]` without bounds checking, and
`rescale[]` is only filled up to maxval; `generate_psnr_packet()` is called before the
`h_event_end_lpf` wait.

**Not yet verified (known only after a capture run):**

- whether each trigger really produces a report at the vulnerable tag and none at the fixed
  tag. TSan triggers are timing-dependent (10 attempts). The zlib entry depends on the
  short-circuit branch surviving compilation, which is why it alone builds at `-O0`;
- whether the older trees still build with the image's clang (C89-era code, autotools
  macros);
- whether the Fedora image ships the MSan runtime (see Tests above).

A failing bug is reported by name and nothing is written. It is then replaced, never
forced. The image gained `cmake`, `autoconf`, `automake`, `libtool`, `gettext-devel` (for
`autopoint`) and `zlib-ng-compat-devel` (for pigz). The capture runs in
`.github/workflows/sanitizer-fixtures.yml`, which is manual only. That workflow lowers
`vm.mmap_rnd_bits` to 28 on the runner (TSan and MSan need a fixed shadow layout) and
uploads each format's fixtures as an artifact for a maintainer to review and commit. The
script gained `--engine` (the runner also has rootless podman, which has a separate image
store) and `--keep-going` (reports every failing bug and still writes nothing).

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
- Until the catalogued bugs have been captured and the fixtures committed, these parsers
  stay unverified; this ADR does not claim otherwise.
