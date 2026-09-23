<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: Apache-2.0
-->

# vulnlab: the hermetic `libhdr` demo lab

`libhdr` is a **fictional** C99 HTTP-header parser invented for the Nikasha project. It
does not correspond to any real library, and it is not meant to be used for anything real.
Its only purpose is to give Nikasha's fact-checking pipeline a small target with a
**deterministic git history** and a **deliberately introduced memory-safety bug**, so that
fixtures and demos can point at exact commits.

> [!WARNING]
> Later versions of `libhdr` contain an intentional heap buffer overflow. This is a
> teaching/testing artifact. Do not copy this code into a real project.

## What `libhdr` is

A tiny header parser: `hdr_parse_line()` turns one `Name: value` line into a stored field,
`hdr_parse_block()` walks a buffer of such lines, and a lookup helper (`hdr_get`, later
`hdr_find`) fetches a value by name. `tools/hdrcat.c` is a CLI:

```
hdrcat [--fold] [--max-lines N] FILE
```

It reads HTTP header lines from `FILE` and prints one `name=value` per parsed header.
`--fold` joins obs-fold continuation lines (a line beginning with a space or tab) onto the
previous header value; `--max-lines N` caps how many lines are read.

## The versions

The per-version source trees live under `src/<tag>/` (plus one intermediate tree,
`src/v1.0.0-pre/`, used only for the first commit). Each tree is a **complete** snapshot of
the library at that point; the builder injects the Apache-2.0 licence as `LICENSE` at every
commit, so the trees do not carry their own copy.

| Tag | What changes |
|---|---|
| `v1.0.0` | Public API `hdr_parse_line()` and `hdr_get()`; a `util_trim()` helper in `util.c`. |
| `v1.1.0` | Adds `hdr_parse_block()` and `util_copy_value()` (copies a value into a 64-byte heap buffer **with** a bounds check); renames `util_trim` to `util_strip`. |
| `v1.2.0` | **Introduces the bug.** A refactor drops the bounds check, so `util_copy_value()` does `memcpy(dst, src, len)` into the 64-byte buffer unconditionally. A header value longer than 64 bytes overflows the heap buffer. Reachable as `hdrcat` main -> `hdr_parse_block` -> `hdr_parse_line` -> `util_copy_value` -> `memcpy`. |
| `v1.2.1` | Comment and whitespace changes only; the bug is unchanged. These shift line numbers in `hdr.c` and `util.c`. |
| `v1.3.0` | Fixes the bounds check with a small self-contained hunk in `src/util.c`, and replaces `hdr_get()` with `hdr_find()`. |

## The bug and how it is reached

At `v1.2.0`/`v1.2.1`, `util_copy_value()` allocates a 64-byte heap buffer and copies the
whole value into it without checking its length:

```c
char *dst = malloc(HDR_VALUE_MAX);   /* HDR_VALUE_MAX == 64 */
...
memcpy(dst, value, len);             /* len is unchecked */
```

A header whose value is longer than 64 bytes triggers an AddressSanitizer
`heap-buffer-overflow` WRITE. Per Nikasha policy, proof-of-concept inputs are **only** run
inside the hardened sandbox; never run `hdrcat` on overflow input on the host.

## Building the git repository

`scripts/build_vulnlab.py` replays `history.toml` into a fresh **bare** repository using
`git fast-import`, with fixed author, committer, dates and messages and LF-normalised file
contents. The resulting commit SHAs are identical on every machine.

```
# print the tag -> commit SHA map for a throwaway build
python scripts/build_vulnlab.py /tmp/vulnlab.git

# rebuild and refresh the golden map in expected.json
python scripts/build_vulnlab.py /tmp/vulnlab.git --write-expected
```

The golden map is stored in [`expected.json`](expected.json), and the integration tests in
`tests/integration/test_vulnlab.py` assert that a fresh build reproduces it exactly.

## Building the C library

From any `src/<tag>/` tree:

```
make                                              # build/libhdr.a and build/hdrcat
make CC=clang CFLAGS='-std=c99 -Wall -Wextra -Werror'
make clean
```
