<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# `ubsan` trace fixtures

Real, unedited tool output. Regenerate with `python scripts/capture_trace_fixtures.py --only ubsan`.

- Captured: 2026-09-23
- Image: `localhost/nikasha-capture:latest` (ID `e755de0c8f83`), base `registry.fedoraproject.org/fedora:44@sha256:b4488a77fd2b96513fc8c18b502df7fbf19dad9e77d9a430c0163c574654822c`
- Sandbox: rootless podman, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, host UID (`--userns=keep-id`)
- Tools: clang clang version 22.1.8 (Fedora 22.1.8-4.fc44), gcc gcc (GCC) 16.2.1 20260819 (Red Hat 16.2.1-2), gdb GNU gdb (Fedora Linux) 17.2-2.fc44, go go version go1.26.8-X:nodwarf5 linux/amd64, java openjdk version "25.0.4.1" 2026-08-18, node v24.18.0, python Python 3.14.7, rustc rustc 1.98.1 (48a229cea 2026-09-01) (Fedora 1.98.1-1.fc44), valgrind valgrind-3.27.1

| Fixture | What | Command run in the container |
|---|---|---|
| `01-signed-integer-overflow.txt` | clang -fsanitize=undefined -g -O0 | `clang -fsanitize=undefined -g -O0 -o /work/prog /src/programs/ubsan/signed_overflow.c && UBSAN_OPTIONS=print_stacktrace=1 /work/prog` |
| `02-shift-exponent.txt` | clang -fsanitize=undefined -g -O0 | `clang -fsanitize=undefined -g -O0 -o /work/prog /src/programs/ubsan/shift_exponent.c && UBSAN_OPTIONS=print_stacktrace=1 /work/prog` |
| `03-divide-by-zero-halt.txt` | clang -fsanitize=undefined -g -O0, halt_on_error=1 | `clang -fsanitize=undefined -g -O0 -o /work/prog /src/programs/ubsan/divide_by_zero.c && UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 /work/prog` |
