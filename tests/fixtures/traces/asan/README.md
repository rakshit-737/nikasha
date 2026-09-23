<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# `asan` trace fixtures

Real, unedited tool output. Regenerate with `python scripts/capture_trace_fixtures.py --only asan`.

- Captured: 2026-09-23
- Image: `localhost/nikasha-capture:latest` (ID `e755de0c8f83`), base `registry.fedoraproject.org/fedora:44@sha256:b4488a77fd2b96513fc8c18b502df7fbf19dad9e77d9a430c0163c574654822c`
- Sandbox: rootless podman, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, host UID (`--userns=keep-id`)
- Tools: clang clang version 22.1.8 (Fedora 22.1.8-4.fc44), gcc gcc (GCC) 16.2.1 20260819 (Red Hat 16.2.1-2), gdb GNU gdb (Fedora Linux) 17.2-2.fc44, go go version go1.26.8-X:nodwarf5 linux/amd64, java openjdk version "25.0.4.1" 2026-08-18, node v24.18.0, python Python 3.14.7, rustc rustc 1.98.1 (48a229cea 2026-09-01) (Fedora 1.98.1-1.fc44), valgrind valgrind-3.27.1

| Fixture | What | Command run in the container |
|---|---|---|
| `01-vulnlab-heap-overflow-v1.2.0.txt` | vulnlab v1.2.0, clang -O1, ASan+UBSan, 96-byte value | `cp -r /src/vulnlab/v1.2.0 /work/libhdr && cd /work/libhdr && make -s CC=clang CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" >/dev/null 2>&1 && ASAN_OPTIONS=symbolize=1:detect_leaks=0 ./build/hdrcat /poc/large.txt` |
| `02-vulnlab-heap-overflow-v1.2.1.txt` | vulnlab v1.2.1 (line numbers shifted), clang -O1 | `cp -r /src/vulnlab/v1.2.1 /work/libhdr && cd /work/libhdr && make -s CC=clang CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" >/dev/null 2>&1 && ASAN_OPTIONS=symbolize=1:detect_leaks=0 ./build/hdrcat /poc/large.txt` |
| `03-vulnlab-heap-overflow-v1.2.0-O0-fold.txt` | vulnlab v1.2.0, clang -O0, --fold, slow unwinding | `cp -r /src/vulnlab/v1.2.0 /work/libhdr && cd /work/libhdr && make -s CC=clang CFLAGS="-O0 -g -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" >/dev/null 2>&1 && ASAN_OPTIONS=symbolize=1:detect_leaks=0:fast_unwind_on_malloc=0 ./build/hdrcat --fold /poc/large.txt` |

Vulnlab inputs: `large.txt` is a header whose value is 96 bytes (the heap buffer is 64); `small.txt` uses a 70-byte value. Both come from this script (`POC_LARGE`, `POC_SMALL`).
