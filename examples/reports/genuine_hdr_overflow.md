<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: Apache-2.0

FICTIONAL TEST FIXTURE for Nikasha. libhdr is the project's own demo library (examples/vulnlab);
this is not a report about real software. The ASan output below was captured by really running the PoC
(tests/fixtures/traces/asan/01-vulnlab-heap-overflow-v1.2.0.txt, scripts/capture_trace_fixtures.py).
-->

# Heap buffer overflow in libhdr util_copy_value() with long header values

**Affected:** libhdr 1.2.0 · **CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H 5.5 (Medium)** · CWE-122

`util_copy_value()` in `src/util.c` allocates a fixed 64-byte buffer (`HDR_VALUE_MAX`) and then
copies the whole header value into it with `memcpy`, without checking the value's length. A
header whose value is longer than 64 bytes writes past the end of the heap buffer.

The function is reached from `hdrcat` through `hdr_parse_block()` and `hdr_parse_line()`, so any
file passed to `hdrcat` can trigger it. I tested libhdr 1.2.0 (tag v1.2.0), built with
AddressSanitizer.

## Steps to reproduce

1. Build libhdr 1.2.0 with ASan:
   `make CC=clang CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined"`
2. Save the proof of concept below as `poc.txt` (a single header whose value is 96 bytes).
3. Run `./build/hdrcat poc.txt`.

## Proof of concept

```
Host: example.test
X-Overflow: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```console
$ ./build/hdrcat poc.txt
```

## Sanitizer output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bc73b5e00c0 at pc 0x0000004a44a2 bp 0x7fff424f3ac0 sp 0x7fff424f3280
WRITE of size 96 at 0x7bc73b5e00c0 thread T0
    #0 0x0000004a44a1 in __asan_memcpy (/work/libhdr/build/hdrcat+0x4a44a1) (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e)
    #1 0x0000004ed539 in util_copy_value /work/libhdr/src/util.c:15:5
    #2 0x0000004ec2c0 in hdr_parse_line /work/libhdr/src/hdr.c:104:13
    #3 0x0000004eca34 in hdr_parse_block /work/libhdr/src/hdr.c:134:17
    #4 0x0000004eb6b9 in main /work/libhdr/tools/hdrcat.c:122:5
    #5 0x7f673c41d680 in __libc_start_call_main /usr/src/debug/glibc-2.43-8.fc44.x86_64/csu/../sysdeps/nptl/libc_start_call_main.h:59:16
    #6 0x7f673c41d797 in __libc_start_main@GLIBC_2.2.5 /usr/src/debug/glibc-2.43-8.fc44.x86_64/csu/../csu/libc-start.c:360:3
    #7 0x000000400764 in _start (/work/libhdr/build/hdrcat+0x400764) (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e)

0x7bc73b5e00c0 is located 0 bytes after 64-byte region [0x7bc73b5e0080,0x7bc73b5e00c0)
allocated by thread T0 here:
    #0 0x0000004a6818 in malloc (/work/libhdr/build/hdrcat+0x4a6818) (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e)
    #1 0x0000004ed51e in util_copy_value /work/libhdr/src/util.c:11:17
    #2 0x0000004ec2c0 in hdr_parse_line /work/libhdr/src/hdr.c:104:13
    #3 0x0000004eca34 in hdr_parse_block /work/libhdr/src/hdr.c:134:17
    #4 0x0000004eb6b9 in main /work/libhdr/tools/hdrcat.c:122:5
    #5 0x7f673c41d680 in __libc_start_call_main /usr/src/debug/glibc-2.43-8.fc44.x86_64/csu/../sysdeps/nptl/libc_start_call_main.h:59:16
    #6 0x7f673c41d797 in __libc_start_main@GLIBC_2.2.5 /usr/src/debug/glibc-2.43-8.fc44.x86_64/csu/../csu/libc-start.c:360:3
    #7 0x000000400764 in _start (/work/libhdr/build/hdrcat+0x400764) (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/work/libhdr/build/hdrcat+0x4a44a1) (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e) in __asan_memcpy
Shadow bytes around the buggy address:
  0x7bc73b5dfe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bc73b5dfe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bc73b5dff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bc73b5dff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bc73b5e0000: fa fa fa fa 00 00 00 00 00 00 00 00 fa fa fa fa
=>0x7bc73b5e0080: 00 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa fa
  0x7bc73b5e0100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7bc73b5e0180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7bc73b5e0200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7bc73b5e0280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7bc73b5e0300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==1==ABORTING
```

## Root cause

At src/util.c line 15, `memcpy(dst, value, len)` copies `strlen(value)` bytes into a buffer of
`HDR_VALUE_MAX` (64) bytes. The length is never compared with the buffer size, and the
following `dst[len] = '\0'` also writes out of bounds.

## Suggested fix

Clamp `len` to `HDR_VALUE_MAX - 1` before the copy, or reject over-long values in
`hdr_parse_line()`.
