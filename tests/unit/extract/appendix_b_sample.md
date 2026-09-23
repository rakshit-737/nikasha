<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0

Fictional report from SPEC.md Appendix B, used as an extraction test input.
-->

# Critical heap overflow in libhdr hdr_decode_chunked_value() leads to RCE

**Affected:** libhdr 1.2.0 and all earlier versions · **CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 9.8 (Critical)** · CWE-122

The function `hdr_decode_chunked_value()` in `src/hdr.c` fails to validate the chunk length before copying into a
fixed buffer, which allows remote attackers to execute arbitrary code. This can be triggered with the
`--unsafe-fold` option of `hdrcat`.

Vulnerable code (src/hdr.c, line 412):
```c
static int hdr_decode_chunked_value(hdr_ctx *ctx, const char *in, size_t n) {
    char tmp[64];
    memcpy(tmp, in + ctx->chunk_off, n);   /* no bounds check */
    return hdr_emit(ctx, tmp, n);
}
```

```
==4121==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000000051 at pc 0x4c3a2e bp 0x7ffd sp 0x7ffd
WRITE of size 96 at 0x606000000051 thread T0
    #0 0x4c3a2d in __asan_memcpy
    #1 0x4f10aa in util_copy_value /src/libhdr/src/util.c:77:5
    #2 0x4f0b3c in hdr_get /src/libhdr/src/hdr.c:412:12
    #3 0x4f0a01 in main /src/libhdr/tools/hdrcat.c:58:9
0x606000000051 is located 1 bytes to the right of 64-byte region [0x606000000000,0x606000000040)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/libhdr/src/hdr.c:77 in hdr_decode_chunked_value
```

Suggested patch:
```diff
--- a/src/hdr.c
+++ b/src/hdr.c
@@ -410,6 +410,8 @@ static int hdr_decode_chunked_value(hdr_ctx *ctx, const char *in, size_t n) {
     char tmp[64];
+    if (n > sizeof(tmp))
+        return HDR_ERR_TOO_LONG;
     memcpy(tmp, in + ctx->chunk_off, n);
```
