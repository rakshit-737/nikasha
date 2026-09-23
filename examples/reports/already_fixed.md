<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: Apache-2.0

FICTIONAL TEST FIXTURE for Nikasha. libhdr is the project's own demo library (examples/vulnlab);
this is not a report about real software. The bug is real and the patch is the real fix, but the report targets v1.3.0,
where that fix is already applied. Expected verdict: MIXED with "possibly already fixed".
-->

# Heap overflow in util_copy_value() in libhdr 1.3.0

**Affected:** libhdr 1.3.0

`util_copy_value()` in `src/util.c` copies the header value into a buffer of `HDR_VALUE_MAX`
(64) bytes using `memcpy` with the full value length. A header value longer than 64 bytes
overflows the heap buffer. I am reporting this against libhdr 1.3.0.

## Suggested patch

```diff
--- a/src/util.c
+++ b/src/util.c
@@ -26,6 +26,9 @@
     if (dst == NULL)
         return NULL;

+    if (len >= HDR_VALUE_MAX)
+        len = HDR_VALUE_MAX - 1;
+
     memcpy(dst, value, len);
     dst[len] = '\0';
     return dst;
```
