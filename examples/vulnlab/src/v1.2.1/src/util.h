/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HDR_UTIL_H
#define HDR_UTIL_H

/* Maximum stored length of a header value, including the NUL terminator. */
#define HDR_VALUE_MAX 64

/* Strip leading and trailing whitespace in place and return the first
 * non-whitespace character of s. */
char *util_strip(char *s);

/* Copy a header value into a freshly allocated HDR_VALUE_MAX-byte heap buffer,
 * NUL-terminated. Returns the buffer, or NULL on allocation failure. */
char *util_copy_value(const char *value);

#endif /* HDR_UTIL_H */
