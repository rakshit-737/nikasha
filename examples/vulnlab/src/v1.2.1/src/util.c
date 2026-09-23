/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * util.c - small string helpers used by the header parser.
 *
 * util_copy_value() places a header value into a fixed-size heap buffer so
 * that stored values all share the same allocation size. util_strip() removes
 * surrounding linear whitespace from a mutable string.
 */
#include "util.h"

#include <stdlib.h>
#include <string.h>

/*
 * Copy a header value into a freshly allocated HDR_VALUE_MAX-byte buffer.
 *
 * The buffer is always HDR_VALUE_MAX bytes so callers can rely on a stable
 * allocation size, and the copied value is NUL-terminated.
 */
char *util_copy_value(const char *value)
{
    size_t len = strlen(value);
    char *dst = malloc(HDR_VALUE_MAX);

    if (dst == NULL)
        return NULL;

    memcpy(dst, value, len);
    dst[len] = '\0';
    return dst;
}

/* True for the linear-whitespace characters we trim from field text. */
static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
 * Strip leading and trailing whitespace from s in place, returning a pointer
 * to the first surviving character.
 */
char *util_strip(char *s)
{
    char *end;

    while (is_ws(*s))
        s++;

    end = s + strlen(s);
    while (end > s && is_ws(end[-1]))
        end--;

    *end = '\0';
    return s;
}
