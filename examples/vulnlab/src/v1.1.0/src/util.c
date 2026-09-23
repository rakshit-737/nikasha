/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "util.h"

#include <stdlib.h>
#include <string.h>

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

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

char *util_copy_value(const char *value)
{
    size_t len = strlen(value);
    char *dst = malloc(HDR_VALUE_MAX);

    if (dst == NULL)
        return NULL;
    /* Never copy more than fits in the buffer; leave room for the NUL. */
    if (len >= HDR_VALUE_MAX)
        len = HDR_VALUE_MAX - 1;
    memcpy(dst, value, len);
    dst[len] = '\0';
    return dst;
}
