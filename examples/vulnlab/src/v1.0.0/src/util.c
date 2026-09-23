/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "util.h"

#include <string.h>

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

char *util_trim(char *s)
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
