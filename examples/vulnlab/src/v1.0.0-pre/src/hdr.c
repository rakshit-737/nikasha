/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "hdr.h"

#include "util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define HDR_NAME_MAX 128

/* Duplicate a NUL-terminated string onto the heap (C99, no POSIX strdup). */
static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p != NULL)
        memcpy(p, s, n);
    return p;
}

/* ASCII case-insensitive comparison. */
static int hdr_casecmp(const char *a, const char *b)
{
    unsigned char ca, cb;

    for (;;) {
        ca = (unsigned char)tolower((unsigned char)*a++);
        cb = (unsigned char)tolower((unsigned char)*b++);
        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == '\0')
            return 0;
    }
}

/* Return the index of the first field named name, or -1. */
static int hdr_find_line(const hdr_list *list, const char *name)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (hdr_casecmp(list->fields[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

/* Ensure the list has room for one more field. */
static int hdr_list_grow(hdr_list *list)
{
    if (list->count == list->cap) {
        size_t ncap = list->cap ? list->cap * 2 : 8;
        hdr_field *nf = realloc(list->fields, ncap * sizeof(*nf));
        if (nf == NULL)
            return -1;
        list->fields = nf;
        list->cap = ncap;
    }
    return 0;
}

void hdr_list_init(hdr_list *list)
{
    list->fields = NULL;
    list->count = 0;
    list->cap = 0;
}

void hdr_list_free(hdr_list *list)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        free(list->fields[i].name);
        free(list->fields[i].value);
    }
    free(list->fields);
    hdr_list_init(list);
}

int hdr_parse_line(hdr_list *list, const char *line)
{
    char *buf, *colon, *name, *value, *ncopy, *vcopy;

    buf = dup_str(line);
    if (buf == NULL)
        return -1;
    colon = strchr(buf, ':');
    if (colon == NULL) {
        free(buf);
        return -1;
    }
    *colon = '\0';
    name = util_trim(buf);
    value = util_trim(colon + 1);

    if (hdr_list_grow(list) != 0) {
        free(buf);
        return -1;
    }
    ncopy = dup_str(name);
    vcopy = dup_str(value);
    if (ncopy == NULL || vcopy == NULL) {
        free(ncopy);
        free(vcopy);
        free(buf);
        return -1;
    }
    list->fields[list->count].name = ncopy;
    list->fields[list->count].value = vcopy;
    list->count++;
    free(buf);
    return 0;
}

const char *hdr_get(const hdr_list *list, const char *name)
{
    char key[HDR_NAME_MAX];
    int idx;

    strncpy(key, name, sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';
    idx = hdr_find_line(list, util_trim(key));
    if (idx < 0)
        return NULL;
    return list->fields[idx].value;
}
