/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HDR_H
#define HDR_H

#include <stddef.h>

/* A single parsed header field. */
typedef struct hdr_field {
    char *name;
    char *value;
} hdr_field;

/* A growable list of parsed header fields. */
typedef struct hdr_list {
    hdr_field *fields;
    size_t count;
    size_t cap;
} hdr_list;

/* Initialise an empty list. */
void hdr_list_init(hdr_list *list);

/* Release every field and reset the list to empty. */
void hdr_list_free(hdr_list *list);

/* Parse one "Name: value" line and append it. Returns 0 on success, -1 on error. */
int hdr_parse_line(hdr_list *list, const char *line);

/* Return the value of the first field whose name matches (case-insensitive),
 * or NULL if there is none. */
const char *hdr_get(const hdr_list *list, const char *name);

#endif /* HDR_H */
