/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "hdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read a whole file into a heap buffer. Caller frees. */
static char *read_file(const char *path)
{
    FILE *fp;
    long size;
    char *buf;

    fp = fopen(path, "rb");
    if (fp == NULL)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[size] = '\0';
    fclose(fp);
    return buf;
}

/* Join obs-fold continuation lines (leading space or tab) onto the previous
 * line, in place. */
static void fold_lines(char *buf)
{
    char *r = buf, *w = buf;

    while (*r != '\0') {
        if (*r == '\n' && (r[1] == ' ' || r[1] == '\t')) {
            *w++ = ' ';
            r++;
            while (*r == ' ' || *r == '\t')
                r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

/* Keep at most max lines, truncating the buffer in place. */
static void cap_lines(char *buf, long max)
{
    long n = 0;
    char *p = buf;

    while (*p != '\0') {
        if (*p == '\n') {
            n++;
            if (n >= max) {
                p[1] = '\0';
                return;
            }
        }
        p++;
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: hdrcat [--fold] [--max-lines N] FILE\n");
}

int main(int argc, char **argv)
{
    int fold = 0;
    long max_lines = -1;
    const char *path = NULL;
    char *buf;
    hdr_list list;
    size_t i;

    for (i = 1; i < (size_t)argc; i++) {
        if (strcmp(argv[i], "--fold") == 0) {
            fold = 1;
        } else if (strcmp(argv[i], "--max-lines") == 0) {
            if (i + 1 >= (size_t)argc) {
                usage();
                return 2;
            }
            max_lines = strtol(argv[++i], NULL, 10);
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "hdrcat: unknown option %s\n", argv[i]);
            return 2;
        } else {
            path = argv[i];
        }
    }
    if (path == NULL) {
        usage();
        return 2;
    }

    buf = read_file(path);
    if (buf == NULL) {
        fprintf(stderr, "hdrcat: cannot read %s\n", path);
        return 1;
    }
    if (fold)
        fold_lines(buf);
    if (max_lines >= 0)
        cap_lines(buf, max_lines);

    hdr_list_init(&list);
    hdr_parse_block(&list, buf);

    for (i = 0; i < list.count; i++)
        printf("%s=%s\n", list.fields[i].name, list.fields[i].value);

    hdr_list_free(&list);
    free(buf);
    return 0;
}
