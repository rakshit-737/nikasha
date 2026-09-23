// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// gdb fixture: SIGFPE from an integer division by zero in a plain -O0 build.
#include <stdio.h>

static int ratio(int a, int b)
{
    return a / b;
}

static int report(int hits, int total)
{
    return ratio(hits * 100, total);
}

int main(int argc, char **argv)
{
    (void)argv;
    printf("%d%%\n", report(7, argc - 1));
    return 0;
}
