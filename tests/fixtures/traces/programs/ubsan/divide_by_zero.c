// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// UBSan fixture: integer division by zero (run with halt_on_error=1).
#include <stdio.h>

static int divide(int total, int count)
{
    return total / count;
}

static int average(const int *values, int count)
{
    int total = 0;
    for (int i = 0; i < count; i++)
        total += values[i];
    return divide(total, count);
}

int main(int argc, char **argv)
{
    int values[1] = {42};
    (void)argv;
    printf("%d\n", average(values, argc - 1));
    return 0;
}
