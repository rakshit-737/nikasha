// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// UBSan fixture: signed integer overflow three calls deep.
#include <limits.h>
#include <stdio.h>

static int scale(int value, int factor)
{
    return value * factor;
}

static int accumulate(int base)
{
    return scale(base, 4);
}

int main(void)
{
    printf("%d\n", accumulate(INT_MAX / 2));
    return 0;
}
