// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// UBSan fixture: shift exponent too large for the type.
#include <stdio.h>

static int shift_left(int value, int bits)
{
    return value << bits;
}

static int encode_flags(int flags, int width)
{
    return shift_left(flags, width * 10);
}

int main(int argc, char **argv)
{
    (void)argv;
    printf("%d\n", encode_flags(argc, 4));
    return 0;
}
