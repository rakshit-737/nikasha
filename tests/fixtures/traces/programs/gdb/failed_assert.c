// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// gdb fixture: abort() from a failed assert, with the libc frames that follow it.
#include <assert.h>
#include <stdio.h>

static void check_config(int version)
{
    assert(version >= 2 && "config version too old");
}

static void load_config(int version)
{
    check_config(version);
    puts("loaded");
}

int main(int argc, char **argv)
{
    (void)argv;
    load_config(argc);
    return 0;
}
