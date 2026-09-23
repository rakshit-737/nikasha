# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python fixture: an exception raised while handling another (implicit chaining)."""

SETTINGS = {"port": "8080"}


def lookup(key):
    return SETTINGS[key]


def read_timeout():
    try:
        return int(lookup("timeout"))
    except KeyError:
        raise ValueError("timeout is not configured")


def main():
    print(read_timeout())


if __name__ == "__main__":
    main()
