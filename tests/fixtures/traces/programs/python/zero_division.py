# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python fixture: ZeroDivisionError three calls deep."""


def divide(numerator, denominator):
    return numerator / denominator


def success_rate(stats):
    return divide(stats["ok"], stats["total"])


def main():
    print(success_rate({"ok": 3, "total": 0}))


if __name__ == "__main__":
    main()
