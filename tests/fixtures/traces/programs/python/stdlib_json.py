# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python fixture: an exception raised inside a standard-library module (json), re-raised
with an explicit cause."""

import json


class ConfigError(Exception):
    pass


def parse_config(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError("config is not valid JSON") from exc


def load(path_text):
    return parse_config(path_text)


def main():
    print(load('{"name": "demo", "retries": 3,,}'))


if __name__ == "__main__":
    main()
