# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import json


def load(path):
    with open(path) as fh:
        return json.load(fh)


class Store:
    """A tiny key-value store."""

    def __init__(self, path):
        self.data = load(path)

    @property
    def size(self):
        return len(self.data)

    async def fetch(self, key):
        def pick(d):
            return d.get(key)

        return pick(self.data)

    class Meta:
        def describe(self):
            return repr(self)


def main():
    store = Store("db.json")
    print(store.size)
    return store.fetch("k")


main()
