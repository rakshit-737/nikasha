# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Regressions found in the line-level review of the HTML renderer."""

from __future__ import annotations

import json
from urllib.parse import unquote

from nikasha.render.html.components.downloads import data_uri
from nikasha.render.html.escaping import attr, clean, text
from nikasha.render.html.excerpts import lines_around


def test_lone_surrogates_are_dropped_so_the_page_encodes() -> None:
    hostile = "a\ud800b\udfffc"
    for out in (clean(hostile), text(hostile), attr(hostile)):
        assert out == "abc"
        out.encode("utf-8")


def test_data_uri_survives_a_lone_surrogate_and_decodes_to_the_same_json() -> None:
    payload = json.dumps({"body": "x\ud800y"}, ensure_ascii=False)
    uri = data_uri(payload)
    uri.encode("ascii")
    decoded = json.loads(unquote(uri.removeprefix("data:application/json,")))
    assert decoded == {"body": "x\ud800y"}


def test_excerpt_past_the_end_of_the_file_shows_nothing() -> None:
    source = "one\ntwo\nthree\n"
    assert list(lines_around(source, 50, 52, context=1)) == []


def test_reversed_range_covers_both_ends() -> None:
    source = "\n".join(str(n) for n in range(1, 21))
    numbers = [n for n, _ in lines_around(source, 12, 8, context=1)]
    assert numbers[0] == 7
    assert numbers[-1] == 13
