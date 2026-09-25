# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""PHP: functions, classes, interfaces, methods (Class::method) and calls (SPEC §11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.PHP, "php/sample.php")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("function", "slugify", "slugify", 7, 10),
        # `render` in the interface has no body: not a definition.
        ("type", "Renderer", "Renderer", 12, 15),
        ("class", "Page", "Page", 17, 38),
        ("method", "__construct", "Page::__construct", 19, 21),
        ("method", "render", "Page::render", 23, 27),
        ("method", "wrap", "Page::wrap", 29, 32),
        ("method", "footer", "Page::footer", 34, 37),
    ]
    assert flags(FACTS, "Page::footer") == {"static"}


def test_calls() -> None:
    assert calls(FACTS) == [
        ("slugify", "strtolower", 9, False),
        ("slugify", "trim", 9, False),
        ("Page::render", "slugify", 25, False),
        ("Page::render", "wrap", 26, True),  # $this->wrap()
        ("Page::render", "footer", 26, False),  # Page::footer(): scoped, direct
        ("Page::wrap", "sprintf", 31, False),  # \sprintf: last component of the name
        (None, "Page", 40, False),  # new Page('Home')
        (None, "render", 41, True),  # $page?->render()
    ]


def test_php_embedded_in_html() -> None:
    src = b"<html><?php function greet($n) { return ucfirst($n); } ?><p><?= greet('a') ?></p>\n"
    facts = parse_file(Lang.PHP, src)
    assert symbols(facts) == [("function", "greet", "greet", 1, 1)]
    assert calls(facts) == [("greet", "ucfirst", 1, False), (None, "greet", 1, False)]
