# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Language detection from extension, header contents and shebang (SPEC §11.2)."""

from __future__ import annotations

import pytest

from nikasha.code.languages import Lang, detect_language


@pytest.mark.parametrize(
    ("path", "lang"),
    [
        ("src/main.c", Lang.C),
        ("lib/x.cc", Lang.CPP),
        ("lib/x.cpp", Lang.CPP),
        ("lib/x.hpp", Lang.CPP),
        ("pkg/mod.py", Lang.PYTHON),
        ("pkg/stubs.pyi", Lang.PYTHON),
        ("web/app.js", Lang.JAVASCRIPT),
        ("web/app.mjs", Lang.JAVASCRIPT),
        ("web/App.jsx", Lang.JAVASCRIPT),
        ("web/app.ts", Lang.TYPESCRIPT),
        ("web/App.tsx", Lang.TSX),
        ("cmd/main.go", Lang.GO),
        ("src/lib.rs", Lang.RUST),
        ("src/Main.java", Lang.JAVA),
        ("www/index.php", Lang.PHP),
        ("lib/tool.rb", Lang.RUBY),
        ("SRC/MAIN.C", Lang.C),  # case-insensitive extensions
    ],
)
def test_extension(path, lang):
    assert detect_language(path) is lang


@pytest.mark.parametrize("path", ["README.md", "Makefile", "data.json", "noext", "x.h.orig"])
def test_unknown(path):
    assert detect_language(path) is None


def test_plain_header_is_c():
    head = b"#ifndef X_H\n#define X_H\nstruct s { int a; };\nint f(void);\n#endif\n"
    assert detect_language("include/x.h", head) is Lang.C


@pytest.mark.parametrize(
    "head",
    [
        b"#pragma once\nnamespace net {\nint f();\n}\n",
        b"#pragma once\nclass Widget {\npublic:\n  int x;\n};\n",
        b"template <typename T>\nT id(T v);\n",
        b"std::string name();\n",
        b"struct A {\nprivate:\n  int x;\n};\n",
    ],
)
def test_header_with_cpp_constructs_is_cpp(head):
    assert detect_language("include/x.h", head) is Lang.CPP


def test_header_override_from_config():
    assert detect_language("include/x.h", b"int f(void);\n", headers_are_cpp=True) is Lang.CPP


@pytest.mark.parametrize(
    ("head", "lang"),
    [
        (b"#!/usr/bin/env python3\nprint(1)\n", Lang.PYTHON),
        (b"#!/usr/bin/python\n", Lang.PYTHON),
        (b"#!/usr/bin/env node\nconsole.log(1)\n", Lang.JAVASCRIPT),
        (b"#!/usr/bin/env -S deno run\n", Lang.TYPESCRIPT),
        (b"#!/usr/bin/ruby -w\n", Lang.RUBY),
        (b"#!/usr/bin/php\n<?php\n", Lang.PHP),
    ],
)
def test_shebang(head, lang):
    assert detect_language("bin/tool", head) is lang


def test_shebang_does_not_override_extension():
    assert detect_language("tool.rb", b"#!/usr/bin/env python\n") is Lang.RUBY


@pytest.mark.parametrize(
    "head",
    [b"#!/bin/sh\necho hi\n", b"#!\n", b"#!\xff\xfe\x00garbage", b"", b"\x00\x01\x02"],
)
def test_unknown_or_garbage_script(head):
    assert detect_language("bin/tool", head) is None


def test_garbage_header_is_still_c():
    assert detect_language("x.h", b"\xff\xfe\x00\x00" * 1000) is Lang.C
