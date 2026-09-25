# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import pytest
from helpers import claims, one

from nikasha.extract.paths import is_path_candidate
from nikasha.extract.symbols import looks_like_code


class TestSymbols:
    def test_inline_code_and_call_forms_merge(self) -> None:
        text = "The function `util_copy_value()` is broken; util_copy_value(dst) overflows."
        c = one(text, "symbol")
        assert c.name == "util_copy_value"
        assert c.symbol_kind_hint == "function"
        assert len(c.spans) == 2

    def test_phrases_require_code_looking_words(self) -> None:
        names = {
            c.name for c in claims("The macro BUF_LIMIT and the function parses input.", "symbol")
        }
        assert names == {"BUF_LIMIT"}
        macro = one("The macro BUF_LIMIT is wrong.", "symbol")
        assert macro.symbol_kind_hint == "macro"

    def test_project_constants_are_options_not_symbols(self) -> None:
        # HDR_ is libhdr's constant prefix, so HDR_MAX is an option claim (SPEC §9.7).
        text = "The macro HDR_MAX is wrong."
        assert claims(text, "symbol") == []
        assert one(text, "option").option_kind == "constant"

    @pytest.mark.parametrize(
        "text",
        [
            "Use `true` and `NULL` here.",  # stoplist
            "See `src/hdr.c` and `--fold`.",  # paths and options are not symbols
            "Run `hdrcat` or `curl`.",  # program and product names
            "It calls `ab`.",  # too short
            "Visit https://example.com/foo_bar(x).",  # inside a URL
        ],
    )
    def test_non_symbols(self, text: str) -> None:
        assert claims(text, "symbol") == []

    def test_qualified_names(self) -> None:
        names = {
            c.name
            for c in claims("Crash in `ns::Parser::read_line()` and `obj.close()`.", "symbol")
        }
        assert names == {"ns::Parser::read_line", "obj.close"}

    def test_external_apis_are_marked(self) -> None:
        c = one("The bug is a `memcpy()` without checks.", "symbol")
        assert c.external
        assert c.provenance == "third_party"
        assert c.role == "peripheral"

    def test_context_path(self) -> None:
        c = one("The function `hdr_get()` in `src/hdr.c` fails.", "symbol")
        assert c.context_path == "src/hdr.c"

    @pytest.mark.parametrize(
        ("name", "code"), [("foo_bar", True), ("fooBar", True), ("sha256", True), ("parses", False)]
    )
    def test_looks_like_code(self, name: str, code: bool) -> None:
        assert looks_like_code(name) is code

    def test_symbols_in_code_blocks_are_not_prose_symbols(self) -> None:
        text = "Intro.\n\n```sh\n$ ./hdrcat --fold poc_file(1)\n```\n"
        assert claims(text, "symbol") == []


class TestPaths:
    @pytest.mark.parametrize(
        ("path", "ok"),
        [
            ("src/hdr.c", True),
            ("config.h.in", True),
            ("lib/vauth/ntlm.c", True),
            ("Node.js", False),
            ("1.2.3", False),
            ("README", False),
            ("e.g", False),
            (".c", False),
        ],
    )
    def test_path_candidates(self, path: str, ok: bool) -> None:
        assert is_path_candidate(path) is ok

    def test_file_line_col(self) -> None:
        c = one("Crash at `src/hdr.c:412:12` in the parser.", "line")
        assert (c.path, c.line, c.col) == ("src/hdr.c", 412, 12)

    @pytest.mark.parametrize(
        "text",
        [
            "The bug is on line 77 of src/util.c when parsing.",
            "Look at src/util.c (line 77) please.",
            "Vulnerable code (src/util.c, line 77):",
            "See src/util.c at line 77.",
        ],
    )
    def test_path_bound_line_forms(self, text: str) -> None:
        c = one(text, "line")
        assert (c.path, c.line) == ("src/util.c", 77)

    def test_bare_line_without_path_stays_pathless(self) -> None:
        c = one("The crash happens at line 42 when input is long.", "line")
        assert c.path is None
        assert c.provenance == "unscoped"

    def test_bare_line_binds_to_single_path_in_clause(self) -> None:
        c = one("In util.c the overflow is at line 15.", "line")
        assert c.path == "util.c"

    def test_bare_line_with_two_paths_is_not_guessed(self) -> None:
        found = claims("Compare a.c and b.c around line 9.", "line")
        assert found[0].path is None

    def test_line_range(self) -> None:
        c = one("Lines 10-20 of src/x.c are wrong.", "line")
        assert (c.line, c.end_line) == (10, 20)

    def test_blob_permalink(self) -> None:
        url = "https://github.com/curl/curl/blob/curl-8_5_0/lib/http.c#L10-L20"
        c = one(f"See {url} for details.", "line")
        assert c.permalink is not None
        assert (c.permalink.owner, c.permalink.repo, c.permalink.ref) == (
            "curl",
            "curl",
            "curl-8_5_0",
        )
        assert (c.path, c.line, c.end_line) == ("lib/http.c", 10, 20)
        assert c.provenance == "project_attributed"

    def test_numbered_snippet_lines(self) -> None:
        text = "In src/x.c:\n\n```\n10 | int a;\n11 | a++;\n```\n"
        lines = [c for c in claims(text, "line") if c.quoted_line is not None]
        assert [(c.line, c.quoted_line, c.path) for c in lines] == [
            (10, "int a;", "src/x.c"),
            (11, "a++;", "src/x.c"),
        ]

    def test_file_claims_and_scoping(self) -> None:
        found = {
            c.path: c.provenance
            for c in claims("Files: lib/a.c, /usr/include/stdio.h, /tmp/poc.c", "file")
        }
        assert found == {
            "lib/a.c": "project_attributed",
            "/usr/include/stdio.h": "third_party",
            "/tmp/poc.c": "reporter_artifact",
        }

    def test_paths_in_urls_are_not_files(self) -> None:
        assert claims("See https://example.com/src/x.c for more.", "file") == []
