# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Snippets, patches, PoCs and the commands inside them."""

import pytest
from helpers import claims, one

from nikasha.extract.patches import parse_leniently, parse_with_unidiff

GOOD_PATCH = """--- a/src/util.c
+++ b/src/util.c
@@ -26,6 +26,9 @@ char *util_copy_value(const char *value, size_t len)
     if (dst == NULL)
         return NULL;

+    if (len >= HDR_VALUE_MAX)
+        len = HDR_VALUE_MAX - 1;
+
     memcpy(dst, value, len);
     dst[len] = '\\0';
     return dst;
"""

BAD_COUNT_PATCH = """--- a/src/hdr.c
+++ b/src/hdr.c
@@ -410,6 +410,8 @@ static int f(void) {
     char tmp[64];
+    if (n > sizeof(tmp))
+        return HDR_ERR_TOO_LONG;
     memcpy(tmp, in, n);
"""


class TestPatches:
    def test_unidiff_parses_and_restores_blank_context(self) -> None:
        parsed = parse_with_unidiff(GOOD_PATCH)
        assert parsed is not None
        files, hunks = parsed
        assert files == ["src/util.c"]
        (hunk,) = hunks
        assert (hunk.source_start, hunk.source_length, hunk.target_length) == (26, 6, 9)
        assert sum(1 for line in hunk.lines if line.op == "+") == 3
        assert hunk.section_header is not None
        assert hunk.section_header.startswith("char *util_copy_value")

    def test_malformed_counts_fall_back_to_lenient(self) -> None:
        assert parse_with_unidiff(BAD_COUNT_PATCH) is None
        parsed = parse_leniently(BAD_COUNT_PATCH)
        assert parsed is not None
        files, hunks = parsed
        assert files == ["src/hdr.c"]
        assert [line.op for line in hunks[0].lines] == [" ", "+", "+", " "]

    def test_patch_claim_from_fence(self) -> None:
        c = one(f"Fix:\n\n```diff\n{GOOD_PATCH}```\n", "patch")
        assert c.files == ("src/util.c",)
        assert c.confidence > 0.9
        assert c.provenance == "project_attributed"

    def test_patch_in_plain_text(self) -> None:
        c = one("Suggested fix below.\n" + GOOD_PATCH + "\nThanks.", "patch", fmt="text")
        assert c.hunks[0].path == "src/util.c"

    def test_symbols_inside_patch_are_not_prose_claims(self) -> None:
        text = "Fix below.\n" + BAD_COUNT_PATCH
        assert claims(text, "symbol", fmt="text") == []


class TestSnippets:
    def test_attributed_snippet_and_definitions(self) -> None:
        text = (
            "Vulnerable code (src/hdr.c, line 412):\n\n```c\n"
            "static int hdr_decode(hdr_ctx *ctx, const char *in, size_t n) {\n"
            "    memcpy(tmp, in, n);\n}\n```\n"
        )
        snippet = one(text, "snippet")
        assert snippet.attributed_path == "src/hdr.c"
        assert snippet.n_lines == 3
        assert snippet.provenance == "project_attributed"
        symbol = one(text, "symbol")
        assert symbol.name == "hdr_decode"
        assert symbol.symbol_kind_hint == "function"

    def test_unattributed_snippet_is_unscoped(self) -> None:
        c = one("Something like this:\n\n```c\nx = y + 1;\n```\n", "snippet")
        assert c.attributed_path is None
        assert c.provenance == "unscoped"

    @pytest.mark.parametrize(
        ("code", "names"),
        [
            ("def parse_header(x):\n    return x", {"parse_header"}),
            ("async function readBody(req) {\n}", {"readBody"}),
            ("func (p *Parser) ParseLine(s string) error {\n}", {"ParseLine"}),
            ("pub fn decode_chunk(buf: &[u8]) {\n}", {"decode_chunk"}),
            ("#define HDR_LIMIT 64", {"HDR_LIMIT"}),
            ("int helper(int a);\nreturn helper(3);", set()),
            ("if (check(x)) {\n}", set()),
        ],
    )
    def test_definition_forms(self, code: str, names: set[str]) -> None:
        found = {c.name for c in claims(f"Code:\n\n```\n{code}\n```\n", "symbol")}
        assert found == names


class TestPocs:
    @pytest.mark.parametrize(
        ("block", "kind"),
        [
            ("```c\n#include <hdr.h>\nint main(void) { return 0; }\n```", "c_harness"),
            ("```python\nimport socket\n```", "python"),
            ("```console\n$ ./hdrcat --fold poc.txt\n```", "cli"),
            ("```sh\nmake\n./hdrcat poc.txt\n```", "shell"),
        ],
    )
    def test_kinds(self, block: str, kind: str) -> None:
        c = one(f"## Proof of concept\n\n{block}\n", "poc")
        assert c.poc_kind == kind
        assert c.provenance == "reporter_artifact"

    def test_file_input_under_poc_heading(self) -> None:
        c = one("## PoC\n\n```\nX-Overflow: AAAA\n```\n", "poc")
        assert c.poc_kind == "file_input"

    def test_entry_is_first_command(self) -> None:
        c = one("## Reproduce\n\n```console\n$ make\n$ ./hdrcat poc.txt\n```\n", "poc")
        assert c.entry == "make"


class TestOptionsFromCommands:
    def test_project_program_flags_are_project_claims(self) -> None:
        text = "## Reproduce\n\n```console\n$ ./hdrcat --fold poc.txt\n$ gcc --version\n```\n"
        found = {c.token: c.provenance for c in claims(text, "option")}
        assert found == {"--fold": "project_attributed", "--version": "third_party"}

    def test_prose_option(self) -> None:
        c = one("This can be triggered with the `--unsafe-fold` option of `hdrcat`.", "option")
        assert c.provenance == "project_attributed"
        assert c.role in {"core", "supporting"}

    def test_constants_and_config_keys(self) -> None:
        text = "Setting CURLOPT_HTTPHEADER with `http.proxy=on` crashes."
        found = {(c.token, c.option_kind) for c in claims(text, "option")}
        assert found == {("CURLOPT_HTTPHEADER", "constant"), ("http.proxy", "config_key")}
