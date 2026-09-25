# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Scoping, polarity and roles, including slopcheck's documented failure cases
(ADR 0003), rebuilt as our own fictional examples."""

import pytest
from helpers import claims, one

from nikasha.extract.polarity import span_is_negated
from nikasha.extract.scope import classify_path
from nikasha.model.report import Span


class TestSlopcheckFailureCases:
    def test_poc_quoted_code_is_the_reporters(self) -> None:
        # slopcheck rejected `void *ptr2 = realloc(ptr, len);`, the reporter's illustration.
        text = (
            "## PoC\n\n```c\n#include <stdlib.h>\n"
            "int main(void) { void *ptr2 = realloc(0, 8); }\n```\n"
        )
        assert claims(text, "symbol") == []
        assert one(text, "poc").provenance == "reporter_artifact"

    def test_third_party_frames_and_apis(self) -> None:
        c = one("The crash is inside `EVP_DigestUpdate()` from OpenSSL.", "symbol")
        assert c.provenance == "third_party"

    def test_negated_absence_statement(self) -> None:
        # "There is no `smb_conns_match` equivalent in `url_match_proto_config`."
        text = "There is no `smb_conns_match` equivalent in `url_match_proto_config`."
        found = {c.name: c for c in claims(text, "symbol")}
        assert found["smb_conns_match"].negated
        assert not found["url_match_proto_config"].negated

    def test_bare_line_is_not_bound_to_a_distant_path(self) -> None:
        text = "The file lib/vauth/ntlm.c is involved.\n\nThe crash is at line 245 of the parser."
        line = one(text, "line")
        assert line.path is None

    def test_path_missing_prefix_is_still_a_project_claim(self) -> None:
        # `vauth/ntlm.c` (without lib/) is a real file; resolution by suffix happens in M2.
        c = one("The issue is in vauth/ntlm.c when parsing.", "file")
        assert c.provenance == "project_attributed"


class TestPolarity:
    @pytest.mark.parametrize(
        ("text", "negated"),
        [
            ("There is no `foo_bar` function in this release.", True),
            ("No such option `--foo-bar` exists.", True),
            ("The function `foo_bar()` does not exist.", True),
            ("`foo_bar` is missing.", True),
            ("`foo_bar` is not defined in the header.", True),
            ("`foo_bar()` is missing a bounds check.", False),
            ("`foo_bar()` is missing bounds checks.", False),
            ("`foo_bar()` copies without checking the length.", False),
            ("The function `foo_bar()` overflows.", False),
            ("It calls `foo_bar()` without a check.", False),
        ],
    )
    def test_negation_cues(self, text: str, negated: bool) -> None:
        found = [c for c in claims(text) if c.kind in ("symbol", "option")]
        assert found
        assert found[0].negated is negated

    def test_negated_only_if_every_mention_is(self) -> None:
        c = one("There is no `foo_bar` here. But `foo_bar()` overflows elsewhere.", "symbol")
        assert not c.negated

    def test_span_is_negated_window(self) -> None:
        body = "we see there is no " + "x " * 40 + "foo_bar here"
        start = body.index("foo_bar")
        assert not span_is_negated(body, Span(start=start, end=start + 7, text="foo_bar"))

    def test_negated_claims_are_supporting(self) -> None:
        c = one("# Crash\n\nThere is no `foo_bar` function.", "symbol")
        assert c.negated
        assert c.role == "supporting"


class TestScope:
    @pytest.mark.parametrize(
        ("path", "provenance"),
        [
            ("lib/http.c", "project_attributed"),
            ("/usr/include/string.h", "third_party"),
            ("/tmp/x.c", "reporter_artifact"),
            ("/home/me/curl/lib/http.c", "unscoped"),
            (None, "unscoped"),
        ],
    )
    def test_classify_path(self, path: str | None, provenance: str) -> None:
        assert classify_path(path) == provenance

    def test_symbol_tied_to_product_name(self) -> None:
        c = one("A heap overflow in libhdr `hdr_decode_value()` leads to RCE.", "symbol")
        assert c.provenance == "project_attributed"

    def test_unattributed_symbol_is_unscoped(self) -> None:
        c = one("Later on, `some_helper` is used.", "symbol")
        assert c.provenance == "unscoped"

    def test_product_hint(self) -> None:
        c = one("Later on, `some_helper` is used by myproj.", "symbol", product="myproj")
        assert c.provenance == "project_attributed"

    def test_version_of_other_product(self) -> None:
        found = {
            c.product: c.provenance
            for c in claims("Tested with curl 8.5.0 and openssl 3.0.13.", "version", product="curl")
        }
        assert found == {"curl": "project_attributed", "openssl": "third_party"}


class TestRoles:
    def test_title_and_lead_symbols_are_core(self) -> None:
        text = (
            "# Overflow in `hdr_get()`\n\nThe `hdr_get()` function crashes.\n\n"
            "Later, `helper_fn` runs."
        )
        found = {c.name: c.role for c in claims(text, "symbol")}
        assert found == {"hdr_get": "core", "helper_fn": "supporting"}

    def test_bug_words_make_core(self) -> None:
        text = (
            "# Report\n\nIntro text here.\n\nMore text.\n\n"
            "A use-after-free happens in `free_ctx()`."
        )
        assert one(text, "symbol").role == "core"

    def test_peripheral_kinds(self) -> None:
        roles = {c.kind: c.role for c in claims("# T\n\nSee CVE-2024-0001 and CVSS 7.5 (High).")}
        assert roles == {"reference": "peripheral", "impact": "peripheral"}


class TestRealisticReportFindings:
    """Issues found by running extraction on the vulnlab fixture reports."""

    def test_html_comments_are_not_report_content(self) -> None:
        text = (
            "<!-- Template: describe the bug. See scripts/example.py and version 9.9.9 -->\n"
            "# Crash in `real_func()`\n\nText. <!-- inline note: `hidden_fn()` -->\n"
        )
        found = {(c.kind, getattr(c, "name", None)) for c in claims(text)}
        assert ("symbol", "real_func") in found
        assert all(kind not in ("file", "version") for kind, _ in found)
        assert ("symbol", "hidden_fn") not in found

    def test_unclosed_comment_runs_to_end(self) -> None:
        assert claims("Before `seen_fn()`.\n<!-- open comment `never_fn()`", "symbol")[0].name == (
            "seen_fn"
        )

    def test_comments_in_text_reports_are_kept(self) -> None:
        # Plain text is not rendered, so a literal "<!--" is just text.
        assert claims("<!-- `kept_fn()` -->", "symbol", fmt="text")[0].name == "kept_fn"

    def test_backticked_project_constant_is_only_an_option(self) -> None:
        text = "The buffer is `HDR_VALUE_MAX` bytes."
        assert claims(text, "symbol") == []
        assert one(text, "option").token == "HDR_VALUE_MAX"

    def test_data_file_names_are_not_symbols(self) -> None:
        assert claims("Save it as `poc.txt` and `crash.bin`, then run it.", "symbol") == []

    def test_program_name_attributes_symbols(self) -> None:
        c = one("It is reached from `hdrcat` through `hdr_parse_block()`.", "symbol")
        assert c.provenance == "project_attributed"
