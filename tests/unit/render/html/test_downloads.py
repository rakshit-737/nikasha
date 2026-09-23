# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The JSON download link and the page footer (SPEC §15.2).

The interesting tests here are about the ``data:`` URI, because a download link that
*looks* right and silently hands over half a file is worse than no link at all. So the
generated URI is decoded back and compared to the exact JSON, and the encoding is checked
for the two characters that corrupt a ``data:`` URI — a bare ``#``, which starts the
fragment and truncates everything after it, and a stray ``%``, which eats the next two
bytes. Report text contains both routinely.

The other invariant is determinism (P2): ``result.timings`` is the one field allowed to
differ between two runs of the same input, so neither the footer nor the embedded JSON may
contain it. :func:`test_timings_never_reach_the_page` renders two results that differ only
in their timings and requires identical bytes.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.result import Environment, ResolvedTarget, Result
from nikasha.model.verdict import Verdict
from nikasha.render.html.components import downloads
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.page import MAX_BYTES

REPORT = ingest_string("some report text", input_format="text", uri="reports/hdr.md")

#: A right-to-left override, spelled with `chr` so that formatting this file cannot
#: turn it back into a literal character ruff refuses to lint (PLE2502).
BIDI = chr(0x202E)

HOSTILE = (
    '</script><img src=x onerror=alert(1)>"><script>alert(1)</script>'
    " javascript:alert(1) \x1b[31mred\x1b[0m " + BIDI + "evresed " + "A" * 900
)

INLINE_HANDLER = re.compile(r"\son\w{1,20}\s*=")
HREF = re.compile(r'href="(data:[^"]{1,4000000})"')

#: Every `%` in the encoded payload must introduce a two-digit escape, and `#` must not
#: appear at all: those are the two ways a `data:` URI loses its tail.
PERCENT_OK = re.compile(r"\A(?:[^%]|%[0-9A-Fa-f]{2}){0,4000000}\Z")


def make_result(
    *,
    environment: Environment | None = None,
    target: ResolvedTarget | None = None,
    timings: dict[str, float] | None = None,
    tool_version: str = "0.4.0",
    report_text: str = "some report text",
    uri: str | None = "reports/hdr.md",
) -> Result:
    return Result(
        tool_version=tool_version,
        report=ingest_string(report_text, input_format="text", uri=uri),
        target=target
        if target is not None
        else ResolvedTarget(
            repo_url="https://example.invalid/libhdr",
            ref_name="v1.2.0",
            commit="3f2a9c1" * 5 + "abcde",
            method="tag from the report",
            confidence="high",
        ),
        verdict=Verdict(label="UNGROUNDED", score=4, confidence="high"),
        timings=timings if timings is not None else {"ingest": 0.01},
        environment=environment if environment is not None else Environment(mode="offline"),
    )


def fragment(**kwargs: object) -> Fragment:
    result = make_result(**kwargs)  # type: ignore[arg-type]
    out = downloads.render(HtmlContext(result=result, tool_version=result.tool_version))
    assert out is not None
    return out


def href_of(markup: str) -> str:
    match = HREF.search(markup)
    assert match is not None, "no data: download link in the footer"
    return match.group(1)


def payload_of(markup: str) -> str:
    uri = href_of(markup)
    head, _, encoded = uri.partition(",")
    assert head == "data:application/json"
    return unquote(encoded, encoding="utf-8", errors="strict")


# --- the data: URI ----------------------------------------------------------------------


def test_uri_decodes_back_to_exactly_the_result_json() -> None:
    result = make_result()
    out = downloads.render(HtmlContext(result=result, tool_version=result.tool_version))
    assert out is not None
    assert payload_of(out.html) == result.to_json(include_timings=False)


def test_decoded_payload_is_parseable_json_with_the_whole_result() -> None:
    data = json.loads(payload_of(fragment().html))
    assert data["verdict"]["label"] == "UNGROUNDED"
    assert data["target"]["repo_url"] == "https://example.invalid/libhdr"
    assert data["report"]["body"] == "some report text"
    assert "timings" not in data


def test_hash_and_percent_are_encoded() -> None:
    """A `#` would truncate the download; a bare `%` would corrupt the next two bytes."""
    body = "a # in the body, 50% of the time, and a fragment #L12-L18"
    out = fragment(report_text=body)
    _head, _, encoded = href_of(out.html).partition(",")
    assert "#" not in encoded
    assert PERCENT_OK.match(encoded), "a % that does not introduce an escape"
    assert body in json.loads(payload_of(out.html))["report"]["body"]


def test_whitespace_is_encoded_because_url_parsing_strips_it() -> None:
    _head, _, encoded = href_of(fragment().html).partition(",")
    for char in (" ", "\t", "\n", "\r"):
        assert char not in encoded


def test_encoding_survives_html_attribute_escaping_unchanged() -> None:
    """The safe set excludes every character `attr()` would turn into an entity."""
    out = fragment(report_text="quotes \" ' & angles < > equals = backtick `")
    uri = href_of(out.html)
    assert "&" not in uri and "&amp;" not in uri
    assert json.loads(payload_of(out.html))["report"]["body"].startswith("quotes")


def test_non_ascii_round_trips_as_utf8() -> None:
    out = fragment(report_text="café — 日本語 \U0001f600")
    assert json.loads(payload_of(out.html))["report"]["body"] == ("café — 日本語 \U0001f600")


def test_data_uri_helper_round_trips_awkward_text() -> None:
    raw = 'a#b%c "d" <e> &f\n\tg\ré\U0001f600+h/i?j'
    uri = downloads.data_uri(raw)
    assert unquote(uri.partition(",")[2], encoding="utf-8", errors="strict") == raw


# --- the link itself --------------------------------------------------------------------


def test_link_downloads_rather_than_navigates() -> None:
    out = fragment()
    assert 'download="nikasha-' in out.html
    assert out.html.count('href="data:application/json') == 1
    assert "Download JSON" in out.html


def test_download_filename_is_deterministic_and_inert() -> None:
    match = re.search(r'download="([^"]{1,120})"', fragment().html)
    assert match is not None
    name = match.group(1)
    assert re.fullmatch(r"nikasha-[A-Za-z0-9_-]{1,40}\.json", name), name


def test_size_label_is_shown() -> None:
    assert re.search(r"\d{1,4} (?:bytes|KB|MB)", fragment().html)


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 bytes"),
        (1023, "1023 bytes"),
        (1024, "1 KB"),
        (51_001, "50 KB"),
        (3_145_728, "3.0 MB"),
    ],
)
def test_human_bytes(count: int, expected: str) -> None:
    assert downloads._human_bytes(count) == expected


# --- the size budget --------------------------------------------------------------------


def test_budget_leaves_room_for_the_rest_of_the_page() -> None:
    assert 0 < downloads.URI_BUDGET < MAX_BYTES


def test_degrades_to_a_command_when_the_json_will_not_fit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(downloads, "URI_BUDGET", 50)
    out = fragment()
    assert "data:application/json" not in out.html
    assert "too large to embed" in out.html
    assert "--format json" in out.html
    assert "nikasha check reports/hdr.md" in out.html


def test_a_normal_result_fits_comfortably() -> None:
    out = fragment()
    assert len(out.html) < downloads.URI_BUDGET


# --- determinism (P2) -------------------------------------------------------------------


def test_timings_never_reach_the_page() -> None:
    # Values distinctive enough that they could not come from anywhere else on the page.
    fast = fragment(timings={"ingest": 0.1234567, "checks": 1122.334455})
    slow = fragment(timings={"ingest": 7.6543219, "checks": 9988.776655})
    assert fast.html == slow.html
    assert "timings" not in json.loads(payload_of(fast.html))
    assert "timings" not in href_of(fast.html)
    for number in ("1234567", "1122.334455", "9988.776655"):
        assert number not in fast.html


def test_rendering_twice_is_byte_identical() -> None:
    result = make_result()
    ctx = HtmlContext(result=result, tool_version=result.tool_version)
    first = downloads.render(ctx)
    second = downloads.render(ctx)
    assert first is not None and second is not None
    assert (first.html, first.css, first.js) == (second.html, second.css, second.js)


# --- the footer -------------------------------------------------------------------------


def test_footer_states_the_version_and_the_command() -> None:
    out = fragment(tool_version="1.2.3")
    assert "nikasha 1.2.3" in out.html
    assert (
        "nikasha check reports/hdr.md --repo https://example.invalid/libhdr "
        "--ref v1.2.0 --format html" in out.html
    )


def test_footer_states_that_nothing_touched_the_network() -> None:
    out = fragment()
    assert "produced offline" in out.html
    assert "no network request was made while checking" in out.html
    assert "this page makes none when you open it" in out.html


def test_footer_says_so_when_the_run_was_online() -> None:
    env = Environment(
        mode="online", fetched_urls=("https://example.invalid/advisory", "ftp://nope.invalid/x")
    )
    out = fragment(environment=env)
    assert "allowed network access" in out.html
    assert 'href="https://example.invalid/advisory"' in out.html
    # A scheme escaping cannot make safe is shown but never linked.
    assert 'href="ftp://nope.invalid/x"' not in out.html
    assert "ftp://nope.invalid/x" in out.html


def test_footer_names_the_sandbox_engine_when_one_ran() -> None:
    out = fragment(environment=Environment(mode="offline", sandbox_engine="podman"))
    assert "podman" in out.html


def test_footer_survives_a_result_with_no_target() -> None:
    out = fragment(target=None, uri=None)
    assert "nikasha check REPORT" in out.html
    assert "data:application/json" in out.html


# --- hostile input ----------------------------------------------------------------------


def test_hostile_target_and_source_are_inert() -> None:
    target = ResolvedTarget(
        repo_url='javascript:alert(1)"><script>alert(1)</script>',
        ref_name=HOSTILE,
        commit=None,
        method="guess",
        confidence="low",
    )
    out = fragment(target=target, uri=HOSTILE, tool_version=HOSTILE)
    markup = out.html
    assert "<img" not in markup
    assert "</script>" not in markup
    assert '"><script' not in markup
    assert "\x1b" not in markup
    assert BIDI not in markup
    # "onerror=" survives as inert character data; what matters is that no tag and no
    # attribute can be formed from it.
    assert "&lt;img src=x onerror=" in markup


def test_hostile_fetched_url_never_becomes_a_link() -> None:
    env = Environment(mode="online", fetched_urls=("javascript:alert(1)", HOSTILE))
    out = fragment(environment=env)
    assert 'href="javascript' not in out.html
    assert "<script" not in out.html
    assert "<img" not in out.html


def test_hostile_text_inside_the_payload_stays_percent_encoded() -> None:
    out = fragment(report_text=HOSTILE[:400])
    uri = href_of(out.html)
    assert "<" not in uri and ">" not in uri and '"' not in uri
    assert "script" in json.loads(payload_of(out.html))["report"]["body"]


def test_the_displayed_command_is_bounded() -> None:
    target = ResolvedTarget(
        repo_url="https://example.invalid/" + "x" * 5000,
        ref_name="v1.2.0",
        commit=None,
        method="guess",
        confidence="low",
    )
    out = fragment(target=target)
    code = re.search(r'<code class="dl-cmd">([^<]{0,5000})</code>', out.html)
    assert code is not None
    assert len(code.group(1)) <= downloads.MAX_COMMAND_CHARS + 1


# --- housekeeping -----------------------------------------------------------------------


def test_component_contract() -> None:
    assert downloads.ORDER == 95
    assert callable(downloads.render)


def test_emits_no_script_and_no_js() -> None:
    out = fragment()
    assert "<script" not in out.html
    assert out.js == ""
    assert INLINE_HANDLER.search(out.html) is None


def test_css_is_namespaced_and_themeable() -> None:
    out = fragment()
    selectors = re.findall(r"^\s{0,8}(\.[A-Za-z][\w-]{0,40})", out.css, re.MULTILINE)
    assert selectors
    assert all(name.startswith(".dl") for name in selectors), selectors
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", out.css) is None
    assert "var(--" in out.css
