# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The questions block and its "Copy as reply" button (SPEC §15.2).

Three properties get more attention here than anywhere else in the page.

**The wording is about claims, never about people (P1).** The questions themselves come
from fusion; what this module adds around them — a heading, a lead sentence, the preamble
of the pasted reply, the status messages — must not editorialise. :func:`test_tone_is_
neutral` scans the rendered markup for the words that would give that away.

**Everything interpolated is hostile (P7).** Question text, rationales and evidence
summaries are all derived from a report a stranger wrote, and they end up in three
different sinks: character data, an ``href`` fragment and the RCDATA content of a
``<textarea>``. Each is tested.

**The page must be byte-identical for one result (P2)**, so the block is rendered twice
and compared.
"""

from __future__ import annotations

import html as html_module
import re

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.evidence import Evidence
from nikasha.model.result import Result
from nikasha.model.verdict import Question, Verdict
from nikasha.render.html.components import questions_block
from nikasha.render.html.context import Fragment, HtmlContext

REPORT = ingest_string("some report text", input_format="text")

#: A tag that would close the script element, an event handler, an attribute breakout, a
#: URL scheme escaping cannot fix, an ANSI escape, a bidi override and a bloat run (P7).
#: A right-to-left override, spelled with `chr` so that formatting this file cannot
#: turn it back into a literal character ruff refuses to lint (PLE2502).
BIDI = chr(0x202E)

HOSTILE = (
    '</script><img src=x onerror=alert(1)>"><script>alert(1)</script>'
    " javascript:alert(1) \x1b[31mred\x1b[0m " + BIDI + "evresed " + "A" * 900
)

#: Words that describe a person or guess at intent rather than naming what was checked.
#: "ai" and "lying" are matched as whole words: "claim", "against", "detail" and
#: "underlying" all contain them as substrings and are perfectly neutral English.
BANNED_SUBSTRINGS = ("slop", "fake", "fabricat", "llm")
BANNED_WORDS = re.compile(r"\b(ai|lying)\b", re.IGNORECASE)

#: Inline event handler attributes, which the CSP would drop anyway. Checked against a
#: render of benign input: escaped report text may legitimately contain "onerror=" as
#: inert character data.
INLINE_HANDLER = re.compile(r"\son\w{1,20}\s*=")

TEXTAREA = re.compile(r"<textarea\b[^>]{0,400}>(.*?)</textarea>", re.DOTALL)


def evidence(eid: str, summary: str, *, check_id: str = "C03") -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=("c1",),
        outcome="REFUTES",
        strength=-2.0,
        group="locus",
        summary=summary,
    )


def context(
    *questions: Question,
    items: tuple[Evidence, ...] = (),
    label: str = "UNGROUNDED",
) -> HtmlContext:
    result = Result(
        tool_version="0.0.0-test",
        report=REPORT,
        evidence=items,
        verdict=Verdict(
            label=label,  # type: ignore[arg-type]
            score=4,
            confidence="high",
            questions=questions,
        ),
    )
    return HtmlContext(result=result, tool_version="0.0.0-test")


def fragment(*questions: Question, **kwargs: object) -> Fragment:
    out = questions_block.render(context(*questions, **kwargs))  # type: ignore[arg-type]
    assert out is not None
    return out


def textarea_text(markup: str) -> str:
    match = TEXTAREA.search(markup)
    assert match is not None, "the plain-text reply is missing"
    return html_module.unescape(match.group(1))


QUESTION = Question(
    text="Which release of libhdr contains hdr_decode_chunked_value()?",
    rationale="The symbol was not found in any release from v1.0.0 to v1.3.0.",
    evidence_ids=("e1",),
)
EVIDENCE = (evidence("e1", "never defined in any release v1.0.0-v1.3.0"),)


# --- nothing to show --------------------------------------------------------------------


def test_returns_none_without_a_verdict() -> None:
    result = Result(tool_version="0.0.0-test", report=REPORT)
    assert questions_block.render(HtmlContext(result=result)) is None


def test_returns_none_without_questions() -> None:
    assert questions_block.render(context()) is None


def test_empty_evidence_and_blank_fields_do_not_raise() -> None:
    out = fragment(Question(text="Which commit fixes it?", rationale="", evidence_ids=()))
    assert "Which commit fixes it?" in out.html
    assert "Why this is asked" not in out.html
    assert "Evidence:" not in out.html


# --- what it renders --------------------------------------------------------------------


def test_renders_every_question_with_its_rationale() -> None:
    second = Question(text="Which command shows the overflow?", rationale="No command given.")
    out = fragment(QUESTION, second, items=EVIDENCE)
    assert "Questions for the reporter (2)" in out.html
    assert "Which release of libhdr contains hdr_decode_chunked_value()?" in out.html
    assert "Which command shows the overflow?" in out.html
    assert "The symbol was not found in any release from v1.0.0 to v1.3.0." in out.html
    assert out.html.count("<li>") == 2
    assert "<ol" in out.html and 'id="questions"' in out.html


def test_cited_evidence_links_to_its_card() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert 'href="#ev-e1"' in out.html
    # The link text is the evidence summary, so the anchor says what it will show.
    assert "never defined in any release v1.0.0-v1.3.0</a>" in out.html


def test_unknown_evidence_id_is_not_a_dangling_link() -> None:
    out = fragment(Question(text="Where?", rationale="", evidence_ids=("nosuch",)), items=EVIDENCE)
    assert 'href="#ev-nosuch"' not in out.html
    assert "nosuch" in out.html  # still shown, as inert text


def test_question_count_is_capped_and_says_so() -> None:
    many = tuple(
        Question(text=f"Question {n}?", rationale="")
        for n in range(questions_block.MAX_QUESTIONS + 5)
    )
    out = fragment(*many)
    assert out.html.count("<li>") == questions_block.MAX_QUESTIONS
    assert f"Showing {questions_block.MAX_QUESTIONS} of {len(many)} questions" in out.html


def test_long_fields_are_bounded() -> None:
    out = fragment(Question(text="B" * 5000, rationale="C" * 5000))
    assert "B" * 5000 not in out.html
    assert "C" * 5000 not in out.html
    assert "…" in out.html
    assert len(out.html) < 5000


# --- the copy button --------------------------------------------------------------------


def test_reply_text_is_ready_to_paste() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    reply = textarea_text(out.html)
    assert reply.startswith(questions_block.INTRO)
    assert reply.endswith(questions_block.SIGNOFF)
    assert "1. Which release of libhdr contains hdr_decode_chunked_value()?" in reply
    assert "   Why this is asked: The symbol was not found" in reply
    assert "   Evidence: never defined in any release v1.0.0-v1.3.0" in reply
    assert "<" not in reply and ">" not in reply


def test_reply_numbers_every_question() -> None:
    reply = textarea_text(
        fragment(QUESTION, Question(text="And the commit?", rationale=""), items=EVIDENCE).html
    )
    assert "\n1. " in "\n" + reply
    assert "\n2. And the commit?" in reply


def test_button_carries_no_inline_handler() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert "<script" not in out.html
    assert INLINE_HANDLER.search(out.html) is None
    assert 'id="qb-copy"' in out.html
    assert 'type="button"' in out.html


def test_script_is_returned_as_js_and_attaches_by_listener() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert 'addEventListener("click"' in out.js
    # A single `<` in the script would let the HTML tokenizer end the element early.
    assert "<" not in out.js


def test_every_copy_path_ends_by_announcing_something() -> None:
    js = fragment(QUESTION, items=EVIDENCE).js
    # clipboard API, then execCommand, then "select it yourself" — and a status either way.
    assert "navigator.clipboard" in js
    assert 'document.execCommand("copy")' in js
    assert "source.select()" in js
    assert js.count("say(") >= 4
    assert "Copied. Paste it into your reply." in js
    assert "did not allow copying" in js


def test_status_region_is_announced_not_only_coloured() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert 'role="status"' in out.html
    assert 'aria-live="polite"' in out.html
    assert 'id="qb-status"' in out.html
    assert 'aria-describedby="qb-status"' in out.html
    # The colour is a second channel, never the only one.
    assert '.qb-status[data-state="ok"]' in out.css


def test_textarea_is_reachable_and_labelled() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert 'id="qb-source"' in out.html
    assert "readonly" in out.html
    assert "aria-label=" in out.html
    # The fallback opens the <details> before selecting: a hidden textarea cannot be.
    assert "reveal.open = true" in out.js


# --- hostile input ----------------------------------------------------------------------


def test_hostile_text_is_inert_everywhere() -> None:
    out = fragment(
        Question(text=HOSTILE, rationale=HOSTILE, evidence_ids=("e1",)),
        items=(evidence("e1", HOSTILE),),
    )
    markup = out.html
    assert "<img" not in markup
    assert "</script>" not in markup
    assert '"><script' not in markup
    assert "<script" not in markup
    assert "\x1b" not in markup
    assert BIDI not in markup
    assert "&lt;img src=x" in markup  # escaped, not silently dropped
    assert "A" * 500 not in markup


def test_hostile_text_cannot_escape_the_textarea() -> None:
    out = fragment(Question(text=HOSTILE, rationale=HOSTILE))
    body = TEXTAREA.search(out.html)
    assert body is not None
    assert "</textarea" not in body.group(1)
    assert "<" not in body.group(1)
    # And it survives unescaping as the original characters, so the paste is faithful.
    assert "</script>" in html_module.unescape(body.group(1))


def test_hostile_evidence_id_cannot_forge_an_attribute() -> None:
    hostile_id = 'e1" onmouseover="alert(1)'
    out = fragment(
        Question(text="Where?", rationale="", evidence_ids=(hostile_id,)),
        items=(evidence(hostile_id, "summary"),),
    )
    # css_ident keeps the letters but drops the quote and the `=`, so no attribute can
    # be formed: what is left is one inert identifier.
    assert INLINE_HANDLER.search(out.html) is None
    assert 'href="#ev-e1onmouseoveralert1"' in out.html


def test_javascript_url_in_a_summary_never_becomes_an_href() -> None:
    out = fragment(
        Question(text="Where?", rationale="", evidence_ids=("e1",)),
        items=(evidence("e1", "javascript:alert(1)"),),
    )
    assert 'href="javascript' not in out.html
    assert 'href="#ev-e1"' in out.html


# --- tone (P1) --------------------------------------------------------------------------


def test_tone_is_neutral() -> None:
    """The chrome around the questions may not editorialise about the reporter."""
    out = fragment(
        QUESTION, Question(text="Which commit?", rationale="No commit named."), items=EVIDENCE
    )
    for surface in (out.html, out.js, out.css):
        lowered = surface.lower()
        for word in BANNED_SUBSTRINGS:
            assert word not in lowered, f"{word!r} in {surface[:80]!r}"
        match = BANNED_WORDS.search(surface)
        assert match is None, f"{match.group(0)!r} appears in the rendered output"


@pytest.mark.parametrize(
    "constant", [questions_block.INTRO, questions_block.SIGNOFF, questions_block.LEAD]
)
def test_fixed_wording_is_neutral(constant: str) -> None:
    lowered = constant.lower()
    assert not any(word in lowered for word in BANNED_SUBSTRINGS)
    assert BANNED_WORDS.search(constant) is None


# --- determinism (P2) -------------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    ctx = context(QUESTION, Question(text=HOSTILE, rationale=HOSTILE), items=EVIDENCE)
    first = questions_block.render(ctx)
    second = questions_block.render(ctx)
    assert first is not None and second is not None
    assert (first.html, first.css, first.js) == (second.html, second.css, second.js)


def test_two_equal_results_render_equally() -> None:
    one = questions_block.render(context(QUESTION, items=EVIDENCE))
    two = questions_block.render(context(QUESTION, items=EVIDENCE))
    assert one is not None and two is not None
    assert one.html == two.html


def test_question_order_is_the_verdict_order() -> None:
    a = Question(text="Alpha?", rationale="")
    b = Question(text="Beta?", rationale="")
    forwards = fragment(a, b).html
    backwards = fragment(b, a).html
    assert forwards.index("Alpha?") < forwards.index("Beta?")
    assert backwards.index("Beta?") < backwards.index("Alpha?")


# --- housekeeping -----------------------------------------------------------------------


def test_component_contract() -> None:
    assert questions_block.ORDER == 80
    assert callable(questions_block.render)


def test_css_is_namespaced() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    selectors = re.findall(r"^\s{0,8}(\.[A-Za-z][\w-]{0,40})", out.css, re.MULTILINE)
    assert selectors, "no class selectors found"
    assert all(name.startswith(".qb") for name in selectors), selectors


def test_no_hard_coded_colours() -> None:
    out = fragment(QUESTION, items=EVIDENCE)
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", out.css) is None
    assert "var(--" in out.css
