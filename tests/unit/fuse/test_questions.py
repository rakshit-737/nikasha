# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Reporter questions (SPEC §14.4, Appendix D).

The tone tests are the point of this file. A wrong verdict is a bug; a question that
accuses a reporter of something is damage, and it is damage Nikasha does in the project's
name (P1). Each tone rule in SPEC §14.4 therefore gets its own test, over both the raw
templates and the text a reporter would actually receive.
"""

from __future__ import annotations

import functools
import re
from typing import Any

import pytest
from jinja2 import TemplateError, UndefinedError

from nikasha.fuse.questions import (
    CLOSING,
    MAX_QUESTIONS,
    TEMPLATE_DIR,
    known_templates,
    listed,
    questions_for,
    ranged,
    render_question,
    template_name,
)
from nikasha.fuse.verdict import Decision
from nikasha.model.claims import VersionClaim, VersionSpec
from nikasha.model.evidence import CodeLocation, Evidence
from nikasha.model.report import Span

# --- the words that must never reach a reporter ---------------------------------------------
#
# Nikasha compares claims with code. It has no evidence about who wrote a report or how, so
# it must never imply that it does, and it must never call a claim a lie. Matched on word
# boundaries: "ai" is banned as a word, not inside "explain" or "detail".
BANNED_WORDS = ("ai", "llm", "chatgpt", "generated", "fabricated", "fake", "lying", "slop", "bogus")
BANNED = re.compile(r"\b(?:" + "|".join(BANNED_WORDS) + r")\b", re.IGNORECASE)

#: Phrasings that turn a measurement into an allegation.
ACCUSATIONS = re.compile(
    r"\b(?:you claim|you claimed|you assert|you say|you said|falsely|made up|made-up|"
    r"invented|dishonest|untrue|nonsense|lie|lied|hallucinat\w*|bogus)\b",
    re.IGNORECASE,
)

#: SPEC §14.4: every question ends with the cheapest way to verify. One of these must be
#: named, or the reporter is being asked to guess what would help.
CHEAP_CHECKS = (
    "commit",
    "version",
    "permalink",
    "proof of concept",
    "command",
    "output",
    "release",
    "source location",
    "git diff",
)

#: The cases SPEC Appendix D spells out. Each one must have a template.
APPENDIX_D = (
    "C03.absent_here_present_elsewhere.j2",  # symbol missing, present in other versions
    "C03.never_in_history_core.j2",  # symbol never existed
    "C04.past_end.j2",  # line past EOF
    "C10.other_release_fits.j2",  # trace fits another version
    "C12.already_applied.j2",  # patch already applied
    "C21.hygiene.j2",  # missing PoC, version or trace
)

#: A context rich enough that every template can render. Deliberately one dict for all of
#: them: a template that needs something exotic should say so by failing here.
FULL_CONTEXT: dict[str, Any] = {
    "check_id": "C03",
    "outcome": "never_in_history_core",
    "group": "locus",
    "strength": -3.0,
    "verdict": "UNGROUNDED",
    "score": 4,
    "target": "libhdr 1.2.0 (commit 3f2a9c1b2d4e)",
    "where": "1.2.0",
    "project": "libhdr",
    "version": "1.2.0",
    "commit": "3f2a9c1b2d4e5f60",
    "short_sha": "3f2a9c1b2d4e",
    "details": {},
    "locations": [],
    "path": "src/hdr_parse.c",
    "line": 412,
    "n_lines": 300,
    "symbol": "hdr_parse_chunk",
    "function": "hdr_parse",
    "function_span": [100, 180],
    "actual_function": "hdr_read",
    "defined_in": ["1.0.0", "1.1.0", "1.1.2"],
    "releases_searched": ["1.0.0", "1.1.0", "1.2.0"],
    "suggestions": ["hdr_parse_chunked"],
    "history_gap": "the repository is a shallow clone",
    "version_fit_hint": {"release": "1.1.0", "commit": "a" * 40},
    "present_in": ["1.0.0", "1.1.0"],
    "other_releases": ["1.1.0"],
    "other_release": "1.1.0",
    "best_release": "1.1.0",
    "latest_release": "1.3.1",
    "caller": "hdr_read",
    "callee": "memcpy_safe",
    "option": "--with-hdr-fuzz",
    "missing": ["poc", "version", "trace"],
}

#: Only the keys :func:`nikasha.fuse.questions._context` guarantees for every evidence item.
MINIMAL_KEYS = (
    "check_id",
    "outcome",
    "group",
    "strength",
    "verdict",
    "score",
    "target",
    "where",
    "details",
    "locations",
)


#: SPEC Appendix D writes release ranges with an en dash.
EN_DASH = chr(0x2013)


def key_of(template: str) -> tuple[str, str]:
    """``"C03.never_in_history_core.j2"`` -> ``("C03", "never_in_history_core")``."""
    check_id, outcome = template.removesuffix(".j2").split(".", 1)
    return check_id, outcome


@functools.cache
def render_all() -> dict[str, str]:
    """Every template rendered with :data:`FULL_CONTEXT`."""
    return {name: render_question(*key_of(name), dict(FULL_CONTEXT)) for name in known_templates()}


# --- test data ------------------------------------------------------------------------------


def make_evidence(
    *,
    check_id: str = "C03",
    outcome_key: str = "never_in_history_core",
    strength: float = -3.0,
    group: str = "locus",
    details: dict[str, Any] | None = None,
    locations: tuple[CodeLocation, ...] = (),
    ident: str | None = None,
    outcome: str = "REFUTES",
) -> Evidence:
    payload = {"outcome": outcome_key} | (details or {})
    return Evidence(
        id=ident or f"{check_id}-{outcome_key}-{strength}",
        check_id=check_id,
        claim_ids=("claim0001",),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=f"{check_id}/{outcome_key}",
        details=payload,
        locations=locations,
    )


def location(path: str = "src/hdr_parse.c") -> CodeLocation:
    return CodeLocation(
        repo="https://github.com/example/libhdr.git",
        ref="v1.2.0",
        commit="3f2a9c1b2d4e5f60718293a4b5c6d7e8f9001122",
        path=path,
        start_line=412,
        end_line=412,
    )


def version_claim() -> VersionClaim:
    return VersionClaim(
        id="claim0001",
        spans=(Span(start=0, end=6, text="1.2.0 "),),
        extractor="test",
        confidence=1.0,
        role="core",
        provenance="project_attributed",
        product="libhdr",
        raw="1.2.0",
        relation="tested_on",
        parsed=VersionSpec(numbers=(1, 2, 0), raw="1.2.0"),
    )


def decision(label: str = "UNGROUNDED", **kwargs: Any) -> Decision:
    base: dict[str, Any] = {
        "label": label,
        "score": 4,
        "confidence": "high",
        "rule": "3a: a core locus that never existed",
    }
    return Decision(**(base | kwargs))  # type: ignore[arg-type]


# --- the templates themselves ------------------------------------------------------------------


def test_templates_are_present_and_named_by_check_and_outcome() -> None:
    names = known_templates()
    assert names, "no question templates were found"
    for name in names:
        check_id, outcome = key_of(name)
        assert re.fullmatch(r"C\d{2}", check_id), name
        assert re.fullmatch(r"[a-z0-9_]+", outcome), name


@pytest.mark.parametrize("name", APPENDIX_D)
def test_appendix_d_cases_all_have_a_template(name: str) -> None:
    assert name in known_templates()


@pytest.mark.parametrize("name", known_templates())
def test_every_template_renders_and_asks_something(name: str) -> None:
    text = render_question(*key_of(name), dict(FULL_CONTEXT))
    assert "?" in text, f"{name} asks nothing"
    assert text.endswith(CLOSING), f"{name} does not end with the closing line"
    assert "None" not in text, f"{name} rendered a missing value"
    assert "  " not in text, f"{name} rendered doubled whitespace"
    assert not re.search(r"\s[,.;:?!]", text), f"{name} left a space before punctuation"


@pytest.mark.parametrize("name", known_templates())
def test_every_template_carries_an_spdx_header(name: str) -> None:
    source = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    assert "SPDX-FileCopyrightText" in source
    # REUSE-IgnoreStart - the literal below is the tag under test, not this file's licence
    assert "SPDX-License-Identifier: Apache-2.0" in source
    # REUSE-IgnoreEnd


@pytest.mark.parametrize("name", known_templates())
def test_templates_render_or_skip_on_a_minimal_context(name: str) -> None:
    """A template may need more than the guaranteed keys, but it must fail, never guess."""
    minimal = {key: FULL_CONTEXT[key] for key in MINIMAL_KEYS}
    try:
        text = render_question(*key_of(name), minimal)
    except UndefinedError:
        return  # the run drops the question; that is the designed behaviour
    assert "None" not in text
    assert text.endswith(CLOSING)


# --- tone rule 1: neutral and specific ----------------------------------------------------------


@pytest.mark.parametrize("name", known_templates())
def test_every_question_names_something_concrete(name: str) -> None:
    text = render_all()[name]
    assert any(token in text.lower() for token in CHEAP_CHECKS), f"{name} is not specific: {text}"


def test_questions_address_the_claim_not_the_reporter() -> None:
    """Second-person verbs are fine ("you tested"); second-person blame is not."""
    for name, text in render_all().items():
        assert "you are" not in text.lower(), name
        assert "your report" not in text.lower(), name


# --- tone rule 2: no accusations ---------------------------------------------------------------


@pytest.mark.parametrize("name", known_templates())
def test_no_accusations_in_templates(name: str) -> None:
    source = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    assert not ACCUSATIONS.search(source), f"{name} accuses the reporter"


def test_no_accusations_in_rendered_questions() -> None:
    for name, text in render_all().items():
        found = ACCUSATIONS.search(text)
        assert found is None, f"{name} accuses the reporter: {found.group(0)!r}"


# --- tone rule 3: never about how the report was written ----------------------------------------


@pytest.mark.parametrize("name", known_templates())
def test_no_banned_words_in_template_source(name: str) -> None:
    source = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    found = BANNED.search(source)
    assert found is None, f"{name} contains the banned word {found.group(0)!r}"


def test_no_banned_words_in_rendered_questions() -> None:
    for name, text in render_all().items():
        found = BANNED.search(text)
        assert found is None, f"{name} rendered the banned word {found.group(0)!r}"


def test_no_banned_words_in_questions_from_the_pipeline() -> None:
    """The whole entry point, text and rationale, not just the templates."""
    evidence = [
        make_evidence(details={"symbol": "hdr_parse_chunk", "releases_searched": ["1.0.0"]}),
        make_evidence(
            check_id="C04",
            outcome_key="past_end",
            strength=-1.5,
            group="line",
            details={"path": "src/hdr_parse.c", "line": 412, "n_lines": 300},
            locations=(location(),),
        ),
        make_evidence(
            check_id="C21",
            outcome_key="hygiene",
            strength=0.0,
            group="hygiene",
            outcome="NEUTRAL",
            details={"missing": ["poc"]},
        ),
    ]
    questions = questions_for(decision(), evidence, [version_claim()])
    assert questions
    for question in questions:
        assert BANNED.search(question.text) is None, question.text
        assert BANNED.search(question.rationale) is None, question.rationale


# --- tone rule 4: always end with the cheapest way to verify -------------------------------------


@pytest.mark.parametrize("name", known_templates())
def test_every_question_ends_with_the_closing_line(name: str) -> None:
    text = render_all()[name]
    assert text.endswith(CLOSING)
    body = text[: -len(CLOSING)].strip()
    assert body, f"{name} is only the closing line"
    assert "?" in body, f"{name} closes without asking for anything"


def test_the_closing_line_is_never_duplicated() -> None:
    text = render_question("C04", "past_end", dict(FULL_CONTEXT))
    assert text.count(CLOSING) == 1


# --- the entry point ----------------------------------------------------------------------------


def test_questions_for_cites_the_evidence_behind_each_question() -> None:
    item = make_evidence(details={"symbol": "hdr_parse_chunk", "releases_searched": ["1.0.0"]})
    questions = questions_for(decision(), [item], [version_claim()])
    assert len(questions) == 1
    assert questions[0].evidence_ids == (item.id,)
    assert "hdr_parse_chunk" in questions[0].text
    assert "C03" in questions[0].rationale


def test_at_most_six_questions() -> None:
    evidence = [
        make_evidence(
            check_id="C04",
            outcome_key="past_end",
            strength=-1.5,
            group=f"line{n}",
            details={"path": f"src/f{n}.c", "line": 400 + n, "n_lines": 10},
            ident=f"e{n:03d}",
        )
        for n in range(12)
    ]
    questions = questions_for(decision("MIXED"), evidence, [version_claim()])
    assert len(questions) == MAX_QUESTIONS


def test_questions_are_ordered_by_how_much_they_would_move_the_verdict() -> None:
    weak = make_evidence(
        check_id="C05",
        outcome_key="outside_function",
        strength=-0.8,
        group="line",
        details={
            "path": "src/hdr_parse.c",
            "line": 412,
            "function": "hdr_parse",
            "function_span": [100, 180],
        },
        ident="e-weak",
    )
    strong = make_evidence(
        details={"symbol": "hdr_parse_chunk", "releases_searched": ["1.0.0"]}, ident="e-strong"
    )
    questions = questions_for(decision(), [weak, strong], [version_claim()])
    assert [q.evidence_ids for q in questions] == [("e-strong",), ("e-weak",)]


def test_the_evidence_the_verdict_turned_on_is_asked_about_first() -> None:
    """SPEC §14.3 rule 4: when the version cap fires, its question must be asked."""
    capped = make_evidence(
        check_id="C12",
        outcome_key="already_applied",
        strength=0.0,
        group="patch",
        outcome="NEUTRAL",
        details={"path": "src/hdr_parse.c"},
        ident="e-cap",
    )
    louder = make_evidence(
        check_id="C04",
        outcome_key="past_end",
        strength=-1.5,
        group="line",
        details={"path": "src/hdr_parse.c", "line": 412, "n_lines": 300},
        ident="e-loud",
    )
    verdict = decision(
        "MIXED",
        score=40,
        confidence="medium",
        rule="4: the evidence fits a different version than the report names",
        key_evidence=("e-cap",),
        capped=True,
    )
    questions = questions_for(verdict, [capped, louder], [version_claim()])
    assert len(questions) == 2
    assert questions[0].evidence_ids == ("e-cap",)


def test_identical_questions_are_merged_and_cite_every_source() -> None:
    first = make_evidence(
        check_id="C04",
        outcome_key="past_end",
        strength=-1.5,
        group="line",
        details={"path": "src/hdr_parse.c", "line": 412, "n_lines": 300},
        ident="e-001",
    )
    second = first.model_copy(update={"id": "e-002", "group": "other"})
    questions = questions_for(decision("MIXED"), [first, second], [version_claim()])
    assert len(questions) == 1
    assert questions[0].evidence_ids == ("e-001", "e-002")


def test_a_missing_template_is_skipped_silently() -> None:
    supported = make_evidence(
        check_id="C03", outcome_key="defined_core", strength=1.0, outcome="SUPPORTS"
    )
    unknown = make_evidence(check_id="C99", outcome_key="whatever", strength=-2.0)
    assert questions_for(decision("GROUNDED"), [supported, unknown], [version_claim()]) == ()


def test_evidence_the_check_could_not_produce_is_skipped() -> None:
    broken = make_evidence(
        check_id="C03",
        outcome_key="never_in_history_core",
        strength=0.0,
        outcome="ERROR",
        details={"error": "boom"},
    )
    incomplete = make_evidence(details={})  # no 'symbol': the template cannot render
    assert questions_for(decision(), [broken, incomplete], [version_claim()]) == ()


def test_output_is_deterministic_whatever_order_the_evidence_arrives_in() -> None:
    evidence = [
        make_evidence(
            check_id="C04",
            outcome_key="past_end",
            strength=-1.5,
            group=f"g{n}",
            details={"path": f"src/f{n}.c", "line": 9, "n_lines": 3},
            ident=f"e{n}",
        )
        for n in range(4)
    ]
    forwards = questions_for(decision("MIXED"), evidence, [version_claim()])
    backwards = questions_for(decision("MIXED"), list(reversed(evidence)), [version_claim()])
    assert forwards == backwards
    assert forwards == questions_for(decision("MIXED"), evidence, [version_claim()])


def test_the_target_is_named_from_the_evidence_when_claims_say_nothing() -> None:
    item = make_evidence(
        check_id="C04",
        outcome_key="past_end",
        strength=-1.5,
        group="line",
        details={"path": "src/hdr_parse.c", "line": 412, "n_lines": 300},
        locations=(location(),),
    )
    questions = questions_for(decision("MIXED"), [item], [])
    assert "v1.2.0" in questions[0].text


# --- strictness and safety -----------------------------------------------------------------------


def test_a_missing_variable_fails_loudly_rather_than_rendering_none() -> None:
    with pytest.raises(UndefinedError):
        render_question("C04", "past_end", {"where": "1.2.0", "path": "a.c", "line": 1})


def test_an_unknown_template_raises_for_direct_callers() -> None:
    with pytest.raises(TemplateError):
        render_question("C03", "no_such_outcome", dict(FULL_CONTEXT))


@pytest.mark.parametrize(
    "check_id,outcome",
    [("../etc", "passwd"), ("C03", "../../secret"), ("C03", "a b"), ("", "x"), ("C03", "")],
)
def test_template_keys_that_could_escape_the_directory_are_refused(
    check_id: str, outcome: str
) -> None:
    assert template_name(check_id, outcome) is None
    with pytest.raises(TemplateError):
        render_question(check_id, outcome, dict(FULL_CONTEXT))


# --- the small filters the templates lean on ------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [([], ""), (["1.0"], "1.0"), (["1.0", "1.2", "1.4"], f"1.0{EN_DASH}1.4"), ("1.0", "1.0")],
)
def test_ranged(value: object, expected: str) -> None:
    assert ranged(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ([], ""),
        (["a"], "a"),
        (["a", "b"], "a and b"),
        (["a", "b", "c"], "a, b and c"),
        (["a", "b", "c", "d"], "a, b, c and 1 other"),
        (["a", "b", "c", "d", "e"], "a, b, c and 2 others"),
    ],
)
def test_listed(value: object, expected: str) -> None:
    assert listed(value) == expected


def test_control_and_bidi_characters_never_reach_a_question() -> None:
    text = render_question(
        "C07", "absent_everywhere", {"target": "curl\x1b[2J\u202e 8.5.0\x07", "where": "8.5.0"}
    )
    assert "\x1b" not in text
    assert "\u202e" not in text
    assert "\x07" not in text
    assert "curl [2J 8.5.0" in text
