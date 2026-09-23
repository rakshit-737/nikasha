# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha check`` terminal view (SPEC §15.1).

Every test renders into a :class:`rich.console.Console` backed by a ``StringIO``. A real
stream would make the output depend on the encoding of whatever terminal happens to run
the suite — rich silently swaps box-drawing characters for ASCII when the stream cannot
encode them — and a view that renders differently on two machines is not reproducible (P2).

Two hazards get their own tests. Report text is hostile (P7): Rich markup, ANSI escapes,
newlines and unbounded strings must come out as inert text. And the wording is evidence
about claims, never about people (P1), so the output may not contain "AI", "slop", "fake"
or "fabricated".
"""

from __future__ import annotations

import io
import itertools
import re
from typing import Any, get_args

import pytest
from rich.console import Console

from nikasha.ingest import ingest_string
from nikasha.model.claims import (
    BehaviorClaim,
    ClaimBase,
    ClaimKind,
    FileClaim,
    Frame,
    ImpactClaim,
    LineClaim,
    OptionClaim,
    PatchClaim,
    PatchHunk,
    PatchLine,
    PocClaim,
    ReferenceClaim,
    SnippetClaim,
    SymbolClaim,
    TraceClaim,
    VersionClaim,
)
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import ResolvedTarget, Result
from nikasha.model.verdict import Question, Verdict
from nikasha.render.terminal import (
    EXIT_CODES,
    claim_label,
    decisive,
    exit_code,
    render_check,
    symbols,
)

WIDTH = 100

#: Claim spans are not checked against the body, so one span serves every fixture.
SPAN = Span(start=0, end=4, text="some")
REPORT = ingest_string("some text", input_format="text")

#: Rich markup, two ANSI escapes, a bell, a newline and a very long unbroken run (P7).
HOSTILE = "[bold red]pwned[/bold red] \x1b[31mred\x1b[0m \x07bell\r\nsecond line " + "A" * 400

#: Words that describe a person rather than a claim, or that guess at intent (P1).
BANNED_WORDS = ("slop", "fake", "fabricat")


def console(width: int = WIDTH) -> Console:
    """A recording console whose width and encoding do not depend on the host."""
    return Console(record=True, width=width, file=io.StringIO(), legacy_windows=False)


def render(result: Result, *, width: int = WIDTH, **kwargs: Any) -> str:
    out = console(width)
    render_check(out, result, **kwargs)
    return out.export_text()


def longest_line(text: str) -> int:
    return max((len(line.rstrip()) for line in text.splitlines()), default=0)


def evidence(
    eid: str,
    claim_id: str,
    *,
    outcome: str = "REFUTES",
    strength: float = -2.0,
    summary: str = "not defined in any release v1.0.0-v1.3.0",
    group: str = "symbol",
    check_id: str = "C03",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(claim_id,),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=summary,
    )


def make_result(
    *,
    claims: tuple[ClaimBase, ...] = (),
    items: tuple[Evidence, ...] = (),
    verdict: Verdict | None = None,
    target: ResolvedTarget | None = None,
) -> Result:
    return Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=claims,  # type: ignore[arg-type]
        evidence=items,
        verdict=verdict,
        target=target,
    )


def simple_result(
    label: str = "UNGROUNDED",
    score: int = 4,
    confidence: str = "high",
    *,
    questions: tuple[Question, ...] = (),
    name: str = "hdr_decode_chunked_value",
    summary: str = "not defined in any release v1.0.0-v1.3.0",
    source_target: bool = True,
) -> Result:
    claim = SymbolClaim(
        id="c1", spans=(SPAN,), extractor="test", confidence=1.0, role="core", name=name
    )
    target = (
        ResolvedTarget(
            repo_url="https://example.invalid/libhdr",
            ref_name="v1.2.0",
            commit="3f2a9c1e5b7d9f0a",
            method="declared version",
            confidence="high",
        )
        if source_target
        else None
    )
    return make_result(
        claims=(claim,),
        items=(evidence("e1", "c1", summary=summary),),
        verdict=Verdict(
            label=label,  # type: ignore[arg-type]
            score=score,
            confidence=confidence,  # type: ignore[arg-type]
            questions=questions,
            rule="3a: a core locus that never existed",
        ),
        target=target,
    )


def claim_of_every_kind() -> dict[str, ClaimBase]:
    """One claim per :data:`ClaimKind`, with every field the label reads populated."""
    common: dict[str, Any] = {"spans": (SPAN,), "extractor": "test", "confidence": 1.0}
    hunk = PatchHunk(
        path="src/hdr.c",
        source_start=400,
        source_length=1,
        target_start=400,
        target_length=2,
        lines=(PatchLine(op="+", text="    if (n > cap) return -1;"),),
    )
    return {
        "version": VersionClaim(id="k1", raw="1.2.0", relation="tested_on", **common),
        "symbol": SymbolClaim(id="k2", name="hdr_get", **common),
        "file": FileClaim(id="k3", path="src/hdr.c", **common),
        "line": LineClaim(id="k4", path="src/hdr.c", line=412, **common),
        "trace": TraceClaim(
            id="k5",
            format="asan",
            frames=(Frame(index=0, function="hdr_get", raw="#0 hdr_get"),),
            **common,
        ),
        "snippet": SnippetClaim(id="k6", code="memcpy(dst, src, n);", n_lines=1, **common),
        "patch": PatchClaim(
            id="k7", diff="--- a\n+++ b\n", files=("src/hdr.c",), hunks=(hunk,), **common
        ),
        "poc": PocClaim(id="k8", poc_kind="cli", **common),
        "reference": ReferenceClaim(id="k9", ref_kind="cve", value="CVE-2026-00001", **common),
        "option": OptionClaim(
            id="k10",
            token="--unsafe-fold",  # noqa: S106 - a CLI flag, not a credential
            option_kind="cli_flag",
            **common,
        ),
        "impact": ImpactClaim(id="k11", cvss_score=9.8, **common),
        "behavior": BehaviorClaim(
            id="k12", subject_symbol="hdr_get", predicate="missing_bounds_check", **common
        ),
    }


# --- verdicts and exit codes -------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "score", "confidence"),
    [
        ("GROUNDED", 88, "high"),
        ("REPRODUCED", 97, "high"),
        ("MIXED", 51, "medium"),
        ("UNGROUNDED", 4, "high"),
        ("INSUFFICIENT", 50, "low"),
    ],
)
def test_every_verdict_label_shows_label_score_and_confidence(
    label: str, score: int, confidence: str
) -> None:
    text = render(simple_result(label, score, confidence))
    assert label in text
    assert f"grounding {score}/100" in text
    assert f"confidence: {confidence}" in text


def test_a_result_without_a_verdict_says_so_instead_of_crashing() -> None:
    text = render(make_result())
    assert "no verdict was produced" in text


def test_a_verdict_with_no_checkable_claim_still_renders_a_row() -> None:
    text = render(make_result(verdict=Verdict(label="INSUFFICIENT", score=50, confidence="low")))
    assert "no claim could be checked" in text


@pytest.mark.parametrize(("label", "code"), sorted(EXIT_CODES.items()))
def test_exit_code_for_every_known_label(label: str, code: int) -> None:
    assert exit_code(label) == code


@pytest.mark.parametrize("label", ["ERROR", "unknown", "", "grounded"])
def test_exit_code_for_an_unknown_label_is_one(label: str) -> None:
    assert label not in EXIT_CODES
    assert exit_code(label) == 1


def test_exit_codes_match_the_spec_table() -> None:
    assert EXIT_CODES == {
        "GROUNDED": 0,
        "REPRODUCED": 0,
        "MIXED": 10,
        "UNGROUNDED": 20,
        "INSUFFICIENT": 30,
    }


# --- quiet, ascii and narrow terminals ---------------------------------------------------


def test_quiet_prints_only_the_verdict_line() -> None:
    result = simple_result(questions=(Question(text="Which commit?", rationale="why"),))
    text = render(result, quiet=True)
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "UNGROUNDED" in lines[0]
    assert "grounding 4/100" in lines[0]
    assert "confidence: high" in lines[0]
    # Nothing else from the full view leaks in.
    for absent in ("nikasha", "Report", "Target", "Claim", "Evidence", "Questions", "Full report"):
        assert absent not in text


def test_ascii_only_switches_the_status_symbols() -> None:
    marks = symbols(ascii_only=True)
    assert set(marks) == {"ok", "fail", "warn", "unknown"}
    assert all(mark.isascii() for mark in marks.values())
    assert marks != symbols(ascii_only=False)
    assert render(simple_result(), ascii_only=True, quiet=True).isascii()


def test_ascii_only_output_is_pure_ascii() -> None:
    """SPEC §15.1: --ascii must reach a stream that cannot encode anything else."""
    text = render(
        simple_result(questions=(Question(text="Which commit did you test?", rationale="r"),)),
        ascii_only=True,
    )
    assert text.isascii()


@pytest.mark.parametrize("width", [40, 60])
def test_narrow_terminals_keep_the_verdict_and_stay_inside_the_width(width: int) -> None:
    result = simple_result(questions=(Question(text="Which commit did you test?", rationale="r"),))
    text = render(result, width=width)
    assert "UNGROUNDED" in text
    assert "grounding" in text
    assert "4/100" in text
    assert "confidence" in text
    assert longest_line(text) <= width


# --- decisive ----------------------------------------------------------------------------


def test_decisive_picks_the_strongest_evidence_for_the_claim() -> None:
    items = [
        evidence("e1", "c1", outcome="SUPPORTS", strength=0.5),
        evidence("e2", "c1", outcome="SUPPORTS", strength=2.5),
        evidence("e3", "c1", outcome="REFUTES", strength=-1.0),
        evidence("e4", "other", outcome="REFUTES", strength=-9.0),
    ]
    chosen = decisive(items, "c1")
    assert chosen is not None
    assert chosen.id == "e2"


def test_decisive_returns_none_when_nothing_is_about_the_claim() -> None:
    assert decisive([evidence("e1", "c1")], "c2") is None
    assert decisive([], "c1") is None


def test_decisive_prefers_a_refutation_at_equal_strength() -> None:
    # The IDs are chosen so the ID tie-break alone would pick the supporting item.
    supports = evidence("aaa", "c1", outcome="SUPPORTS", strength=2.0, summary="found")
    refutes = evidence("zzz", "c1", outcome="REFUTES", strength=-2.0)
    for order in ([supports, refutes], [refutes, supports]):
        chosen = decisive(order, "c1")
        assert chosen is not None
        assert chosen.id == "zzz"


def test_decisive_is_deterministic_under_input_reordering() -> None:
    items = [
        evidence("e1", "c1", outcome="SUPPORTS", strength=1.5),
        evidence("e2", "c1", outcome="REFUTES", strength=-1.5),
        evidence("e3", "c1", outcome="NEUTRAL", strength=0.0),
        evidence("e4", "c1", outcome="REFUTES", strength=-1.5),
    ]
    first = decisive(items, "c1")
    assert first is not None
    assert first.id == "e2"
    for order in itertools.permutations(items):
        chosen = decisive(list(order), "c1")
        assert chosen is not None
        assert chosen.id == first.id


# --- claim labels ------------------------------------------------------------------------


#: The exact first column for each kind, pinned so a relabelling is a deliberate change.
EXPECTED_LABELS = {
    "version": 'version "1.2.0"',
    "symbol": "fn hdr_get()",
    "file": "file src/hdr.c",
    "line": "src/hdr.c:412",
    "trace": "trace (asan, 1 frames)",
    "snippet": "snippet (1 lines)",
    "patch": "patch (1 hunks)",
    "poc": "PoC (cli)",
    "reference": "cve CVE-2026-00001",
    "option": "option --unsafe-fold",
    "impact": "CVSS 9.8",
    "behavior": "hdr_get missing_bounds_check",
}


def test_claim_label_covers_every_claim_kind() -> None:
    claims = claim_of_every_kind()
    assert set(claims) == set(get_args(ClaimKind))
    assert len(claims) == 12
    assert set(EXPECTED_LABELS) == set(claims)
    for kind, claim in claims.items():
        label = claim_label(claim)
        assert label.strip(), kind
        assert "None" not in label, kind
        assert "\n" not in label, kind
        assert label == EXPECTED_LABELS[kind], kind


def test_a_line_claim_without_a_path_falls_back_to_the_line_number() -> None:
    claim = LineClaim(id="c1", spans=(SPAN,), extractor="test", confidence=1.0, path=None, line=412)
    assert claim_label(claim) == "line 412"


def test_claim_label_marks_core_claims() -> None:
    core = SymbolClaim(
        id="c1", spans=(SPAN,), extractor="test", confidence=1.0, role="core", name="hdr_get"
    )
    supporting = core.model_copy(update={"role": "supporting"})
    assert claim_label(core) == "core fn hdr_get()"
    assert claim_label(supporting) == "fn hdr_get()"


def test_every_claim_kind_reaches_the_rendered_table() -> None:
    claims = tuple(claim_of_every_kind().values())
    items = tuple(
        evidence(f"e{i}", claim.id, outcome="SUPPORTS", strength=1.0, summary="checked")
        for i, claim in enumerate(claims)
    )
    text = render(
        make_result(
            claims=claims,
            items=items,
            verdict=Verdict(label="MIXED", score=50, confidence="medium"),
        )
    )
    for claim in claims:
        head = claim_label(claim).split(" (")[0]
        assert head in text, claim.kind


# --- hostile input (P7) ------------------------------------------------------------------


def test_hostile_report_claim_and_evidence_text_is_inert() -> None:
    claim = SymbolClaim(
        id="c1", spans=(SPAN,), extractor="test", confidence=1.0, role="core", name=HOSTILE
    )
    result = make_result(
        claims=(claim,),
        items=(evidence("e1", "c1", summary=HOSTILE),),
        verdict=Verdict(
            label="UNGROUNDED",
            score=4,
            confidence="high",
            questions=(Question(text=HOSTILE, rationale="why"),),
        ),
    )
    text = render(result, source=HOSTILE)

    # The markup survives as literal text, which is exactly what "not interpreted" means:
    # had rich parsed it, the brackets would have been consumed into a style.
    assert "[bold red]" in text
    assert "[/bold red]" in text
    assert "pwned" in text
    # No escape, bell or carriage return reaches the terminal, and nothing overflows.
    for control in ("\x1b", "\x07", "\r"):
        assert control not in text
    assert longest_line(text) <= WIDTH


@pytest.mark.parametrize("width", [40, 60, WIDTH])
def test_hostile_input_never_crashes_at_any_width(width: int) -> None:
    claim = FileClaim(id="c1", spans=(SPAN,), extractor="test", confidence=1.0, path=HOSTILE)
    result = make_result(
        claims=(claim,),
        items=(evidence("e1", "c1", outcome="NEUTRAL", strength=0.0, summary=HOSTILE),),
        verdict=Verdict(label="MIXED", score=50, confidence="low", notes=(HOSTILE,)),
    )
    text = render(result, source=HOSTILE, width=width)
    assert text
    assert "\x1b" not in text
    assert longest_line(text) <= width


def test_hostile_resolved_target_is_inert() -> None:
    """P7: `method` quotes report text, so escapes must never reach the terminal."""
    target = ResolvedTarget(
        repo_url=HOSTILE,
        ref_name=HOSTILE,
        commit="3f2a9c1e5b7d9f0a",
        method=HOSTILE,
        confidence="low",
    )
    result = make_result(verdict=Verdict(label="MIXED", score=50, confidence="low"), target=target)
    text = render(result)
    assert "\x1b" not in text
    assert longest_line(text) <= WIDTH


def test_a_long_printable_resolved_target_folds_inside_the_width() -> None:
    """The target header wraps correctly; only control characters escape it."""
    target = ResolvedTarget(
        repo_url="https://example.invalid/" + "b" * 300,
        ref_name="v" + "1" * 300,
        commit="3f2a9c1e5b7d9f0a",
        method="declared " + "version " * 40,
        confidence="low",
    )
    result = make_result(verdict=Verdict(label="MIXED", score=50, confidence="low"), target=target)
    text = render(result)
    assert longest_line(text) <= WIDTH
    assert "3f2a9c1" in text


# --- wording (P1) ------------------------------------------------------------------------


def test_the_view_never_names_ai_or_calls_a_report_fake() -> None:
    claims = tuple(claim_of_every_kind().values())
    items = tuple(
        evidence(
            f"e{i}",
            claim.id,
            outcome="REFUTES",
            strength=-2.0,
            summary="not present in any release v1.0.0-v1.3.0",
        )
        for i, claim in enumerate(claims)
    )
    result = make_result(
        claims=claims,
        items=items,
        verdict=Verdict(
            label="UNGROUNDED",
            score=3,
            confidence="high",
            questions=(
                Question(text="Which commit did you test against?", rationale="r"),
                Question(text="Can you share the exact build command?", rationale="r"),
            ),
        ),
        target=ResolvedTarget(
            repo_url="https://example.invalid/libhdr",
            ref_name="v1.2.0",
            commit="3f2a9c1e5b7d9f0a",
            method="declared version",
            confidence="high",
        ),
    )
    for text in (
        render(result),
        render(result, quiet=True),
        render(result, ascii_only=True),
        render(result, width=40),
    ):
        lowered = text.lower()
        for word in BANNED_WORDS:
            assert word not in lowered
        assert re.search(r"\bAI\b", text) is None
