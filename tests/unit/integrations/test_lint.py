# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha lint`` (SPEC §16.1, P8): the reporter's pre-submit check.

Three contracts are pinned here. The wording is addressed to the person editing the draft
and never describes that person (P1): the whole rendered view, every friendly sentence and
every question is scanned for the words that would break this. No verdict label is
printed, because GROUNDED and UNGROUNDED are said about a submitted report by the
maintainer, not about a draft. And the exit code is non-zero only when something is
refuted: the genuine example against the real demo history exits 0, the one whose every
detail is wrong does not, and a run is byte-for-byte reproducible (P2).

The two pipeline runs are shared by the module; the CLI's own exit codes are exercised end
to end once per example, and the cheaper flags (``--json``, ``--ascii``) reuse the shared
run through a stubbed ``lint_report`` so the file stays inside the fast suite.
"""

from __future__ import annotations

import io
import json
import re
import shlex
import shutil
from pathlib import Path
from typing import Any

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from nikasha.fuse.questions import CLOSING
from nikasha.ingest import ingest_string
from nikasha.integrations import lint as lint_module
from nikasha.integrations.lint import (
    EXIT_OK,
    EXIT_REFUTED,
    LintReport,
    describe,
    exit_code_for,
    is_refuting,
    lint_report,
    plain,
    question_text,
    refutations,
    register,
    render_lint,
    row_item,
    where_of,
)
from nikasha.model.claims import LineClaim, SymbolClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import ResolvedTarget, Result
from nikasha.model.verdict import Question, Verdict

ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / "examples" / "reports"
GENUINE = "genuine_hdr_overflow"
CONTRADICTED = "fabricated_hdr_overflow"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

WIDTH = 100
SPAN = Span(start=0, end=4, text="some")
REPORT = ingest_string("some text", input_format="text")

#: The maintainer's words. None of them may appear in the view (whole words, upper case).
LABELS = re.compile(r"\b(?:REPRODUCED|GROUNDED|UNGROUNDED|MIXED|INSUFFICIENT)\b")

#: Words that describe a person or guess at how a draft was written (P1), on word
#: boundaries so "explain" and "detail" stay legal. Same list as the question tone tests.
BANNED = re.compile(
    r"\b(?:ai|llm|chatgpt|generated|fabricated|fake|lying|slop|bogus|hallucinat\w*)\b",
    re.IGNORECASE,
)
ACCUSATIONS = re.compile(
    r"\b(?:you claim|you claimed|you assert|you say|you said|falsely|made up|made-up|"
    r"invented|dishonest|untrue|nonsense|lie|lied)\b",
    re.IGNORECASE,
)

#: Rich markup, two ANSI escapes, a bell, a newline and a long unbroken run (P7).
HOSTILE = "[bold red]pwned[/bold red] \x1b[31mred\x1b[0m \x07bell\r\nsecond line " + "A" * 300


# --- fixtures and helpers ------------------------------------------------------------------


@pytest.fixture(scope="module")
def linted(vulnlab_repo: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, LintReport]:
    """Both examples linted once against the demo history, as the documented command does."""
    index_dir = tmp_path_factory.mktemp("lint-index")
    return {
        name: lint_report(
            REPORTS / f"{name}.md",
            repo=str(vulnlab_repo),
            version="1.2.0",
            index_path=index_dir / f"{name}.sqlite",
        )
        for name in (GENUINE, CONTRADICTED)
    }


def console(width: int = WIDTH) -> Console:
    """A recording console whose width and encoding do not depend on the host."""
    return Console(record=True, width=width, file=io.StringIO(), legacy_windows=False)


def render(report: LintReport | Result, *, width: int = WIDTH, **kwargs: Any) -> str:
    out = console(width)
    if isinstance(report, LintReport):
        render_lint(out, report.result, report.questions, **kwargs)
    else:
        render_lint(out, report, **kwargs)
    return out.export_text()


def flat(text: str) -> str:
    """The rendered text with Rich's word-wrapping undone, so a sentence can be searched for
    whole even when a table column or a panel folded it over several lines. Panel borders
    (``│`` or ``|`` at a line's edges) go too, since they sit between the folded pieces."""
    edges = "│|"
    lines = [line.strip().strip(edges).strip() for line in text.splitlines()]
    return " ".join(" ".join(lines).split())


def make_app() -> typer.Typer:
    """The command registered the way the orchestrator wires it, beside a second command
    so typer keeps the ``lint`` subcommand name instead of collapsing to a single command."""
    app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
    register(app)

    @app.command()
    def version() -> None:
        typer.echo("0.0.0-test")

    return app


def evidence(
    eid: str,
    claim_id: str | None = "c1",
    *,
    check_id: str = "C03",
    outcome: str = "REFUTES",
    strength: float = -3.0,
    summary: str = "hdr_decode_chunked_value is defined in none of the sampled releases",
    details: dict[str, Any] | None = None,
    group: str = "locus",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(claim_id,) if claim_id else (),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=summary,
        details=details or {},
    )


def target(commit: str | None = "3f2a9c1e5b7d9f0a") -> ResolvedTarget:
    return ResolvedTarget(
        repo_url="https://example.invalid/libhdr",
        ref_name="v1.2.0" if commit else None,
        commit=commit,
        method="declared version" if commit else "no version could be resolved",
        confidence="high" if commit else "low",
    )


def make_result(
    *,
    claims: tuple[Any, ...] = (),
    items: tuple[Evidence, ...] = (),
    resolved: ResolvedTarget | None = None,
    label: str = "MIXED",
) -> Result:
    return Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=claims,
        evidence=items,
        target=resolved,
        verdict=Verdict(label=label, score=50, confidence="low"),  # type: ignore[arg-type]
    )


def symbol_claim(
    cid: str = "c1", name: str = "hdr_decode_chunked_value", role: str = "core"
) -> Any:
    return SymbolClaim(
        id=cid,
        spans=(SPAN,),
        extractor="test",
        confidence=1.0,
        role=role,  # type: ignore[arg-type]
        name=name,
    )


# --- exit codes on the real examples -----------------------------------------------------------


def test_the_genuine_example_is_clean_and_exits_zero(linted: dict[str, LintReport]) -> None:
    report = linted[GENUINE]
    assert report.clean
    assert report.refuted == ()
    assert report.exit_code == EXIT_OK == 0
    assert exit_code_for(report.result.evidence) == EXIT_OK


def test_the_contradicted_example_is_refuted_and_exits_non_zero(
    linted: dict[str, LintReport],
) -> None:
    report = linted[CONTRADICTED]
    assert not report.clean
    assert report.exit_code == EXIT_REFUTED != 0
    assert EXIT_REFUTED != 1, "1 is reserved for errors"
    assert all(is_refuting(item) for item in report.refuted)
    # Strongest first: the core symbol that never existed leads.
    assert report.refuted[0].check_id == "C03"
    assert report.refuted == refutations(report.result.evidence)


def test_the_cli_exits_zero_for_the_genuine_example(
    vulnlab_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("COLUMNS", "120")
    result = CliRunner().invoke(
        make_app(),
        ["lint", str(REPORTS / f"{GENUINE}.md"), "--repo", str(vulnlab_repo), "--version", "1.2.0"],
    )
    assert result.exit_code == 0, result.output
    assert "Nothing in the draft is contradicted by the code at v1.2.0" in flat(result.output)
    assert not LABELS.search(result.output)


def test_the_cli_exits_non_zero_for_the_contradicted_example(
    vulnlab_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("COLUMNS", "120")
    result = CliRunner().invoke(
        make_app(),
        [
            "lint",
            str(REPORTS / f"{CONTRADICTED}.md"),
            "--repo",
            str(vulnlab_repo),
            "--version",
            "1.2.0",
        ],
    )
    assert result.exit_code == EXIT_REFUTED, result.output
    assert "We couldn't find hdr_decode_chunked_value() at v1.2.0" in flat(result.output)
    assert not LABELS.search(result.output)


def test_an_unreadable_draft_is_an_error_not_a_crash(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        make_app(), ["lint", str(tmp_path / "missing.md"), "--repo", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_an_error_naming_a_markup_looking_draft_is_still_one_line(tmp_path: Path) -> None:
    """The error message embeds the draft path; a path that reads as a Rich closing tag
    must print as text, not turn the one-line ``error:`` into a MarkupError traceback."""
    # A bare relative name: pathlib would turn the "/" into a separator on Windows.
    result = CliRunner().invoke(make_app(), ["lint", "[/b].md", "--repo", str(tmp_path)])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "error:" in result.output
    assert "[/b].md" in result.output
    assert "MarkupError" not in result.output


def test_the_rerun_hint_is_one_runnable_command(monkeypatch: pytest.MonkeyPatch) -> None:
    """A space or a shell metacharacter in a value is quoted, so the printed command does
    what the original one did when pasted back; plain values stay unquoted."""
    hint = lint_module._rerun_hint("my draft.md", "https://x/y; rm -rf /", None, "1.2.0", None)
    assert shlex.split(hint) == [
        "nikasha", "lint", "my draft.md", "--repo", "https://x/y; rm -rf /", "--version", "1.2.0",
    ]  # fmt: skip
    assert hint == "nikasha lint 'my draft.md' --repo 'https://x/y; rm -rf /' --version 1.2.0"
    assert lint_module._rerun_hint("d.md", "./r", "v1", None, "libhdr") == (
        "nikasha lint d.md --repo ./r --ref v1 --product libhdr"
    )
    assert lint_module._rerun_hint("-", None, None, None, None) == "nikasha lint -"
    # And the view prints that quoted form, clipped but with its quotes intact.
    fixture = make_result(claims=(symbol_claim(),), items=(evidence("e1"),), resolved=target())
    linted = LintReport(result=fixture, questions=(), refuted=refutations(fixture.evidence))
    monkeypatch.setattr(lint_module, "lint_report", lambda *a, **k: linted)
    monkeypatch.setenv("COLUMNS", "120")
    result = CliRunner().invoke(
        make_app(), ["lint", "my draft.md", "--repo", "https://x/y; rm -rf /", "--ascii"]
    )
    assert result.exit_code == EXIT_REFUTED
    assert "nikasha lint 'my draft.md' --repo 'https://x/y; rm -rf /'" in flat(result.output)


def test_a_bad_input_format_is_a_usage_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        make_app(), ["lint", str(tmp_path / "x.md"), "--input-format", "pdf"]
    )
    assert result.exit_code == 2
    assert "must be auto, markdown, text or html" in result.output


def test_register_adds_the_lint_command() -> None:
    result = CliRunner().invoke(make_app(), ["--help"])
    assert result.exit_code == 0
    assert "lint" in result.output
    result = CliRunner().invoke(make_app(), ["lint", "--help"])
    assert result.exit_code == 0
    for flag in ("--repo", "--ref", "--version", "--product", "--json", "--ascii", "--online"):
        assert flag in result.output


# --- json and ascii -------------------------------------------------------------------------


@pytest.mark.parametrize("name", [GENUINE, CONTRADICTED])
def test_json_emits_the_result_and_keeps_the_exit_code(
    linted: dict[str, LintReport], monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    fixture = linted[name]
    monkeypatch.setattr(lint_module, "lint_report", lambda *a, **k: fixture)
    result = CliRunner().invoke(make_app(), ["lint", "draft.md", "--repo", "x", "--json"])
    assert result.exit_code == fixture.exit_code
    payload = json.loads(result.stdout)
    assert Result.model_validate(payload) == fixture.result
    assert payload["verdict"] is not None, "the Result is the maintainer's document, whole"


@pytest.mark.parametrize("name", [GENUINE, CONTRADICTED])
def test_ascii_output_is_pure_ascii(linted: dict[str, LintReport], name: str) -> None:
    """SPEC §15.1: --ascii must reach a stream that cannot encode anything else."""
    text = render(linted[name], ascii_only=True, source="draft.md")
    assert text.isascii(), [line for line in text.splitlines() if not line.isascii()]
    assert "+" in text or "x" in text


def test_the_cli_ascii_flag_is_respected(
    linted: dict[str, LintReport], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = linted[CONTRADICTED]
    monkeypatch.setattr(lint_module, "lint_report", lambda *a, **k: fixture)
    result = CliRunner().invoke(make_app(), ["lint", "draft.md", "--repo", "x", "--ascii"])
    assert result.exit_code == EXIT_REFUTED
    assert result.output.isascii()
    assert "nikasha lint - before you submit" in result.output


def test_plain_maps_the_punctuation_the_templates_emit() -> None:
    en_dash, em_dash, dot = chr(0x2013), chr(0x2014), chr(0xB7)
    ellipsis, arrow = chr(0x2026), chr(0x2192)
    quotes = f"{chr(0x2018)}q{chr(0x2019)} {chr(0x201C)}q{chr(0x201D)}"
    fancy = f"v1.0.0{en_dash}v1.3.0 {em_dash} a {dot} b {ellipsis} {quotes} {arrow}"
    assert not fancy.isascii()
    assert plain(fancy, ascii_only=False) == fancy
    assert plain(fancy, ascii_only=True) == "v1.0.0-v1.3.0 - a - b ... 'q' \"q\" ->"
    assert plain(fancy, ascii_only=True).isascii()


# --- wording (P1) ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [GENUINE, CONTRADICTED])
def test_the_view_never_describes_the_reporter(linted: dict[str, LintReport], name: str) -> None:
    text = render(linted[name], source="draft.md", rerun="nikasha lint draft.md")
    assert not BANNED.search(text), BANNED.search(text)
    assert not ACCUSATIONS.search(text), ACCUSATIONS.search(text)


@pytest.mark.parametrize("name", [GENUINE, CONTRADICTED])
def test_every_finding_and_question_is_about_a_claim(
    linted: dict[str, LintReport], name: str
) -> None:
    report = linted[name]
    for item in report.result.evidence:
        sentence = describe(item, report.where)
        assert sentence.strip(), item.id
        assert "None" not in sentence, sentence
        assert not BANNED.search(sentence), sentence
        assert not ACCUSATIONS.search(sentence), sentence
    for question in report.questions:
        text = question_text(question)
        assert not BANNED.search(text), text
        assert not ACCUSATIONS.search(text), text


@pytest.mark.parametrize("name", [GENUINE, CONTRADICTED])
def test_no_verdict_label_is_printed(linted: dict[str, LintReport], name: str) -> None:
    text = render(linted[name], source="draft.md")
    assert not LABELS.search(text), LABELS.search(text)
    assert "verdict" in text  # the footer says whose word that is
    assert linted[name].result.verdict is not None  # but the Result still carries it


def test_the_contradicted_example_gets_second_person_findings(
    linted: dict[str, LintReport],
) -> None:
    text = flat(render(linted[CONTRADICTED], source="draft.md"))
    assert "We couldn't find hdr_decode_chunked_value() at v1.2.0" in text
    assert "so line 412 doesn't exist there" in text
    assert "What a maintainer would ask" in text
    assert "details don't match the code at v1.2.0" in text and "re-run" in text
    assert "before you submit" in text
    # The summary counts claims and the call to action repeats that number, never the
    # (larger) number of evidence items behind them.
    summary = re.search(r"Summary\s+(\d+) details don't match", text)
    assert summary is not None
    assert f"{summary.group(1)} details don't match the code at v1.2.0" in text
    # Every question is shown whole: a clipped question is a question nobody can answer.
    for question in linted[CONTRADICTED].questions:
        assert flat(question_text(question)) in text


def test_the_genuine_example_reads_as_clean(linted: dict[str, LintReport]) -> None:
    text = flat(render(linted[GENUINE], source="draft.md"))
    assert "Nothing in the draft is contradicted by the code at v1.2.0" in text
    assert "check out" in text
    assert "don't match" not in text


def test_the_closing_thanks_is_not_said_to_the_drafts_own_author(
    linted: dict[str, LintReport],
) -> None:
    report = linted[CONTRADICTED]
    assert report.questions, "the contradicted example must raise questions"
    for question in report.questions:
        assert question.text.endswith(CLOSING)
        assert not question_text(question).endswith(CLOSING)
        assert question_text(question).strip()
    assert CLOSING not in render(report, source="draft.md")


# --- determinism (P2) -----------------------------------------------------------------------


def test_a_fresh_run_is_byte_identical(
    linted: dict[str, LintReport], vulnlab_repo: Path, tmp_path: Path
) -> None:
    first = linted[GENUINE]
    second = lint_report(
        REPORTS / f"{GENUINE}.md",
        repo=str(vulnlab_repo),
        version="1.2.0",
        index_path=tmp_path / "again.sqlite",
    )
    assert first.result.to_json(include_timings=False) == second.result.to_json(
        include_timings=False
    )
    assert first.questions == second.questions
    assert first.refuted == second.refuted
    assert render(first, source="draft.md") == render(second, source="draft.md")


def test_rendering_the_same_report_twice_is_identical(linted: dict[str, LintReport]) -> None:
    report = linted[CONTRADICTED]
    assert render(report, source="draft.md") == render(report, source="draft.md")
    assert render(report, ascii_only=True) == render(report, ascii_only=True)


# --- the friendly table -----------------------------------------------------------------------


def test_a_missing_symbol_suggests_the_nearest_names() -> None:
    item = evidence(
        "e1",
        details={
            "outcome": "never_in_history_core",
            "symbol": "hdr_decode_chunked_value",
            "releases_searched": ["v1.0.0", "v1.1.0", "v1.2.0"],
            "suggestions": ["hdr_decode_value", "hdr_chunked"],
        },
    )
    text = describe(item, "v1.2.0")
    assert text.startswith("We couldn't find hdr_decode_chunked_value() at v1.2.0")
    assert f"(v1.0.0{chr(0x2013)}v1.2.0)" in text
    assert text.endswith("did you mean hdr_decode_value() and hdr_chunked()?")
    assert plain(text, ascii_only=True).isascii()


def test_a_missing_symbol_without_suggestions_says_what_to_do() -> None:
    item = evidence("e1", details={"outcome": "never_in_history_core", "symbol": "foo"})
    text = describe(item, "v1.2.0")
    assert "did you mean" not in text
    assert text.endswith("Check the spelling, or link to where it is defined.")


def test_a_symbol_defined_on_both_sides_of_the_target_is_listed_not_ranged() -> None:
    """``defined_in`` can straddle the target; "v1.0.0-v1.3.0" would include v1.2.0, the
    very version where the symbol is absent, so the releases are listed one by one."""
    item = evidence(
        "e1",
        strength=-1.0,
        details={
            "outcome": "absent_here_present_elsewhere",
            "symbol": "foo",
            "defined_in": ["v1.0.0", "v1.3.0"],
        },
    )
    text = describe(item, "v1.2.0")
    assert text == (
        "We couldn't find foo() at v1.2.0; it is defined in v1.0.0 and v1.3.0."
        " Were you testing one of those versions?"
    )
    assert chr(0x2013) not in text and "v1.0.0-v1.3.0" not in text
    single = item.model_copy(update={"details": {**item.details, "defined_in": ["v1.3.0"]}})
    assert "it is defined in v1.3.0." in describe(single, "v1.2.0")


def test_a_line_past_the_end_of_the_file() -> None:
    item = evidence(
        "e1",
        check_id="C04",
        strength=-1.5,
        details={"outcome": "past_end", "path": "src/hdr.c", "line": 412, "n_lines": 156},
    )
    assert describe(item, "v1.2.0") == (
        "src/hdr.c has 156 lines at v1.2.0, so line 412 doesn't exist there."
        " Re-check the line number against the version you tested."
    )


def test_a_trace_that_fits_another_release_asks_which_version() -> None:
    item = evidence(
        "e1",
        check_id="C10",
        strength=-0.3,
        details={"outcome": "other_release_fits", "best_release": "v1.2.0"},
    )
    assert describe(item, "v1.1.0") == (
        "The stack trace fits v1.2.0 exactly, but the draft names v1.1.0. Were you testing v1.2.0?"
    )


def test_missing_call_edges_are_listed() -> None:
    item = evidence(
        "e1",
        check_id="C09",
        strength=-2.0,
        details={
            "outcome": "missing_edge",
            "edges": [
                {"caller": "hdr_get", "callee": "util_copy_value", "kind": "none"},
                {"caller": "main", "callee": "hdr_get", "kind": "direct"},
            ],
        },
    )
    text = describe(item, "v1.2.0")
    assert "hdr_get -> util_copy_value" in text
    assert "main -> hdr_get" not in text


def test_missing_details_fall_back_to_the_summary() -> None:
    item = evidence("e1", details={"outcome": "never_in_history_core"})
    assert describe(item, "v1.2.0") == (
        "This doesn't match the code at v1.2.0:"
        " hdr_decode_chunked_value is defined in none of the sampled releases"
    )


def test_an_unknown_check_falls_back_by_outcome() -> None:
    refuted = evidence("e1", check_id="C99", summary="something is off")
    assert describe(refuted, "v1.2.0") == "This doesn't match the code at v1.2.0: something is off"
    error = evidence("e2", check_id="C99", outcome="ERROR", strength=0.0, summary="timed out")
    assert describe(error, "v1.2.0") == "This check couldn't run: timed out"
    supports = evidence("e3", check_id="C99", outcome="SUPPORTS", strength=1.0, summary="found")
    assert describe(supports, "v1.2.0") == "found"
    neutral = evidence("e4", check_id="C99", outcome="NEUTRAL", strength=0.0, summary="noted")
    assert describe(neutral, "v1.2.0") == "noted"


def test_a_gated_refutation_is_explained_and_not_counted() -> None:
    """ADR 0003: a finding about code the draft places elsewhere is shown, never counted."""
    item = evidence(
        "e1",
        outcome="NEUTRAL",
        strength=0.0,
        details={
            "outcome": "never_in_history_core",
            "symbol": "zlib_inflate",
            "gated": ["third_party"],
            "withheld_strength": -3.0,
        },
    )
    text = describe(item, "v1.2.0")
    assert text.startswith("We couldn't find zlib_inflate() at v1.2.0")
    assert text.endswith(
        "Not counted against the draft: the draft places it outside this repository."
    )
    assert not is_refuting(item)
    assert exit_code_for([item]) == EXIT_OK


def test_hygiene_names_what_the_draft_lacks() -> None:
    item = evidence(
        "e1",
        None,
        check_id="C21",
        outcome="NEUTRAL",
        strength=0.0,
        group="info",
        details={"outcome": "hygiene", "missing": ["poc", "version"]},
    )
    text = describe(item, "v1.2.0")
    assert "a proof of concept with the exact command" in text
    assert "the exact version or commit you tested" in text
    complete = item.model_copy(update={"details": {"outcome": "hygiene", "missing": []}})
    assert "everything a maintainer needs" in describe(complete, "v1.2.0")


def test_only_negative_refutes_count() -> None:
    assert is_refuting(evidence("e1", strength=-0.1))
    assert not is_refuting(evidence("e2", outcome="REFUTES", strength=0.0))
    assert not is_refuting(evidence("e3", outcome="SUPPORTS", strength=2.0))
    assert not is_refuting(evidence("e4", outcome="NEUTRAL", strength=0.0))
    assert exit_code_for([]) == EXIT_OK
    assert exit_code_for([evidence("e2", outcome="REFUTES", strength=0.0)]) == EXIT_OK
    assert exit_code_for([evidence("e5", outcome="SUPPORTS", strength=1.0), evidence("e6")]) == (
        EXIT_REFUTED
    )


def test_the_row_shows_the_refutation_even_when_support_is_stronger() -> None:
    items = [
        evidence("aaa", outcome="SUPPORTS", strength=3.0, summary="found"),
        evidence("zzz", strength=-0.5),
        evidence("mmm", strength=-1.0),
    ]
    chosen = row_item(items, "c1")
    assert chosen is not None
    assert chosen.id == "mmm"
    assert row_item([items[0]], "c1") is items[0]
    assert row_item(items, "other") is None


# --- the view on synthetic results ------------------------------------------------------------


def test_hostile_report_text_is_inert() -> None:
    claim = symbol_claim(name=HOSTILE)
    item = evidence("e1", summary=HOSTILE, details={})
    result = make_result(claims=(claim,), items=(item,), resolved=target())
    text = render(result, source=HOSTILE, rerun=HOSTILE)
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "pwned" in text  # the markup was printed, not interpreted
    assert max(len(line) for line in text.splitlines()) <= WIDTH


def test_an_unresolved_version_is_explained_and_exits_zero() -> None:
    result = make_result(
        claims=(symbol_claim(),), resolved=target(commit=None), label="INSUFFICIENT"
    )
    text = render(result, source="draft.md")
    assert "no version in the draft resolves to a release" in text
    assert "Add the exact version or commit you tested" in text
    assert "nothing here could be checked" in text
    assert exit_code_for(result.evidence) == EXIT_OK
    assert where_of(result) == "the version the draft names"
    assert not LABELS.search(text)


def test_where_of_prefers_the_ref_then_the_commit() -> None:
    assert where_of(make_result(resolved=target())) == "v1.2.0"
    bare = target().model_copy(update={"ref_name": None})
    assert where_of(make_result(resolved=bare)) == "commit 3f2a9c1e5b7d"
    assert where_of(make_result()) == "the version the draft names"


def test_problems_come_first_and_claimless_findings_are_labelled_the_draft() -> None:
    fine = symbol_claim("c1", "util_copy_value")
    wrong = LineClaim(
        id="c2", spans=(SPAN,), extractor="test", confidence=1.0, path="src/hdr.c", line=412
    )
    items = (
        evidence("e1", "c1", outcome="SUPPORTS", strength=1.0, summary="defined at v1.2.0"),
        evidence(
            "e2",
            "c2",
            check_id="C04",
            strength=-1.5,
            details={"outcome": "past_end", "path": "src/hdr.c", "line": 412, "n_lines": 156},
        ),
        evidence(
            "e3",
            None,
            check_id="C21",
            outcome="NEUTRAL",
            strength=0.0,
            group="info",
            details={"outcome": "hygiene", "missing": ["trace"]},
        ),
    )
    text = render(make_result(claims=(fine, wrong), items=items, resolved=target()), source="d.md")
    lines = text.splitlines()
    refuted = next(i for i, line in enumerate(lines) if "src/hdr.c:412" in line)
    unconfirmed = next(i for i, line in enumerate(lines) if line.startswith("the draft"))
    confirmed = next(i for i, line in enumerate(lines) if "core fn util_copy_value()" in line)
    # Problems first, then what could not be confirmed, then what checks out.
    assert refuted < unconfirmed < confirmed
    assert "1 detail doesn't match the code" in text
    assert "1 couldn't be confirmed" in text
    assert "1 checks out" in text
    # The call to action counts the same way the Summary line does: per claim, not per item.
    assert "1 detail doesn't match the code at v1.2.0" in flat(text)
    assert "fix it, or name the version you tested, then re-run" in flat(text)


def test_questions_are_numbered_and_the_verdict_word_is_absent_from_them() -> None:
    questions = (
        Question(text="Were you testing v1.2.0? Thanks.", rationale="r"),
        Question(text="Could you share a permalink?", rationale="r"),
    )
    result = make_result(claims=(symbol_claim(),), items=(evidence("e1"),), resolved=target())
    out = console()
    render_lint(out, result, questions, source="draft.md")
    text = out.export_text()
    assert "What a maintainer would ask (2)" in text
    assert "1. Were you testing v1.2.0?" in text
    assert "2. Could you share a permalink?" in text


@pytest.mark.parametrize("width", [40, 60])
def test_narrow_terminals_stay_inside_the_width(width: int) -> None:
    result = make_result(claims=(symbol_claim(),), items=(evidence("e1"),), resolved=target())
    text = render(result, width=width, source="draft.md", rerun="nikasha lint draft.md")
    assert max(len(line.rstrip()) for line in text.splitlines()) <= width
    assert "before you submit" in text
