# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Command-line interface (SPEC §16.1). Commands are added milestone by milestone."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.table import Table

from nikasha.doctor import run_doctor

if TYPE_CHECKING:
    from nikasha.pipeline import CheckReport
    from nikasha.resolve.target import Resolution
from nikasha.errors import NikashaError
from nikasha.version import __version__

app = typer.Typer(
    name="nikasha",
    help="Proof, not prose. Fact-check vulnerability reports against the real code "
    "at the exact version they name.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)

_STATUS_STYLE = {"ok": "green", "warn": "yellow", "fail": "red"}
_UNICODE_SYMBOLS = {"ok": "✓", "warn": "~", "fail": "✗"}
_ASCII_SYMBOLS = {"ok": "+", "warn": "~", "fail": "x"}


def status_symbols(encoding: str | None, *, force_ascii: bool = False) -> dict[str, str]:
    """Pick status symbols the output stream can encode (SPEC §15.1 ``--ascii`` fallback).

    Legacy consoles (e.g. cp1252 on Windows) cannot encode ✓/✗, so fall back to ASCII.
    """
    if force_ascii:
        return _ASCII_SYMBOLS
    try:
        "".join(_UNICODE_SYMBOLS.values()).encode(encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return _ASCII_SYMBOLS
    return _UNICODE_SYMBOLS


@app.command()
def version() -> None:
    """Print the Nikasha version.

    Example:
        nikasha version
    """
    typer.echo(__version__)


@app.command()
def doctor(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON instead of a table.")
    ] = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="Use ASCII symbols only.")] = False,
) -> None:
    """Check the local environment: Python, git, cache directory and container engines.

    Makes no network calls. Exits 1 if a required check fails.

    Example:
        nikasha doctor
        nikasha doctor --json
    """
    report = run_doctor()
    if as_json:
        typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        console = Console()
        symbols = status_symbols(console.encoding, force_ascii=ascii_only)
        table = Table(title=f"nikasha {__version__} - doctor", title_justify="left")
        table.add_column("", width=1)
        table.add_column("Check")
        table.add_column("Detail", overflow="fold")
        for check in report.checks:
            style = _STATUS_STYLE[check.status]
            table.add_row(f"[{style}]{symbols[check.status]}[/]", check.name, check.detail)
        console.print(table)
        console.print(
            "[green]All required checks passed.[/]"
            if report.ok
            else "[red]A required check failed.[/]"
        )
    raise typer.Exit(code=0 if report.ok else 1)


@app.command()
def extract(
    report: Annotated[
        str, typer.Argument(help="Report file (Markdown, text or HTML), or - for stdin.")
    ],
    input_format: Annotated[
        str, typer.Option("--input-format", help="auto, markdown, text or html.")
    ] = "auto",
    product: Annotated[
        str | None, typer.Option("--product", help="Product name, e.g. curl or libhdr.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the claims as JSON.")] = False,
    record_svg: Annotated[
        str | None, typer.Option("--record-svg", hidden=True, help="Also save the view as SVG.")
    ] = None,
) -> None:
    """Show every claim Nikasha extracts from a report (a debugging view).

    Each claim is highlighted in the report by kind, then listed with its role (core,
    supporting, peripheral) and scope (whether it is a claim about the project at all).

    Example:
        nikasha extract examples/reports/fabricated_hdr_overflow.md
        nikasha extract report.md --json > claims.json
    """
    from nikasha.extract import extract_claims  # noqa: PLC0415 (keeps `nikasha version` fast)
    from nikasha.ingest import InputFormat, load_report  # noqa: PLC0415
    from nikasha.model.result import Result  # noqa: PLC0415
    from nikasha.render.extract_view import render_extract  # noqa: PLC0415

    if input_format not in ("auto", "markdown", "text", "html"):
        raise typer.BadParameter(
            "must be auto, markdown, text or html", param_hint="--input-format"
        )
    fmt: InputFormat = input_format  # type: ignore[assignment]
    try:
        loaded = load_report(report, input_format=fmt)
    except NikashaError as exc:
        _fail(exc)
    extraction = extract_claims(loaded, product=product)
    if as_json:
        loaded = loaded.model_copy(update={"warnings": loaded.warnings + extraction.warnings})
        result = Result(tool_version=__version__, report=loaded, claims=extraction.claims)
        _emit_utf8(result.to_json(include_timings=False))
        return
    svg_path = record_svg or os.environ.get("NIKASHA_RECORD_SVG")
    console = Console(record=bool(svg_path))
    render_extract(console, loaded, extraction.claims, extraction.warnings)
    if svg_path:
        console.save_svg(svg_path, title=f"nikasha extract {report}")


RepoOption = Annotated[str, typer.Option("--repo", help="Repository URL (https) or local path.")]
OnlineOption = Annotated[
    bool, typer.Option("--online", help="Allow network access (clone or refresh the repository).")
]
JsonOption = Annotated[bool, typer.Option("--json", help="Emit JSON instead of a table.")]


@app.command()
def index(
    repo: RepoOption,
    ref: Annotated[str | None, typer.Option("--ref", help="Git ref to index.")] = None,
    version: Annotated[str | None, typer.Option("--version", help="Release to index.")] = None,
    history: Annotated[
        bool, typer.Option("--history", help="Index every final release (full timeline).")
    ] = False,
    online: OnlineOption = False,
) -> None:
    """Clone (with --online) and index a repository for fast, offline checks.

    Example:
        nikasha index --repo https://github.com/curl/curl --online
        nikasha index --repo ./libhdr.git --history
    """
    from nikasha.code.index import CodeIndex  # noqa: PLC0415

    try:
        res = _resolve_repo(repo, ref=ref, version=version, online=online)
        console = Console()
        with res.repo, CodeIndex(res.repo) as idx:
            targets = (
                [(r.name, r.commit) for r in res.releases.finals()]
                if history
                else [
                    (res.target.ref_name or "HEAD", res.target.commit or res.repo.rev_parse("HEAD"))
                ]
            )
            table = Table(title=f"index {res.target.repo_url}", title_justify="left")
            for column in ("Ref", "Files", "Source files", "Parsed now", "Seconds"):
                table.add_column(column, justify="right" if column != "Ref" else "left")
            for name, commit in targets:
                if commit is None:
                    continue
                stats = idx.index_commit(commit)
                table.add_row(name, str(stats.files), str(stats.source_files),
                              str(stats.parsed_now), f"{stats.seconds:.1f}")  # fmt: skip
            console.print(table)
    except NikashaError as exc:
        _fail(exc)


@app.command()
def timeline(
    symbol: Annotated[str, typer.Argument(help="Function, macro or type name.")],
    repo: RepoOption,
    strategy: Annotated[str, typer.Option("--strategy", help="lazy or full.")] = "lazy",
    online: OnlineOption = False,
    as_json: JsonOption = False,
) -> None:
    """Show in which releases a symbol is defined (and suggest names if it never is).

    Example:
        nikasha timeline util_copy_value --repo ./libhdr.git
        nikasha timeline Curl_http_readwrite_headers --repo https://github.com/curl/curl
    """
    from nikasha.code.bktree import BKTree  # noqa: PLC0415
    from nikasha.code.index import CodeIndex  # noqa: PLC0415
    from nikasha.code.timeline import build_timeline  # noqa: PLC0415

    if strategy not in ("lazy", "full"):
        raise typer.BadParameter("must be lazy or full", param_hint="--strategy")
    try:
        res = _resolve_repo(repo, online=online)
        with res.repo, CodeIndex(res.repo) as idx:
            tl = build_timeline(idx, res.releases, symbol, strategy=strategy)  # type: ignore[arg-type]
            suggestions: list[str] = []
            finals = res.releases.finals()
            if not tl.ever_defined and finals:
                latest = finals[-1].commit
                idx.index_commit(latest)
                names = {row[0] for row in idx.db.execute("SELECT DISTINCT name FROM symbols")}
                suggestions = BKTree(sorted(names)).suggest(symbol)
    except NikashaError as exc:
        _fail(exc)
    if as_json:
        _emit_utf8(json.dumps({
            "symbol": symbol, "strategy": tl.strategy, "runs": tl.runs,
            "presence": [{"release": p.release, "defined": p.defined, "referenced": p.referenced,
                          "paths": list(p.paths), "partial": list(p.partial),
                          "uncertain": p.uncertain} for p in tl.presence],
            "uncertain_releases": tl.uncertain_releases,
            "history_complete": tl.history_complete, "never_in_history": tl.never_in_history,
            "suggestions": suggestions, "seconds": round(tl.seconds, 3), "notes": tl.notes,
        }, indent=2, sort_keys=True) + "\n")  # fmt: skip
        return
    console = Console()
    strip = "".join(
        "█" if p.defined else "?" if p.uncertain else "·" if p.referenced else " "
        for p in tl.presence
    )
    first = tl.presence[0].release if tl.presence else "-"
    last = tl.presence[-1].release if tl.presence else "-"
    console.print(f"[bold]{symbol}[/] across {len(tl.presence)} releases ({first} … {last})",
                  highlight=False)  # fmt: skip
    console.print(f"  [{strip}]", highlight=False)
    console.print(
        "  █ defined  ? mentioned in a file that did not parse cleanly  · mentioned",
        style="dim", highlight=False,
    )  # fmt: skip
    if tl.runs:
        for a, b in tl.runs:
            console.print(
                f"  defined in {a} to {b}" if a != b else f"  defined in {a}", highlight=False
            )
    else:
        console.print("  [red]no definition found in any release[/]", highlight=False)
        if tl.never_in_history:
            console.print(
                "  and the name never appears anywhere in the git history", highlight=False
            )
        if not tl.history_complete:
            console.print("  [yellow]history search incomplete:[/] " + "; ".join(tl.notes),
                          highlight=False)  # fmt: skip
        if suggestions:
            console.print("  did you mean: " + ", ".join(suggestions), highlight=False)
    if tl.uncertain_releases:
        console.print(
            f"  [yellow]uncertain in {len(tl.uncertain_releases)} release(s):[/] the name "
            "appears in files that did not parse cleanly, so a definition may have been missed",
            highlight=False,
        )  # fmt: skip
    console.print(f"  ({tl.strategy} strategy, {tl.seconds:.1f}s)", style="dim", highlight=False)


@app.command()
def trace(
    file: Annotated[str, typer.Argument(help="A file containing a stack trace (or a report).")],
    *,
    repo: RepoOption,
    version: Annotated[str | None, typer.Option("--version", help="Claimed release.")] = None,
    ref: Annotated[str | None, typer.Option("--ref", help="Git ref.")] = None,
    online: OnlineOption = False,
    as_json: JsonOption = False,
) -> None:
    """Check a stack trace against the code: files, lines, functions and call edges.

    Example:
        nikasha trace crash.txt --repo ./libhdr.git --version 1.2.0
    """
    from nikasha.code.index import CodeIndex  # noqa: PLC0415
    from nikasha.code.trace_forensics import analyze_trace  # noqa: PLC0415
    from nikasha.extract import extract_claims  # noqa: PLC0415
    from nikasha.ingest import load_report  # noqa: PLC0415
    from nikasha.model.claims import TraceClaim  # noqa: PLC0415

    try:
        report = load_report(file)
        traces = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
        if not traces:
            raise NikashaError(f"no stack trace found in {file}")
        res = _resolve_repo(repo, ref=ref, version=version, online=online)
        if res.target.commit is None:
            raise NikashaError("pass --version or --ref to choose the code to check against")
        with res.repo, CodeIndex(res.repo) as idx:
            analyses = [
                analyze_trace(idx, res.target.commit, t, project=res.project) for t in traces
            ]
    except NikashaError as exc:
        _fail(exc)
    if as_json:
        payload = [
            {"format": t.format, "commit": a.commit, "ratio": a.ratio,
             "frames": [f.__dict__ | {"generated": f.generated.reason if f.generated else None}
                        for f in a.frames],
             "edges": [{"caller": e.caller, "callee": e.callee, "kind": e.kind,
                        "caller_calls": e.caller_calls} for e in a.edges]}
            for t, a in zip(traces, analyses, strict=True)
        ]  # fmt: skip
        _emit_utf8(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return
    console = Console()
    ok, bad = ("✓", "✗") if status_symbols(console.encoding)["ok"] == "✓" else ("+", "x")
    for t, a in zip(traces, analyses, strict=True):
        table = Table(title=f"{t.format} trace at {res.target.ref_name} ({a.commit[:12]})",
                      title_justify="left")  # fmt: skip
        for column in ("#", "Function", "Claimed location", "File", "Line", "Function at line"):
            table.add_column(column)
        for f in a.frames:
            where = f"{f.claimed_path}:{f.line}" if f.line else str(f.claimed_path)
            file_cell = "generated" if f.generated else (ok if f.file_exists else bad)
            line_cell = (
                ""
                if f.line_in_bounds is None
                else (ok if f.line_in_bounds else f"{bad} (file has {f.n_lines})")
            )
            fn_cell = (
                ""
                if f.function_matches is None
                else (ok if f.function_matches else f"{bad} {f.actual_function or '(none)'}")
            )
            table.add_row(str(f.index), f.function or "", where, file_cell, line_cell, fn_cell)
        console.print(table)
        for e in a.edges:
            mark = ok if e.kind != "none" else bad
            detail = (
                ""
                if e.kind != "none"
                else f" ({e.caller} calls: {', '.join(e.caller_calls) or 'nothing'})"
            )
            console.print(f"  {mark} {e.caller} → {e.callee}: {e.kind}{detail}", highlight=False)
        ratio = "n/a" if a.ratio is None else f"{a.ratio:.0%}"
        console.print(f"  consistent frames: {ratio}", highlight=False)


@app.command()
def check(  # noqa: PLR0917 - a CLI command's options are its signature
    report: Annotated[
        str, typer.Argument(help="Report file (Markdown, text or HTML), or - for stdin.")
    ],
    repo: Annotated[
        str | None, typer.Option("--repo", help="Repository URL (https) or local path.")
    ] = None,
    ref: Annotated[
        str | None, typer.Option("--ref", help="Exact git ref to check against.")
    ] = None,
    version: Annotated[
        str | None, typer.Option("--version", help="Release the report is about, e.g. 8.5.0.")
    ] = None,
    product: Annotated[
        str | None, typer.Option("--product", help="Product name, e.g. curl or libhdr.")
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="terminal, json or markdown.")
    ] = "terminal",
    out: Annotated[
        str | None, typer.Option("--out", "-o", help="Write the output to a file instead.")
    ] = None,
    online: OnlineOption = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="ASCII symbols only.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Print only the verdict line.")] = False,
    explain: Annotated[
        bool, typer.Option("--explain", help="Also print the log-odds ledger.")
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero at this verdict or worse (for CI)."),
    ] = None,
    record_svg: Annotated[
        str | None, typer.Option("--record-svg", hidden=True, help="Also save the view as SVG.")
    ] = None,
) -> None:
    """Fact-check a vulnerability report against the code at the version it names.

    Exit codes: 0 GROUNDED/REPRODUCED, 10 MIXED, 20 UNGROUNDED, 30 INSUFFICIENT, 1 error.

    Example:
        nikasha check report.md --repo https://github.com/curl/curl
        nikasha check report.md --repo ./libhdr.git --format markdown -o reply.md
    """
    from nikasha.pipeline import check_report  # noqa: PLC0415
    from nikasha.render.explain_view import render_explain  # noqa: PLC0415
    from nikasha.render.terminal import render_check  # noqa: PLC0415

    if output_format not in ("terminal", "json", "markdown"):
        raise typer.BadParameter("must be terminal, json or markdown", param_hint="--format")
    try:
        checked = check_report(
            report, repo=repo, ref=ref, version=version, product=product, online=online
        )
    except NikashaError as exc:
        _fail(exc)

    if output_format == "terminal":
        svg_path = record_svg or os.environ.get("NIKASHA_RECORD_SVG")
        console = Console(record=bool(svg_path))
        render_check(
            console, checked.result, ascii_only=ascii_only, quiet=quiet, source=str(report)
        )
        if explain:
            render_explain(
                console, checked.ledger, checked.verdict, {e.id: e for e in checked.evidence}
            )
        if svg_path:
            console.save_svg(svg_path, title=f"nikasha check {report}")
    else:
        _write_out(_format_check(checked, output_format), out)

    raise typer.Exit(code=_check_exit_code(checked.verdict.label, fail_on))


def _format_check(checked: CheckReport, output_format: str) -> str:
    if output_format == "json":
        return checked.result.to_json()
    from nikasha.render.markdown import render_markdown  # noqa: PLC0415

    return render_markdown(checked)


def _write_out(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        _emit_utf8(text)


#: Verdicts ordered from best to worst, for ``--fail-on`` (SPEC §15.1).
_VERDICT_ORDER = ("GROUNDED", "REPRODUCED", "MIXED", "UNGROUNDED", "INSUFFICIENT")


def _check_exit_code(label: str, fail_on: str | None) -> int:
    from nikasha.render.terminal import exit_code  # noqa: PLC0415

    if not fail_on:
        return exit_code(label)
    wanted = fail_on.upper()
    if wanted not in _VERDICT_ORDER:
        raise typer.BadParameter(
            f"must be one of {', '.join(_VERDICT_ORDER)}", param_hint="--fail-on"
        )
    if label not in _VERDICT_ORDER:
        return 1
    return 1 if _VERDICT_ORDER.index(label) >= _VERDICT_ORDER.index(wanted) else 0


@app.command()
def explain(
    result_json: Annotated[
        str, typer.Argument(help="A RESULT.json from `nikasha check --format json`.")
    ],
) -> None:
    """Print the log-odds ledger behind a verdict: every strength, weight and contribution.

    Example:
        nikasha check report.md --repo ./libhdr.git --format json > result.json
        nikasha explain result.json
    """
    from nikasha.fuse.scoring import fuse  # noqa: PLC0415
    from nikasha.model.result import Result  # noqa: PLC0415
    from nikasha.render.explain_view import render_explain  # noqa: PLC0415

    try:
        data = json.loads(Path(result_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        Console(stderr=True).print(f"[red]error:[/] cannot read {result_json}: {exc}")
        raise typer.Exit(code=1) from exc
    result = Result.model_validate(data)
    if result.verdict is None:
        Console(stderr=True).print("[red]error:[/] that result carries no verdict")
        raise typer.Exit(code=1)
    ledger = fuse(result.evidence)
    render_explain(Console(), ledger, result.verdict, {e.id: e for e in result.evidence})


def _resolve_repo(
    repo: str, *, ref: str | None = None, version: str | None = None, online: bool = False
) -> Resolution:
    from nikasha.ingest import ingest_string  # noqa: PLC0415
    from nikasha.resolve.target import resolve_target  # noqa: PLC0415

    empty = ingest_string("", input_format="text")
    return resolve_target(empty, [], repo=repo, ref=ref, version=version, online=online)


def _emit_utf8(text: str) -> None:
    """Write machine output as UTF-8 bytes whatever the console encoding (e.g. cp1252)."""
    stream = sys.stdout
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(text)
    else:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()


def _fail(exc: NikashaError) -> typer.Exit:
    Console(stderr=True).print(f"[red]error:[/] {exc}", markup=True, highlight=False)
    raise typer.Exit(code=1)


def main() -> None:
    """Console-script entry point."""
    app()
