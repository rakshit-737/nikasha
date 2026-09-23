# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Command-line interface (SPEC §16.1). Commands are added milestone by milestone."""

from __future__ import annotations

import json
import os
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from nikasha.doctor import run_doctor
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
