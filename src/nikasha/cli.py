# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Command-line interface (SPEC §16.1). Commands are added milestone by milestone."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from nikasha.doctor import run_doctor
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


def main() -> None:
    """Console-script entry point."""
    app()
