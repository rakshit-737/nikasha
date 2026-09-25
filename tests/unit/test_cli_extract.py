# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from typer.testing import CliRunner

from nikasha.cli import app

runner = CliRunner()
SAMPLE = Path(__file__).parent / "extract" / "appendix_b_sample.md"


def test_extract_table_view() -> None:
    result = runner.invoke(app, ["extract", str(SAMPLE)], env={"COLUMNS": "160"})
    assert result.exit_code == 0, result.output
    assert "hdr_decode_chunked_value" in result.output
    assert "claims" in result.output


def test_extract_json_is_deterministic() -> None:
    first = runner.invoke(app, ["extract", str(SAMPLE), "--json"])
    second = runner.invoke(app, ["extract", str(SAMPLE), "--json"])
    assert first.exit_code == 0
    assert first.stdout == second.stdout
    data = json.loads(first.stdout)
    kinds = {c["kind"] for c in data["claims"]}
    assert {"symbol", "line", "option", "snippet", "patch", "impact", "version"} <= kinds
    assert "timings" not in data


def test_extract_stdin() -> None:
    result = runner.invoke(app, ["extract", "-", "--json"], input="`foo_bar()` overflows.\n")
    assert result.exit_code == 0
    assert json.loads(result.stdout)["claims"][0]["name"] == "foo_bar"


def test_extract_missing_file_is_a_clean_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["extract", str(tmp_path / "nope.md")])
    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_extract_bad_input_format() -> None:
    result = runner.invoke(app, ["extract", str(SAMPLE), "--input-format", "pdf"])
    assert result.exit_code != 0


def test_extract_records_svg(tmp_path: Path) -> None:
    svg = tmp_path / "view.svg"
    result = runner.invoke(app, ["extract", str(SAMPLE), "--record-svg", str(svg)])
    assert result.exit_code == 0
    assert svg.read_text(encoding="utf-8").startswith("<svg")


def test_report_markup_is_not_interpreted() -> None:
    result = runner.invoke(app, ["extract", "-"], input="[bold red]not markup[/] `foo_bar()`\n")
    assert result.exit_code == 0
    assert "[bold red]not markup[/]" in result.output


def test_json_output_survives_a_cp1252_console() -> None:
    result = CliRunner(charset="cp1252").invoke(app, ["extract", str(SAMPLE), "--json"])
    assert result.exit_code == 0, result.output
    assert "\u2014" in result.stdout_bytes.decode("utf-8")  # the em dash in the report
