# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The local web UI's pages and flow (SPEC §16.4): New check, Result, History, ``serve``.

The hardening rules have their own file (``tests/security/test_web_hardening.py``); this
one checks that the pages do their job. The pipeline is replaced by a small stand-in so
the flow is fast and deterministic; one end-to-end test (marked ``slow``) runs the real
pipeline on the vulnlab demo history.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nikasha.errors import NikashaError
from nikasha.fuse.scoring import fuse
from nikasha.ingest import ingest_string
from nikasha.integrations import web as web_pkg
from nikasha.integrations.web import app as webapp
from nikasha.integrations.web import security
from nikasha.integrations.web.app import (
    CheckOutcome,
    History,
    create_app,
    report_policy,
)
from nikasha.model.result import ResolvedTarget, Result
from nikasha.model.verdict import Verdict
from nikasha.pipeline import CheckReport
from nikasha.render.html import render_html_result

PORT = 43122
ORIGIN = f"http://127.0.0.1:{PORT}"
ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / "examples" / "reports"


def fake_check_report(path: Path, **options: Any) -> CheckReport:
    text = Path(path).read_text(encoding="utf-8")
    report = ingest_string(text, input_format="text", uri=str(path))
    label = "UNGROUNDED" if "fabricated" in text else "GROUNDED"
    result = Result(
        tool_version="0.0.0-test",
        report=report,
        target=ResolvedTarget(
            repo_url=str(options.get("repo") or ""),
            ref_name=options.get("version") or options.get("ref") or "v1.2.0",
            commit="0123456789abcdef0123456789abcdef01234567",
            method="test",
            confidence="high",
        ),
        verdict=Verdict(label=label, score=88, confidence="high", rule="1a"),
    )
    return CheckReport(result=result, ledger=fuse(()), decision=None, runs=(), resolution=None)  # type: ignore[arg-type]


@pytest.fixture
def token() -> str:
    return security.make_token()


@pytest.fixture
def git_dir(tmp_path: Path) -> Path:
    bare = tmp_path / "repo.git"
    (bare / "objects").mkdir(parents=True)
    (bare / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return bare


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def spy(path: Path, **options: Any) -> CheckReport:
        seen.append({"path": Path(path), **options})
        return fake_check_report(path, **options)

    monkeypatch.setattr(webapp, "check_report", spy)
    return seen


@pytest.fixture
def client(
    token: str, calls: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> TestClient:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    return TestClient(
        create_app(token=token, port=PORT), base_url=ORIGIN, raise_server_exceptions=False
    )


def url(path: str, token: str) -> str:
    return f"{path}?token={token}"


def post(client: TestClient, token: str, data: dict[str, str], **kwargs: Any):
    return client.post(
        url("/checks", token),
        data=data,
        headers={"origin": ORIGIN},
        follow_redirects=False,
        **kwargs,
    )


# --- new check ------------------------------------------------------------------------------


def test_the_new_check_page_has_every_field(client: TestClient, token: str) -> None:
    html = client.get(url("/", token)).text
    for name in ("report_text", "report_file", "input_format", "repo", "version", "ref", "product"):
        assert re.search(rf'(name|id)="{name}"', html), name
    assert re.search(
        r'<input[^>]*name="online"[^>]*type="checkbox"|type="checkbox"[^>]*name="online"', html
    )
    assert re.search(r'<input[^>]*name="repro"[^>]*disabled', html)
    assert "M5" in html
    assert 'enctype="multipart/form-data"' in html
    assert f'action="/checks?token={token}"' in html


def test_a_pasted_report_is_checked_and_redirects_to_its_result(
    client: TestClient, token: str, git_dir: Path, calls: list[dict[str, Any]]
) -> None:
    response = post(client, token, {"report_text": "hdr_get overflows.\n", "repo": str(git_dir)})
    assert response.status_code == 303
    assert response.headers["location"] == url("/results/1", token)
    (call,) = calls
    assert call["repo"] == str(git_dir)
    assert call["path"].name == "report"  # no extension: the intake sniffs a paste
    assert call["online"] is False
    assert call["input_format"] == "auto"
    assert call["version"] is None and call["ref"] is None and call["product"] is None


def test_every_option_reaches_the_pipeline(
    client: TestClient, token: str, git_dir: Path, calls: list[dict[str, Any]]
) -> None:
    response = post(
        client,
        token,
        {
            "report_text": "hdr_get",
            "repo": str(git_dir),
            "version": "1.2.0",
            "ref": "v1.2.0",
            "product": "libhdr",
            "input_format": "markdown",
            "online": "1",
        },
    )
    assert response.status_code == 303
    (call,) = calls
    assert call["version"] == "1.2.0"
    assert call["ref"] == "v1.2.0"
    assert call["product"] == "libhdr"
    assert call["input_format"] == "markdown"
    assert call["online"] is True


def test_an_uploaded_file_keeps_a_known_extension_for_format_detection(
    client: TestClient, token: str, git_dir: Path, calls: list[dict[str, Any]]
) -> None:
    response = client.post(
        url("/checks", token),
        data={"repo": str(git_dir)},
        files={"report_file": ("crash report.MD", b"# hdr_get\n", "text/markdown")},
        headers={"origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    (call,) = calls
    assert call["path"].suffix == ".md"
    result = client.get(url("/results/1", token)).text
    assert "crash_report.MD" in result


def test_an_unknown_extension_lets_the_intake_sniff(
    client: TestClient, token: str, git_dir: Path, calls: list[dict[str, Any]]
) -> None:
    response = client.post(
        url("/checks", token),
        data={"repo": str(git_dir)},
        files={"report_file": ("report.eml.bak", b"hdr_get\n", "application/octet-stream")},
        headers={"origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert calls[0]["path"].suffix == ""


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"repo": "REPO"}, "Paste a report or upload one."),
        ({"report_text": "   \n", "repo": "REPO"}, "Paste a report or upload one."),
        ({"report_text": "hdr_get", "repo": "REPO", "input_format": "pdf"}, "format"),
        ({"report_text": "hdr_get", "repo": "REPO", "repro": "1"}, "M5"),
        ({"report_text": "hdr_get", "repo": "REPO", "version": "--evil"}, "version"),
        ({"report_text": "hdr_get", "repo": "REPO", "product": "a b"}, "product"),
        ({"report_text": "hdr_get", "repo": ""}, "repository is required"),
        ({"report_text": "hdr_get", "repo": "http://github.com/curl/curl"}, "https://"),
    ],
)
def test_invalid_submissions_re_render_the_form_with_a_message(
    client: TestClient,
    token: str,
    git_dir: Path,
    *,
    calls: list[dict[str, Any]],
    data: dict[str, str],
    fragment: str,
) -> None:
    data = {k: (str(git_dir) if v == "REPO" else v) for k, v in data.items()}
    response = post(client, token, data)
    assert response.status_code == 400
    assert fragment in response.text
    assert 'id="check-form"' in response.text, "the form comes back, not a bare error"
    assert calls == []


def test_text_and_file_together_are_refused(
    client: TestClient, token: str, git_dir: Path, calls: list[dict[str, Any]]
) -> None:
    response = client.post(
        url("/checks", token),
        data={"repo": str(git_dir), "report_text": "one"},
        files={"report_file": ("two.md", b"two", "text/markdown")},
        headers={"origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "not both" in response.text
    assert calls == []


def test_the_form_echoes_the_typed_fields_after_an_error(
    client: TestClient, token: str, git_dir: Path
) -> None:
    response = post(
        client,
        token,
        {
            "report_text": "the pasted text",
            "repo": "/nowhere",
            "version": "8.5.0",
            "product": "curl",
        },
    )
    assert response.status_code == 400
    assert 'value="/nowhere"' in response.text
    assert 'value="8.5.0"' in response.text
    assert 'value="curl"' in response.text
    assert ">the pasted text</textarea>" in response.text


def test_a_pipeline_error_comes_back_as_a_message_on_the_form(
    client: TestClient, token: str, git_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(path: Path, **options: Any) -> CheckReport:
        raise NikashaError("could not tell which repository this report is about")

    monkeypatch.setattr(webapp, "check_report", failing)
    response = post(client, token, {"report_text": "hdr_get", "repo": str(git_dir)})
    assert response.status_code == 400
    assert "could not tell which repository" in response.text
    assert f'value="{git_dir}"' in response.text, "the typed repository comes back"


def test_an_unexpected_failure_is_a_generic_500_page(
    client: TestClient, token: str, git_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def exploding(path: Path, **options: Any) -> CheckReport:
        raise ValueError("details that must not be shown")

    monkeypatch.setattr(webapp, "check_report", exploding)
    response = post(client, token, {"report_text": "hdr_get", "repo": str(git_dir)})
    assert response.status_code == 500
    assert "must not be shown" not in response.text
    assert "could not be completed" in response.text


def test_a_body_that_is_not_a_form_is_refused(
    client: TestClient, token: str, calls: list[dict[str, Any]]
) -> None:
    """A JSON body is an empty form to Starlette, so it fails validation like one."""
    response = client.post(
        url("/checks", token),
        content=b'{"repo": "x", "report_text": "hdr_get"}',
        headers={"origin": ORIGIN, "content-type": "application/json"},
    )
    assert response.status_code == 400
    assert "Paste a report" in response.text
    assert calls == []


def test_a_form_the_parser_rejects_is_a_400_page(
    client: TestClient, token: str, calls: list[dict[str, Any]]
) -> None:
    """More fields than the parser accepts: Starlette refuses the body, we show a page."""
    response = client.post(
        url("/checks", token),
        data={f"field{n}": "x" for n in range(40)},
        headers={"origin": ORIGIN},
    )
    assert response.status_code == 400
    assert "could not be read" in response.text
    assert calls == []


# --- result view ----------------------------------------------------------------------------


def test_the_result_page_shows_the_verdict_and_the_target(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert (
        post(client, token, {"report_text": "hdr_get\n", "repo": str(git_dir)}).status_code == 303
    )
    html = client.get(url("/results/1", token)).text
    assert "GROUNDED" in html
    assert "pasted report" in html
    assert "0123456789abcdef0123456789abcdef01234567" in html
    assert "v1.2.0" in html
    assert 'class="pill ok"' in html
    for suffix in ("/report", "/report.html", "/result.json"):
        assert url(f"/results/1{suffix}", token) in html


def test_the_report_page_is_the_self_contained_html_report(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert (
        post(client, token, {"report_text": "hdr_get\n", "repo": str(git_dir)}).status_code == 303
    )
    response = client.get(url("/results/1/report", token))
    assert response.status_code == 200
    assert response.text.startswith("<!doctype html>")
    assert "<title>Nikasha: GROUNDED</title>" in response.text
    assert "content-disposition" not in response.headers


def test_the_downloads_are_attachments(client: TestClient, token: str, git_dir: Path) -> None:
    assert (
        post(client, token, {"report_text": "hdr_get\n", "repo": str(git_dir)}).status_code == 303
    )
    html = client.get(url("/results/1/report.html", token))
    assert html.headers["content-disposition"] == 'attachment; filename="nikasha-result-1.html"'
    assert html.text == client.get(url("/results/1/report", token)).text
    data = client.get(url("/results/1/result.json", token))
    assert data.headers["content-type"] == "application/json"
    assert data.headers["content-disposition"] == 'attachment; filename="nikasha-result-1.json"'
    payload = json.loads(data.text)
    result = Result.model_validate(payload)
    assert result.verdict is not None and result.verdict.label == "GROUNDED"
    assert result.report.source.uri == "pasted report"


def test_the_same_paste_gives_the_same_json(client: TestClient, token: str, git_dir: Path) -> None:
    for _ in range(2):
        assert (
            post(client, token, {"report_text": "hdr_get\n", "repo": str(git_dir)}).status_code
            == 303
        )
    first = client.get(url("/results/1/result.json", token)).text
    second = client.get(url("/results/2/result.json", token)).text
    assert first == second


def test_an_unknown_result_is_a_404_page(client: TestClient, token: str) -> None:
    response = client.get(url("/results/7", token))
    assert response.status_code == 404
    assert "no such result" in response.text
    assert client.get(url("/results/7/report", token)).status_code == 404
    assert client.get(url("/results/7/result.json", token)).status_code == 404


def test_report_policy_is_the_page_s_meta_policy_plus_framing() -> None:
    report = ingest_string("hdr_get\n", input_format="text")
    result = Result(tool_version="0.0.0-test", report=report)
    html = render_html_result(result)
    policy = report_policy(html)
    assert policy.startswith("default-src 'none'")
    assert "script-src 'sha256-" in policy
    assert policy.endswith("; frame-ancestors 'self'")
    assert report_policy("<html></html>") == (
        "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'"
    )


# --- history --------------------------------------------------------------------------------


def test_the_history_lists_results_newest_first_and_purges(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert "No results yet" in client.get(url("/history", token)).text
    for text in ("first hdr_get\n", "second fabricated\n"):
        assert post(client, token, {"report_text": text, "repo": str(git_dir)}).status_code == 303
    html = client.get(url("/history", token)).text
    assert html.index("/results/2?") < html.index("/results/1?")
    assert "UNGROUNDED" in html and "GROUNDED" in html
    assert 'id="purge-form"' in html
    response = client.post(
        url("/history/purge", token), headers={"origin": ORIGIN}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == url("/history", token)
    assert "No results yet" in client.get(url("/history", token)).text
    assert client.get(url("/results/1", token)).status_code == 404


def outcome(source: str = "x") -> CheckOutcome:
    return CheckOutcome(
        source=source, verdict="MIXED", score=50, confidence="low", rule="3", repo="r",
        ref="v1", commit="c", html="<p>", json="{}", report_csp="default-src 'none'",
    )  # fmt: skip


def test_history_keeps_only_the_most_recent_entries() -> None:
    history = History(limit=2)
    ids = [history.add(outcome(str(n))).id for n in range(4)]
    assert ids == ["1", "2", "3", "4"]
    assert [e.id for e in history.entries()] == ["4", "3"]
    assert history.get("1") is None
    assert len(history) == 2
    assert history.purge() == 2
    assert history.entries() == []
    assert history.add(outcome()).id == "5", "ids are never reused after a purge"


def test_history_ids_do_not_change_when_older_entries_are_evicted() -> None:
    history = History(limit=1)
    first = history.add(outcome("a"))
    second = history.add(outcome("b"))
    assert history.get(first.id) is None
    assert history.get(second.id) is second


def test_the_outcome_css_class_follows_the_verdict() -> None:
    assert outcome().css_class == "warn"
    assert dataclasses.replace(outcome(), verdict="NOVEL").css_class == "unknown"


# --- the serve command ----------------------------------------------------------------------


def cli() -> typer.Typer:
    """A CLI with ``serve`` and one other command (a single-command Typer app takes no
    subcommand name, which is not how ``nikasha`` is laid out)."""
    app = typer.Typer()
    web_pkg.register(app)
    app.command(name="other")(lambda: None)
    return app


def test_register_adds_serve_to_a_typer_app() -> None:
    result = CliRunner().invoke(cli(), ["serve", "--help"])
    assert result.exit_code == 0
    assert "127.0.0.1" in result.output
    assert "--port" in result.output
    assert "--host" not in result.output


def test_serve_reports_a_missing_extra_as_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys  # noqa: PLC0415

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    result = CliRunner().invoke(cli(), ["serve"])
    assert result.exit_code == 1
    assert "nikasha[web]" in result.output


def test_serve_refuses_a_port_out_of_range() -> None:
    assert CliRunner().invoke(cli(), ["serve", "--port", "70000"]).exit_code != 0
    assert CliRunner().invoke(cli(), ["serve", "--port", "-1"]).exit_code != 0


def test_the_static_assets_are_served_with_their_types(client: TestClient, token: str) -> None:
    css = client.get(url("/static/ui.css", token))
    assert css.headers["content-type"].startswith("text/css")
    assert ":root" in css.text and ".form-grid" in css.text
    js = client.get(url("/static/ui.js", token))
    assert js.headers["content-type"].startswith("text/javascript")
    assert "check-form" in js.text


# --- end to end -----------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_a_real_check_through_the_ui_on_the_demo_history(
    vulnlab_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    token = security.make_token()
    client = TestClient(create_app(token=token, port=PORT), base_url=ORIGIN)
    response = client.post(
        url("/checks", token),
        data={"repo": str(vulnlab_repo)},
        files={
            "report_file": (
                "genuine_hdr_overflow.md",
                (REPORTS / "genuine_hdr_overflow.md").read_bytes(),
                "text/markdown",
            )
        },
        headers={"origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text[:2000]
    page = client.get(url("/results/1", token)).text
    assert "GROUNDED" in page and "UNGROUNDED" not in page
    payload = json.loads(client.get(url("/results/1/result.json", token)).text)
    assert re.fullmatch(r"[0-9a-f]{40}", payload["target"]["commit"])
    assert payload["report"]["source"]["uri"] == "genuine_hdr_overflow.md"
    report = client.get(url("/results/1/report", token)).text
    assert "util_copy_value" in report
