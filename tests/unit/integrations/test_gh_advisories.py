# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""GitHub private vulnerability reports (SPEC §8, §16.5): read-only over urllib, offline
unless ``--online``, a token from the environment, one host, and no author identity."""

from __future__ import annotations

import email.message
import json
import urllib.error
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from nikasha.errors import NikashaError
from nikasha.ingest.markdown import ingest_markdown
from nikasha.integrations import gh_advisories as gh
from nikasha.integrations.gh_advisories import (
    fetch_advisories,
    next_link,
    parse_advisory,
    validate_owner_repo,
    validate_state,
)
from nikasha.integrations.h1 import report_json

SAMPLE = Path(__file__).resolve().parents[1] / "extract" / "appendix_b_sample.md"
BASE = "https://api.github.com/repos/libhdr/libhdr/security-advisories"
PAGE1 = f"{BASE}?state=triage&per_page=100"
PAGE2 = f"{BASE}?state=triage&per_page=100&page=2"
GHSA = "GHSA-abcd-efgh-2jkm"
AUTHOR = "secret-author-login"
CREDITED = "credited-person-login"
TOKEN = {"GITHUB_TOKEN": "ghp_testtokenvalue"}


def _advisory(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ghsa_id": GHSA,
        "cve_id": "CVE-2026-0001",
        "url": f"https://api.github.com/repos/libhdr/libhdr/security-advisories/{GHSA}",
        "html_url": f"https://github.com/libhdr/libhdr/security/advisories/{GHSA}",
        "summary": "Critical heap overflow in libhdr hdr_decode_chunked_value() leads to RCE",
        "description": SAMPLE.read_text(encoding="utf-8"),
        "severity": "high",
        "author": {"login": AUTHOR, "id": 1},
        "publisher": {"login": "publisher-login", "id": 2},
        "identifiers": [{"type": "GHSA", "value": GHSA}],
        "state": "triage",
        "created_at": "2026-01-20T10:00:00Z",
        "updated_at": "2026-01-21T10:00:00Z",
        "published_at": None,
        "submission": {"accepted": False},
        "vulnerabilities": [
            {
                "package": {"ecosystem": "other", "name": "libhdr"},
                "vulnerable_version_range": "<= 1.2.0",
                "patched_versions": "1.2.1",
                "vulnerable_functions": ["hdr_decode_chunked_value"],
            }
        ],
        "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
        "cwes": [{"cwe_id": "CWE-122", "name": "Heap-based Buffer Overflow"}],
        "credits": [{"login": CREDITED, "type": "reporter"}],
        "credits_detailed": [
            {"user": {"login": CREDITED}, "type": "reporter", "state": "accepted"}
        ],
    }
    item.update(overrides)
    return item


DRAFT = _advisory(
    ghsa_id="GHSA-2222-3333-4444",
    cve_id=None,
    html_url="https://evil.example/not-github",
    summary="Draft without text",
    description=None,
    severity=None,
    cvss={"vector_string": None, "score": None},
    cwes=[],
    vulnerabilities=[],
)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        url: str | None = None,
    ) -> None:
        self.body, self.status, self.url = body, status, url
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def install(monkeypatch, routes: dict[str, object]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_urlopen(request, timeout=None):
        assert timeout is not None and timeout > 0
        url = request.full_url
        calls.append(
            {
                "method": request.get_method(),
                "url": url,
                "headers": {k.lower(): v for k, v in request.header_items()},
            }
        )
        route = routes.get(url)
        if route is None:
            raise urllib.error.URLError(f"no route to {url}")
        if isinstance(route, Exception):
            raise route
        if isinstance(route, bytes):
            return FakeResponse(route, url=url)
        return route

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def _boom(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("the network was reached")

    monkeypatch.setattr("urllib.request.urlopen", boom)


def _http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "nope", email.message.Message(), None)


def _routes() -> dict[str, object]:
    return {
        PAGE1: FakeResponse(
            json.dumps([_advisory()]).encode("utf-8"),
            headers={"Link": f'<{PAGE2}>; rel="next", <{PAGE1}>; rel="first"'},
        ),
        PAGE2: json.dumps([DRAFT]).encode("utf-8"),
    }


# --- refusals (before any request) -------------------------------------------------------------


def test_refuses_offline_before_any_request(monkeypatch):
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="--online") as info:
        fetch_advisories("libhdr/libhdr", online=False, env=TOKEN)
    assert "nothing was requested" in str(info.value)


def test_refuses_without_a_token(monkeypatch):
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="GITHUB_TOKEN"):
        fetch_advisories("libhdr/libhdr", online=True, env={})
    with pytest.raises(NikashaError, match="printable ASCII"):
        fetch_advisories("libhdr/libhdr", online=True, env={"GITHUB_TOKEN": "bad\ntoken"})


def test_gh_token_is_a_fallback(monkeypatch):
    install(monkeypatch, {PAGE1: b"[]"})
    fetched = fetch_advisories("libhdr/libhdr", online=True, env={"GH_TOKEN": "gho_x"})
    assert fetched.reports == ()


@pytest.mark.parametrize(
    "bad", ["", "libhdr", "a/b/c", "owner/", "/repo", "-bad/x", "o/..", "o/.", "o w/r", "o/r?x=1"]
)
def test_rejects_malformed_owner_repo(bad, monkeypatch):
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="OWNER/REPO"):
        fetch_advisories(bad, online=True, env=TOKEN)


def test_owner_repo_accepts_github_names() -> None:
    assert validate_owner_repo("curl/curl") == ("curl", "curl")
    assert validate_owner_repo(" python/cpython.git ") == ("python", "cpython.git")


def test_rejects_unknown_state(monkeypatch):
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="--state"):
        fetch_advisories("libhdr/libhdr", state="open", online=True, env=TOKEN)
    assert validate_state(" Triage ") == "triage"


# --- requests and conversion -----------------------------------------------------------------


def test_fetch_follows_pagination_and_builds_reports(monkeypatch):
    calls = install(monkeypatch, _routes())
    fetched = fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)

    assert [c["url"] for c in calls] == [PAGE1, PAGE2]
    assert all(c["method"] == "GET" for c in calls)
    for call in calls:
        assert call["headers"]["authorization"] == "Bearer ghp_testtokenvalue"
        assert call["headers"]["accept"] == "application/vnd.github+json"
        assert call["headers"]["x-github-api-version"] == gh.API_VERSION
        assert call["headers"]["user-agent"].startswith("nikasha/")
    assert fetched.fetched_urls == (PAGE1, PAGE2)
    assert fetched.warnings == ()

    first, draft = fetched.reports
    assert first.source.kind == "gh_advisory"
    assert first.source.uri == f"https://github.com/libhdr/libhdr/security/advisories/{GHSA}"
    assert first.title is not None and first.title.startswith("Critical heap overflow")
    assert "hdr_decode_chunked_value" in first.body
    assert first.reported_at == date(2026, 1, 20)
    assert first.declared_target is not None
    assert first.declared_target.repo_url == "https://github.com/libhdr/libhdr"
    assert first.declared_target.versions == ("<= 1.2.0",)

    assert draft.body == ""
    assert draft.title == "Draft without text"
    assert "the advisory has no description text" in draft.warnings
    # A foreign html_url is not trusted; the page URL is built from the advisory ID.
    assert (
        draft.source.uri
        == "https://github.com/libhdr/libhdr/security/advisories/GHSA-2222-3333-4444"
    )


def test_author_and_credits_are_never_stored(monkeypatch):
    install(monkeypatch, _routes())
    fetched = fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    for text in (report_json(fetched.reports), fetched.markdown()):
        assert AUTHOR not in text
        assert CREDITED not in text
        assert "publisher-login" not in text


def test_markdown_lists_every_advisory_and_round_trips(monkeypatch):
    install(monkeypatch, _routes())
    fetched = fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    markdown = fetched.markdown()
    assert markdown.startswith("# Critical heap overflow")
    assert f"nikasha intake: GitHub advisory {GHSA} in libhdr/libhdr" in markdown
    assert "cve: CVE-2026-0001" in markdown
    assert "severity: high (7.5)" in markdown
    assert "cvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" in markdown
    assert "cwe: CWE-122 Heap-based Buffer Overflow" in markdown
    assert "packages: libhdr (other)" in markdown
    assert "vulnerable versions: <= 1.2.0" in markdown
    assert "patched versions: 1.2.1" in markdown
    assert "vulnerable functions: hdr_decode_chunked_value" in markdown
    assert "\n---\n\n# Draft without text" in markdown
    first_doc = markdown.split("\n---\n\n")[0]
    assert ingest_markdown(first_doc).body.endswith(fetched.reports[0].body)


def test_empty_listing_is_a_comment(monkeypatch):
    install(monkeypatch, {PAGE1: b"[]"})
    fetched = fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    assert fetched.markdown() == "<!-- nikasha intake: no triage advisories in libhdr/libhdr -->\n"
    assert report_json(fetched.reports) == "[]\n"


def test_next_link_only_stays_on_the_api_host() -> None:
    assert next_link(f'<{PAGE2}>; rel="next"') == PAGE2
    assert next_link(f'<{PAGE1}>; rel="prev", <{PAGE2}>; rel="next"') == PAGE2
    assert next_link('<https://evil.example/steal>; rel="next"') is None
    assert next_link('<http://api.github.com/x>; rel="next"') is None
    assert next_link(None) is None
    assert next_link("") is None


def test_foreign_next_link_is_not_followed(monkeypatch):
    calls = install(
        monkeypatch,
        {PAGE1: FakeResponse(b"[]", headers={"Link": '<https://evil.example/steal>; rel="next"'})},
    )
    fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    assert [c["url"] for c in calls] == [PAGE1]


def test_page_cap_warns(monkeypatch):
    monkeypatch.setattr(gh, "MAX_PAGES", 2)
    calls = install(
        monkeypatch,
        {
            PAGE1: FakeResponse(b"[]", headers={"Link": f'<{PAGE2}>; rel="next"'}),
            PAGE2: FakeResponse(b"[]", headers={"Link": f'<{PAGE2}>; rel="next"'}),
        },
    )
    fetched = fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    assert len(calls) == 2
    assert any("more than 2 pages" in w for w in fetched.warnings)


def test_non_list_answer_is_refused(monkeypatch):
    install(monkeypatch, {PAGE1: b'{"message": "Not Found"}'})
    with pytest.raises(NikashaError, match="not a list"):
        fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)


def test_http_errors_carry_hints(monkeypatch):
    install(monkeypatch, {PAGE1: _http_error(PAGE1, 403)})
    with pytest.raises(NikashaError, match="HTTP 403") as info:
        fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    assert "security advisories" in str(info.value)
    assert TOKEN["GITHUB_TOKEN"] not in str(info.value)
    install(monkeypatch, {PAGE1: _http_error(PAGE1, 404)})
    with pytest.raises(NikashaError, match="repository not found"):
        fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)


def test_token_is_never_forwarded_on_redirect_nor_printed(monkeypatch):
    seen: list[Any] = []

    def capture(request, timeout=None):
        seen.append(request)
        raise urllib.error.URLError("refused")

    monkeypatch.setattr("urllib.request.urlopen", capture)
    with pytest.raises(NikashaError) as info:
        fetch_advisories("libhdr/libhdr", online=True, env=TOKEN)
    assert "ghp_testtokenvalue" not in str(info.value)
    (request,) = seen
    # urllib copies ``headers`` (not ``unredirected_hdrs``) onto a redirected request.
    assert "Authorization" not in request.headers
    assert request.unredirected_hdrs["Authorization"] == "Bearer ghp_testtokenvalue"


def test_parse_advisory_tolerates_garbage() -> None:
    for item in ("nonsense", [], {"ghsa_id": 5, "cvss": "x", "vulnerabilities": "y", "cwes": 3}):
        parsed = parse_advisory(item)
        assert parsed.ghsa_id == ""
        assert parsed.description == ""
        assert parsed.ranges == ()
        assert parsed.cwes == ()
    parsed = parse_advisory({"ghsa_id": "GHSA-not-valid", "cvss": {"score": True}})
    assert parsed.ghsa_id == ""
    assert parsed.cvss_score == ""
    report = gh.build_report(parsed, "o", "r")
    assert report.source.uri == "https://github.com/o/r/security/advisories"


# --- CLI ------------------------------------------------------------------------------------------

runner = CliRunner()


def _app() -> typer.Typer:
    app = typer.Typer()

    def root() -> None:
        """Test root."""

    app.callback()(root)
    gh.register(app)
    return app


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN["GITHUB_TOKEN"])
    monkeypatch.delenv("GH_TOKEN", raising=False)
    return tmp_path


def test_cli_refuses_offline(env, monkeypatch):
    _boom(monkeypatch)
    result = runner.invoke(_app(), ["gh-advisories", "libhdr/libhdr"])
    assert result.exit_code == 1
    assert "--online" in result.output
    assert "Traceback" not in result.output


def test_cli_refuses_without_a_token(env, monkeypatch):
    _boom(monkeypatch)
    monkeypatch.delenv("GITHUB_TOKEN")
    result = runner.invoke(_app(), ["gh-advisories", "libhdr/libhdr", "--online"])
    assert result.exit_code == 1
    assert "GITHUB_TOKEN" in result.output


def test_cli_prints_markdown_and_json(env, monkeypatch):
    calls = install(monkeypatch, _routes())
    result = runner.invoke(_app(), ["gh-advisories", "libhdr/libhdr", "--online"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("# Critical heap overflow")
    assert AUTHOR not in result.output
    assert all(c["method"] == "GET" for c in calls)

    result = runner.invoke(_app(), ["gh-advisories", "libhdr/libhdr", "--online", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert [d["source"]["kind"] for d in data] == ["gh_advisory", "gh_advisory"]


def test_cli_rejects_bad_state(env, monkeypatch):
    _boom(monkeypatch)
    result = runner.invoke(_app(), ["gh-advisories", "libhdr/libhdr", "--online", "--state", "x"])
    assert result.exit_code == 1
    assert "--state" in result.output


def test_cli_out_dir_writes_one_file_per_advisory(env, monkeypatch):
    install(monkeypatch, _routes())
    out_dir = env / "advisories"
    result = runner.invoke(
        _app(), ["gh-advisories", "libhdr/libhdr", "--online", "--out-dir", str(out_dir)]
    )
    assert result.exit_code == 0, result.output
    expected = sorted([f"{GHSA}.md", "GHSA-2222-3333-4444.md"])
    assert sorted(p.name for p in out_dir.iterdir()) == expected
    assert (out_dir / f"{GHSA}.md").read_text(encoding="utf-8").startswith("# Critical heap")
    assert result.stdout == ""


def test_cli_check_prints_reply_markdown(env, monkeypatch, vulnlab_repo):
    install(monkeypatch, {PAGE1: json.dumps([_advisory()]).encode("utf-8")})
    result = runner.invoke(
        _app(),
        [
            "gh-advisories", "libhdr/libhdr", "--online", "--check",
            "--repo", str(vulnlab_repo), "--version", "1.2.0",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert any(
        label in result.stdout for label in ("GROUNDED", "MIXED", "UNGROUNDED", "INSUFFICIENT")
    ), result.stdout
    assert AUTHOR not in result.output
    saved = env / "cache" / "intake" / "github" / "libhdr" / "libhdr" / f"{GHSA}.md"
    assert saved.is_file()
