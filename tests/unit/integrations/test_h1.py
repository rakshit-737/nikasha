# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""HackerOne intake (SPEC §8, §16.5): read-only, offline unless ``--online``, credentials
from the environment, HTTPS only, and the reporter's identity never stored."""

from __future__ import annotations

import base64
import email.message
import json
import urllib.error
import urllib.request
from datetime import date
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, NoReturn, cast

import pytest
import typer
from typer.testing import CliRunner

from nikasha.errors import NikashaError
from nikasha.extract import extract_claims
from nikasha.ingest.markdown import ingest_markdown
from nikasha.integrations import h1
from nikasha.integrations.h1 import (
    API_BASE,
    Credentials,
    credentials_from_env,
    fetch_bytes,
    fetch_json,
    fetch_report,
    parse_report,
    report_json,
    validate_report_id,
)

SAMPLE = Path(__file__).resolve().parents[1] / "extract" / "appendix_b_sample.md"
REPORT_URL = API_BASE + "123456"
POC_URL = "https://h1-attachments.example/poc.c?signature=abc"
CREDS = {"HACKERONE_USER": "program-api", "HACKERONE_TOKEN": "s3cr3t-token-value"}
REPORTER_HANDLE = "secret-reporter-handle"
REPORTER_NAME = "Real Person Name"


def _payload(**overrides: Any) -> dict[str, Any]:
    attributes = {
        "title": "Critical heap overflow in libhdr hdr_decode_chunked_value() leads to RCE",
        "vulnerability_information": SAMPLE.read_text(encoding="utf-8"),
        "state": "triaged",
        "created_at": "2026-01-15T09:20:30.000Z",
    }
    attributes.update(overrides)
    return {
        "data": {
            "id": "123456",
            "type": "report",
            "attributes": attributes,
            "relationships": {
                "reporter": {
                    "data": {
                        "id": "42",
                        "type": "user",
                        "attributes": {"username": REPORTER_HANDLE, "name": REPORTER_NAME},
                    }
                },
                "program": {"data": {"attributes": {"handle": "libhdr"}}},
                "severity": {"data": {"attributes": {"rating": "high", "score": 7.5}}},
                "weakness": {
                    "data": {
                        "attributes": {
                            "name": "Heap-based Buffer Overflow",
                            "external_id": "cwe-122",
                        }
                    }
                },
                "structured_scope": {
                    "data": {
                        "attributes": {
                            "asset_identifier": "github.com/libhdr/libhdr",
                            "asset_type": "SOURCE_CODE",
                        }
                    }
                },
                "attachments": {
                    "data": [
                        {
                            "attributes": {
                                "file_name": "poc.c",
                                "content_type": "text/x-c",
                                "file_size": 29,
                                "expiring_url": POC_URL,
                            }
                        },
                        {
                            "attributes": {
                                "file_name": "../huge.bin",
                                "content_type": "application/octet-stream",
                                "file_size": 99_999_999,
                                "expiring_url": "https://h1-attachments.example/huge",
                            }
                        },
                        {
                            "attributes": {
                                "file_name": "plain.txt",
                                "content_type": "text/plain",
                                "file_size": 5,
                                "expiring_url": "http://insecure.example/plain.txt",
                            }
                        },
                    ]
                },
            },
        }
    }


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


def install(monkeypatch: pytest.MonkeyPatch, routes: dict[str, object]) -> list[dict[str, Any]]:
    """Route ``urllib.request.urlopen`` to canned answers and record every request."""
    calls: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> object:
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


def _boom(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("the network was reached")

    monkeypatch.setattr("urllib.request.urlopen", boom)


def _http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "nope", email.message.Message(), None)


def _routes() -> dict[str, object]:
    return {
        REPORT_URL: json.dumps(_payload()).encode("utf-8"),
        POC_URL: b"int main(void) { return 0; }\n",
    }


# --- refusals (before any request) -------------------------------------------------------------


def test_refuses_offline_before_any_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="--online") as info:
        fetch_report("123456", online=False, env=CREDS, run_dir=tmp_path)
    assert "nothing was requested" in str(info.value)


def test_refuses_without_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="HACKERONE_USER") as info:
        fetch_report("123456", online=True, env={}, run_dir=tmp_path)
    assert "HACKERONE_TOKEN" in str(info.value)
    with pytest.raises(NikashaError, match="HACKERONE"):
        credentials_from_env({"HACKERONE_USER": "u"})


@pytest.mark.parametrize("bad", ["", "abc", "12/../3", "1?x=1", "0", "1" * 13, "1 2", "-1"])
def test_rejects_malformed_report_ids(
    bad: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="report ID"):
        fetch_report(bad, online=True, env=CREDS, run_dir=tmp_path)


def test_accepts_hash_prefixed_id() -> None:
    assert validate_report_id("#123456") == "123456"
    assert validate_report_id(" 7 ") == "7"


@pytest.mark.parametrize("token", ["with space", "line\nbreak", "tab\there", "é"])
def test_credentials_must_be_printable_ascii(
    token: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="printable ASCII"):
        fetch_report(
            "1",
            online=True,
            env={"HACKERONE_USER": "u", "HACKERONE_TOKEN": token},
            run_dir=tmp_path,
        )


def test_basic_auth_header() -> None:
    creds = Credentials(user="u", token="t")  # noqa: S106 - a stand-in for tests
    assert creds.basic_auth() == "Basic " + base64.b64encode(b"u:t").decode()


# --- the request and the conversion ------------------------------------------------------------


def test_fetch_builds_a_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = install(monkeypatch, _routes())
    fetched = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path / "att")

    assert [c["method"] for c in calls] == ["GET", "GET"]
    api, poc = calls
    assert api["url"] == REPORT_URL
    assert (
        api["headers"]["authorization"]
        == Credentials("program-api", "s3cr3t-token-value").basic_auth()
    )
    assert api["headers"]["accept"] == "application/json"
    assert api["headers"]["user-agent"].startswith("nikasha/")
    assert poc["url"] == POC_URL
    assert (
        "authorization" not in poc["headers"]
    )  # pre-signed URL: no credentials leave the API host

    report = fetched.report
    assert report.source.kind == "hackerone"
    assert report.source.uri == "https://hackerone.com/reports/123456"
    assert report.title is not None and report.title.startswith("Critical heap overflow")
    assert "hdr_decode_chunked_value" in report.body
    assert any(b.lang_hint == "c" for b in report.code_blocks)
    assert report.reported_at == date(2026, 1, 15)
    assert report.declared_target is not None
    assert report.declared_target.repo_url == "https://github.com/libhdr/libhdr"
    assert [a.name_sanitized for a in report.attachments] == ["poc.c"]
    assert report.attachments[0].size == 29
    assert (tmp_path / "att" / "poc.c").read_bytes() == b"int main(void) { return 0; }\n"
    assert any("huge.bin" in w and "exceeds the cap" in w for w in report.warnings)
    assert any("plain.txt" in w and "no HTTPS" in w for w in report.warnings)
    assert fetched.fetched_urls == (REPORT_URL, "https://h1-attachments.example/poc.c?[redacted]")
    assert "signature=abc" not in fetched.markdown()


def test_reporter_identity_is_never_stored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    install(monkeypatch, _routes())
    fetched = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    for text in (report_json([fetched.report]), fetched.markdown(), fetched.report.body):
        assert REPORTER_HANDLE not in text
        assert REPORTER_NAME not in text
    assert "The reporter's identity was not recorded." in fetched.markdown()


def test_same_answer_same_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    install(monkeypatch, _routes())
    first = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path / "1")
    second = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path / "2")
    assert report_json([first.report]) == report_json([second.report])
    assert first.markdown() == second.markdown()


def test_markdown_round_trips_and_metadata_is_not_a_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install(monkeypatch, _routes())
    fetched = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    markdown = fetched.markdown()
    assert markdown.startswith("# Critical heap overflow")
    assert "state: triaged" in markdown
    assert "severity: high (7.5)" in markdown
    assert "weakness: CWE-122 Heap-based Buffer Overflow" in markdown
    assert "program: libhdr" in markdown
    assert f"fetched: {REPORT_URL}" in markdown
    again = ingest_markdown(markdown)
    assert again.title == fetched.report.title
    assert again.body.endswith(fetched.report.body)
    # Nothing inside the intake comment becomes a claim (the title heading before it may).
    comment_start = again.body.index("<!--")
    comment_end = again.body.index("-->", comment_start)
    assert "state: triaged" in again.body[comment_start:comment_end]
    for claim in extract_claims(again).claims:
        for span in claim.spans:
            assert not (comment_start <= span.start < comment_end), claim


def test_intake_comment_cannot_be_closed_from_inside() -> None:
    parsed = parse_report(
        _payload(
            title="t", state="--><script>alert(1)</script><!--", vulnerability_information="b"
        ),
        "1",
    )
    markdown = h1.Fetched(h1.build_report(parsed), parsed, ()).markdown()
    assert [line for line in markdown.splitlines() if "-->" in line] == ["-->"]
    assert "<script>" not in markdown.split("-->", 1)[0]


def test_no_attachments_flag_skips_downloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = install(monkeypatch, _routes())
    fetched = fetch_report(
        "123456", online=True, env=CREDS, run_dir=tmp_path, with_attachments=False
    )
    assert [c["url"] for c in calls] == [REPORT_URL]
    assert fetched.report.attachments == ()
    assert "attachments: 3 (poc.c, ../huge.bin, plain.txt)" in fetched.markdown()


def test_parse_report_tolerates_garbage() -> None:
    payload: object
    for payload in ("nonsense", [], {"data": 5}, {"data": {"attributes": {"title": 5}}}):
        parsed = parse_report(payload, "1")
        assert parsed.title == ""
        assert parsed.body == ""
        assert parsed.attachments == ()
    parsed = parse_report({"data": {"attributes": {"created_at": "yesterday"}}}, "1")
    assert parsed.created_at is None
    report = h1.build_report(parsed)
    assert report.body == ""
    assert any("no vulnerability information" in w for w in report.warnings)
    assert report.declared_target is None


def test_scope_repo_url_only_for_github_source_code() -> None:
    assert (
        h1.repo_url_from_scope("github.com/curl/curl", "SOURCE_CODE")
        == "https://github.com/curl/curl"
    )
    assert (
        h1.repo_url_from_scope("https://github.com/curl/curl/", "source_code")
        == "https://github.com/curl/curl"
    )
    assert h1.repo_url_from_scope("github.com/curl/curl", "URL") is None
    assert h1.repo_url_from_scope("gitlab.com/curl/curl", "SOURCE_CODE") is None
    assert h1.repo_url_from_scope("github.com/curl/curl/../x", "SOURCE_CODE") is None


# --- transport hardening -----------------------------------------------------------------------


def test_http_errors_become_nikasha_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    install(monkeypatch, {REPORT_URL: _http_error(REPORT_URL, 401)})
    with pytest.raises(NikashaError, match="HTTP 401") as info:
        fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    assert "HACKERONE_USER" in str(info.value)
    assert CREDS["HACKERONE_TOKEN"] not in str(info.value)
    install(monkeypatch, {REPORT_URL: _http_error(REPORT_URL, 404)})
    with pytest.raises(NikashaError, match="no such report"):
        fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    install(monkeypatch, {})
    with pytest.raises(NikashaError, match="could not fetch"):
        fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)


def test_non_https_is_refused_without_a_request(monkeypatch: pytest.MonkeyPatch) -> None:
    _boom(monkeypatch)
    with pytest.raises(NikashaError, match="non-HTTPS"):
        fetch_bytes("http://api.hackerone.com/v1/reports/1")
    with pytest.raises(NikashaError, match="non-HTTPS"):
        fetch_bytes("file:///etc/passwd")


def test_redirect_off_https_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, {REPORT_URL: FakeResponse(b"{}", url="http://evil.example/")})
    with pytest.raises(NikashaError, match="non-HTTPS"):
        fetch_json(REPORT_URL)


def test_oversized_answer_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, {REPORT_URL: b"[" + b"1," * 4_300_000 + b"1]"})
    with pytest.raises(NikashaError, match="exceeds"):
        fetch_json(REPORT_URL)


def test_not_json_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, {REPORT_URL: b"<html>nope</html>"})
    with pytest.raises(NikashaError, match="not JSON"):
        fetch_json(REPORT_URL)


@pytest.mark.parametrize(
    "body",
    [b"[" * 200_000 + b"]" * 200_000, b"1" * 5000, b'{"a": "\xff"}'],
    ids=["deep", "huge-int", "bad-utf8"],
)
def test_hostile_json_is_refused_cleanly(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    # Deep nesting (RecursionError) and a 5000-digit int (plain ValueError) used to escape.
    install(monkeypatch, {REPORT_URL: body})
    with pytest.raises(NikashaError, match="not JSON"):
        fetch_json(REPORT_URL)


def test_hostile_attachment_list_shapes_do_not_crash() -> None:
    data: object
    payload: dict[str, object]
    for data in ("x" * 10_000, {"k": 1}, 7, [None, "s", {"attributes": []}]):
        payload = {"data": {"relationships": {"attachments": {"data": data}}}}
        parsed = parse_report(payload, "1")
        assert len(parsed.attachments) <= 3


def test_credentials_are_not_forwarded_on_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, _routes())
    fetch_report("123456", online=True, env=CREDS, with_attachments=False)
    seen: list[urllib.request.Request] = []

    def capture(request: urllib.request.Request, timeout: float | None = None) -> FakeResponse:
        seen.append(request)
        return h1_fake_response()

    monkeypatch.setattr("urllib.request.urlopen", capture)
    fetch_json(REPORT_URL, headers={"Authorization": "Basic c2VjcmV0"})
    (request,) = seen
    assert "Authorization" not in request.headers  # headers are copied onto redirects
    assert request.unredirected_hdrs.get("Authorization") == "Basic c2VjcmV0"
    # urllib's own redirect handler builds the follow-up request: no credential on it.
    follow = urllib.request.HTTPRedirectHandler().redirect_request(
        request,
        cast("IO[bytes]", None),
        302,
        "Found",
        cast("HTTPMessage", email.message.Message()),
        "https://elsewhere.example/x",
    )
    assert follow is not None
    assert all(k.lower() != "authorization" for k, _ in follow.header_items())


def h1_fake_response() -> FakeResponse:
    return FakeResponse(b"{}", url=REPORT_URL)


def test_errors_never_carry_a_presigned_query(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    routes = _routes()
    routes[POC_URL] = urllib.error.URLError("boom " + POC_URL)
    install(monkeypatch, routes)
    fetched = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    assert "signature=abc" not in fetched.report.model_dump_json()
    assert "signature=abc" not in fetched.markdown()


def test_attachment_failures_are_warnings_not_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    routes = _routes()
    routes[POC_URL] = _http_error(POC_URL, 403)
    install(monkeypatch, routes)
    fetched = fetch_report("123456", online=True, env=CREDS, run_dir=tmp_path)
    assert fetched.report.attachments == ()
    assert any("poc.c not downloaded" in w and "HTTP 403" in w for w in fetched.report.warnings)


# --- CLI ------------------------------------------------------------------------------------------

runner = CliRunner()


def _app() -> typer.Typer:
    app = typer.Typer()

    def root() -> None:
        """Test root."""

    app.callback()(root)
    h1.register(app)
    return app


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    for key, value in CREDS.items():
        monkeypatch.setenv(key, value)
    return tmp_path


def test_cli_refuses_offline(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _boom(monkeypatch)
    result = runner.invoke(_app(), ["h1", "123456"])
    assert result.exit_code == 1
    assert "--online" in result.output
    assert "Traceback" not in result.output


def test_cli_refuses_without_credentials(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _boom(monkeypatch)
    monkeypatch.delenv("HACKERONE_TOKEN")
    result = runner.invoke(_app(), ["h1", "123456", "--online"])
    assert result.exit_code == 1
    assert "HACKERONE_TOKEN" in result.output


def test_cli_prints_markdown_and_json(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install(monkeypatch, _routes())
    result = runner.invoke(_app(), ["h1", "123456", "--online"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("# Critical heap overflow")
    assert REPORTER_HANDLE not in result.output
    assert all(c["method"] == "GET" for c in calls)

    result = runner.invoke(_app(), ["h1", "123456", "--online", "--json", "--no-attachments"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["source"] == {"kind": "hackerone", "uri": "https://hackerone.com/reports/123456"}
    assert data["attachments"] == []


def test_cli_writes_to_a_file(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, _routes())
    out = env / "report.md"
    result = runner.invoke(_app(), ["h1", "123456", "--online", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8").startswith("# Critical heap overflow")
    # The Markdown file is a report `nikasha check` can read back.
    assert ingest_markdown(out.read_text(encoding="utf-8")).title is not None


def test_cli_check_prints_the_reply_markdown(
    env: Path, monkeypatch: pytest.MonkeyPatch, vulnlab_repo: Path
) -> None:
    install(monkeypatch, _routes())
    result = runner.invoke(
        _app(),
        ["h1", "123456", "--online", "--repo", str(vulnlab_repo), "--version", "1.2.0"],
    )
    assert result.exit_code == 0, result.output
    assert "report saved to" in result.output
    assert any(
        label in result.stdout for label in ("GROUNDED", "MIXED", "UNGROUNDED", "INSUFFICIENT")
    ), result.stdout
    assert REPORTER_HANDLE not in result.output
    saved = env / "cache" / "intake" / "hackerone" / "report-123456.md"
    assert saved.is_file()
