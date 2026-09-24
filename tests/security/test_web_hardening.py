# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The hardening tests for the local web UI (SPEC §16.4, §19.2, §22).

The MCP Inspector RCE (CVE-2025-49596) is the shape of bug this file exists to rule out: a
server bound to localhost, with no authentication, no ``Origin`` check and no ``Host``
check, reachable from any web page the user has open (directly, or through DNS rebinding).
Each numbered rule in :mod:`nikasha.integrations.web.security` has a section here, and
the tests are written against the served responses wherever a response is involved, not
against the constants.

None of these tests opens a real port: ``fastapi.testclient.TestClient`` drives the ASGI
application in process. The one socket test binds and closes without ever serving.
"""

from __future__ import annotations

import asyncio
import inspect
import io
import json
import re
import sys
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from starlette.datastructures import FormData, UploadFile

from nikasha.errors import NikashaError
from nikasha.fuse.scoring import fuse
from nikasha.ingest import MAX_INPUT_BYTES, ingest_string
from nikasha.integrations import web as web_pkg
from nikasha.integrations.web import app as webapp
from nikasha.integrations.web import security
from nikasha.integrations.web.app import create_app
from nikasha.model.result import ResolvedTarget, Result
from nikasha.model.verdict import Verdict
from nikasha.pipeline import CheckReport

PORT = 43121
HOST = f"127.0.0.1:{PORT}"
ORIGIN = f"http://{HOST}"

#: One payload per way out of a sink (the same corpus the HTML report is tested with).
PAYLOADS = (
    "</script><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</style><style>@import url(https://evil.example/x)</style>",
    "</textarea></title></noscript></template>",
    "javascript:alert(1)",
    "<!--<script>",
    "'`--><svg/onload=alert(1)>",
    "\u202eannex/c.evil",
    "]]><script>alert(1)</script>",
)
HOSTILE = " ".join(PAYLOADS)

SRC = Path(__file__).resolve().parents[2] / "src" / "nikasha" / "integrations" / "web"


# --- fixtures -----------------------------------------------------------------------------


def fake_check_report(path: Path, **options: Any) -> CheckReport:
    """A stand-in for the pipeline: the pasted text becomes the report, verdict GROUNDED."""
    text = Path(path).read_text(encoding="utf-8")
    report = ingest_string(text, input_format="text", uri=str(path))
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
        verdict=Verdict(label="GROUNDED", score=88, confidence="high", rule="1a"),
    )
    return CheckReport(result=result, ledger=fuse(()), decision=None, runs=(), resolution=None)  # type: ignore[arg-type]


@pytest.fixture
def token() -> str:
    return security.make_token()


@pytest.fixture
def git_dir(tmp_path: Path) -> Path:
    """Something :func:`security.validate_repo` accepts: a bare repository's shape."""
    bare = tmp_path / "repo.git"
    (bare / "objects").mkdir(parents=True)
    (bare / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return bare


@pytest.fixture
def client(token: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(webapp, "check_report", fake_check_report)
    app = create_app(token=token, port=PORT)
    return TestClient(app, base_url=ORIGIN, raise_server_exceptions=False)


def url(path: str, token: str) -> str:
    return f"{path}?token={token}"


def post_headers() -> dict[str, str]:
    return {"origin": ORIGIN}


def submit(client: TestClient, token: str, git_dir: Path, text: str = "hdr_get overflows.\n"):
    return client.post(
        url("/checks", token),
        data={"report_text": text, "repo": str(git_dir)},
        headers=post_headers(),
        follow_redirects=False,
    )


class Document(HTMLParser):
    """Every element of a served page, for assertions a substring search cannot make."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, {k: (v or "") for k, v in attrs}))

    handle_startendtag = handle_starttag

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def tags(self, name: str) -> list[dict[str, str]]:
        return [attrs for tag, attrs in self.elements if tag == name]


def parse(html: str) -> Document:
    doc = Document()
    doc.feed(html)
    doc.close()
    return doc


# --- rule 1: loopback only, random port ----------------------------------------------------


def test_the_socket_binds_to_loopback_on_a_random_port() -> None:
    sock = security.bind_loopback(0)
    try:
        address, port = sock.getsockname()[:2]
    finally:
        sock.close()
    assert address == "127.0.0.1"
    assert 0 < port <= 65535


def test_there_is_no_option_to_bind_anywhere_else() -> None:
    assert "host" not in inspect.signature(web_pkg.serve).parameters
    assert "bind" not in inspect.signature(web_pkg.serve).parameters
    settings = web_pkg.server_settings(4321)
    assert settings["host"] == "127.0.0.1"
    assert settings["proxy_headers"] is False
    for source in SRC.rglob("*.py"):
        assert "0.0.0.0" not in source.read_text(encoding="utf-8"), source.name  # noqa: S104


def test_a_port_out_of_range_is_refused_before_binding() -> None:
    with pytest.raises(NikashaError):
        security.bind_loopback(70000)


def test_the_printed_url_is_the_loopback_address_with_the_token(token: str) -> None:
    assert security.build_url(43210, token) == f"http://127.0.0.1:43210/?token={token}"


def test_serve_binds_loopback_and_hands_uvicorn_the_bound_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uvicorn = pytest.importorskip("uvicorn")
    seen: dict[str, Any] = {}

    def fake_run(self: Any, sockets: Any = None) -> None:
        seen["sockets"] = sockets
        seen["config"] = self.config

    monkeypatch.setattr(uvicorn.Server, "run", fake_run)
    lines: list[str] = []
    web_pkg.serve_forever(port=0, announce=lines.append)
    (sock,) = seen["sockets"]
    assert sock.fileno() == -1, "the server closes its socket when it stops"
    config = seen["config"]
    assert config.host == "127.0.0.1"
    assert config.access_log is False, "the access log would print URLs carrying the token"
    assert lines[0].startswith("Nikasha web UI: http://127.0.0.1:")
    port = int(re.search(r":(\d+)/", lines[0]).group(1))
    assert port == config.port
    assert re.search(r"\?token=[A-Za-z0-9_-]{43,}$", lines[0])


# --- rule 2: the access token --------------------------------------------------------------


def test_a_fresh_token_has_thirty_two_bytes_of_entropy() -> None:
    a, b = security.make_token(), security.make_token()
    assert a != b
    assert len(a) >= 43  # 32 bytes, base64url without padding
    assert re.fullmatch(r"[A-Za-z0-9_-]+", a)


@pytest.mark.parametrize("presented", [None, "", "x", "wrong"])
def test_token_ok_rejects_anything_but_the_exact_token(presented: str | None, token: str) -> None:
    assert security.token_ok(presented, token) is False
    assert security.token_ok(token + "x", token) is False
    assert security.token_ok(token[:-1], token) is False
    assert security.token_ok(token, token) is True


def test_a_request_without_the_token_is_forbidden_with_no_detail(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 403
    assert response.text == "Forbidden"
    assert "www-authenticate" not in response.headers
    assert "token" not in response.text.lower()


def test_a_wrong_token_gets_the_same_answer_as_no_token(client: TestClient, token: str) -> None:
    wrong = client.get(url("/", token[::-1]))
    missing = client.get("/")
    assert wrong.status_code == missing.status_code == 403
    assert wrong.text == missing.text
    assert token not in wrong.text
    assert token[::-1] not in wrong.text


def test_the_token_is_accepted_in_the_query_or_in_a_header(client: TestClient, token: str) -> None:
    assert client.get(url("/", token)).status_code == 200
    assert client.get("/", headers={"X-Nikasha-Token": token}).status_code == 200


def test_every_page_and_asset_needs_the_token(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir).status_code == 303
    for path in (
        "/",
        "/history",
        "/static/ui.css",
        "/static/ui.js",
        "/results/1",
        "/results/1/report",
        "/results/1/report.html",
        "/results/1/result.json",
    ):
        assert client.get(path).status_code == 403, path
        assert client.get(url(path, token)).status_code == 200, path


def test_a_post_with_an_origin_but_no_token_is_forbidden(client: TestClient) -> None:
    response = client.post("/checks", data={"repo": "x"}, headers=post_headers())
    assert response.status_code == 403
    assert response.text == "Forbidden"


def test_the_token_is_never_set_as_a_cookie(client: TestClient, token: str) -> None:
    for path in ("/", "/history"):
        assert "set-cookie" not in client.get(url(path, token)).headers


# --- rule 3: the Host header (DNS rebinding) -----------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        f"evil.example:{PORT}",
        f"127.0.0.1.evil.example:{PORT}",
        "127.0.0.1",
        f"127.0.0.1:{PORT + 1}",
        f"0.0.0.0:{PORT}",
        f"[::1]:{PORT}",
        "",
    ],
)
def test_a_foreign_host_is_misdirected_even_with_the_token(
    client: TestClient, token: str, host: str
) -> None:
    response = client.get(url("/", token), headers={"host": host})
    assert response.status_code == 421, host
    assert response.text == "Misdirected Request"


@pytest.mark.parametrize("host", [HOST, f"localhost:{PORT}", f"LOCALHOST:{PORT}"])
def test_our_own_host_names_are_accepted(client: TestClient, token: str, host: str) -> None:
    assert client.get(url("/", token), headers={"host": host}).status_code == 200


def test_the_host_check_happens_before_the_token_check(client: TestClient) -> None:
    """A rebinding attacker never holds the token, but must be refused as a stranger, not
    as an unauthenticated friend: the answer must not depend on the token at all."""
    response = client.get("/", headers={"host": f"rebound.example:{PORT}"})
    assert response.status_code == 421


def test_host_ok_is_exact_on_the_port() -> None:
    assert security.host_ok(f"127.0.0.1:{PORT}", PORT)
    assert security.host_ok(f"localhost:{PORT}", PORT)
    assert not security.host_ok(f"127.0.0.1:{PORT}", PORT + 1)
    assert not security.host_ok(None, PORT)
    assert not security.host_ok("127.0.0.1", PORT)
    assert security.host_ok("127.0.0.1", 80)


# --- rule 4: POST needs the token and a same-origin Origin ---------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "",
        "null",
        "http://evil.example",
        f"http://evil.example:{PORT}",
        f"http://127.0.0.1.evil.example:{PORT}",
        f"https://{HOST}",
        f"http://localhost:{PORT}",  # a loopback name, but not *this page's* origin
        f"http://127.0.0.1:{PORT + 1}",
        f"{ORIGIN}/",
        f"{ORIGIN}.evil.example",
    ],
)
def test_a_post_without_a_same_origin_origin_is_forbidden(
    client: TestClient, token: str, git_dir: Path, origin: str | None
) -> None:
    headers = {} if origin is None else {"origin": origin}
    response = client.post(
        url("/checks", token),
        data={"report_text": "hdr_get", "repo": str(git_dir)},
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 403, origin
    assert response.text == "Forbidden"
    assert client.get(url("/history", token)).text.count("<tr>") <= 1


def test_the_same_origin_post_goes_through(client: TestClient, token: str, git_dir: Path) -> None:
    assert submit(client, token, git_dir).status_code == 303


def test_a_cross_site_fetch_metadata_is_refused_even_with_a_matching_origin(
    client: TestClient, token: str, git_dir: Path
) -> None:
    response = client.post(
        url("/checks", token),
        data={"report_text": "hdr_get", "repo": str(git_dir)},
        headers={"origin": ORIGIN, "sec-fetch-site": "cross-site"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_purging_the_history_needs_the_same_origin_too(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir).status_code == 303
    assert client.post(url("/history/purge", token), follow_redirects=False).status_code == 403
    assert client.post(url("/history/purge", token), headers={"origin": "http://evil.example"},
                       follow_redirects=False).status_code == 403  # fmt: skip
    assert "pasted report" in client.get(url("/history", token)).text
    assert client.post(url("/history/purge", token), headers=post_headers(),
                       follow_redirects=False).status_code == 303  # fmt: skip
    assert "pasted report" not in client.get(url("/history", token)).text


def test_origin_ok_requires_the_page_s_own_origin_exactly() -> None:
    assert security.origin_ok(ORIGIN, HOST, PORT)
    assert security.origin_ok(f"http://localhost:{PORT}", f"localhost:{PORT}", PORT)
    assert not security.origin_ok(f"http://localhost:{PORT}", HOST, PORT)
    assert not security.origin_ok(ORIGIN, "evil.example", PORT)
    assert not security.origin_ok(None, HOST, PORT)


def test_other_methods_are_not_allowed(client: TestClient, token: str) -> None:
    for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
        response = client.request(method, url("/", token), headers=post_headers())
        assert response.status_code == 405, method


# --- rule 5: security headers --------------------------------------------------------------

REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cache-control": "no-store",
}


def responses_of_every_kind(client: TestClient, token: str, git_dir: Path) -> list[Any]:
    assert submit(client, token, git_dir).status_code == 303
    return [
        client.get(url("/", token)),
        client.get(url("/history", token)),
        client.get(url("/results/1", token)),
        client.get(url("/results/1/report", token)),
        client.get(url("/results/1/result.json", token)),
        client.get(url("/results/99", token)),
        client.get(url("/static/ui.css", token)),
        client.get(url("/static/ui.js", token)),
        client.get("/"),
        client.get(url("/", token), headers={"host": "evil.example"}),
        client.get(url("/no-such-page", token)),
        submit(client, token, git_dir),
    ]


def test_every_response_carries_the_security_headers(
    client: TestClient, token: str, git_dir: Path
) -> None:
    for response in responses_of_every_kind(client, token, git_dir):
        where = f"{response.request.method} {response.request.url.path} -> {response.status_code}"
        csp = response.headers.get("content-security-policy", "")
        assert csp.startswith("default-src 'none'"), where
        for name, value in REQUIRED_HEADERS.items():
            assert response.headers.get(name) == value, f"{where}: {name}"


def test_the_ui_policy_allows_no_inline_script_and_nothing_remote(
    client: TestClient, token: str
) -> None:
    csp = client.get(url("/", token)).headers["content-security-policy"]
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}
    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert "'unsafe-inline'" not in directives["script-src"]
    assert "'unsafe-eval'" not in csp
    assert "http" not in csp


def test_ui_pages_have_no_inline_script_handler_or_remote_reference(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir, text=HOSTILE).status_code == 303
    for path in ("/", "/history", "/results/1", "/results/99"):
        doc = parse(client.get(url(path, token)).text)
        for tag, attrs in doc.elements:
            assert not any(k.startswith("on") for k in attrs), (path, tag, attrs)
            for key in ("src", "href", "action", "formaction", "data", "poster"):
                value = attrs.get(key)
                if value is None:
                    continue
                assert not re.match(r"(?i)\s*(javascript|data|vbscript):", value), (path, tag)
                assert not re.match(r"(?i)\s*(https?:|//)", value), (path, tag, value)
                assert value.startswith(("/", "#")), (path, tag, value)
        for script in doc.tags("script"):
            assert script.get("src", "").startswith("/static/"), (path, script)
        assert not doc.tags("iframe") or path == "/results/1"


def test_the_report_page_keeps_the_report_s_own_hashed_policy(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir).status_code == 303
    response = client.get(url("/results/1/report", token))
    csp = response.headers["content-security-policy"]
    meta = re.search(
        r'content="([^"]+)"',
        re.search(r"<meta http-equiv=\"Content-Security-Policy\"[^>]*>", response.text).group(0),
    ).group(1)
    assert csp == f"{meta}; frame-ancestors 'self'"
    assert "script-src 'sha256-" in csp
    assert response.headers["x-frame-options"] == "SAMEORIGIN"


def test_the_report_frame_is_same_origin_and_sandboxed(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir).status_code == 303
    doc = parse(client.get(url("/results/1", token)).text)
    (frame,) = doc.tags("iframe")
    assert frame["src"].startswith("/results/1/report?token=")
    assert "sandbox" in frame


# --- rule 6: caps and validation before use ------------------------------------------------


def test_a_request_larger_than_the_cap_is_refused_before_it_is_read(
    client: TestClient, token: str
) -> None:
    response = client.post(
        url("/checks", token),
        content=b"x",
        headers={**post_headers(), "content-length": str(security.MAX_REQUEST_BYTES + 1)},
    )
    assert response.status_code == 413


def test_the_upload_cap_is_the_intake_cap() -> None:
    assert security.MAX_UPLOAD_BYTES == MAX_INPUT_BYTES


def test_an_upload_over_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "MAX_UPLOAD_BYTES", 1000)
    upload = UploadFile(io.BytesIO(b"x" * 1001), filename="big.md")
    form = FormData([("report_file", upload), ("repo", ".")])
    with pytest.raises(webapp.TooLargeError):
        asyncio.run(webapp.read_check_form(form))


def test_a_paste_over_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "MAX_UPLOAD_BYTES", 1000)
    form = FormData([("report_text", "x" * 1001), ("repo", ".")])
    with pytest.raises(webapp.TooLargeError):
        asyncio.run(webapp.read_check_form(form))


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "http://github.com/curl/curl",
        "ftp://example.org/repo",
        "git://github.com/curl/curl",
        "ssh://git@github.com/curl/curl",
        "file:///etc",
        "git@github.com:curl/curl.git",
        "javascript:alert(1)",
        "data:text/plain,hello",
        "-oProxyCommand=calc",
        "--upload-pack=calc",
        "https://github.com/../../etc",
        "https://github.com/curl/cu rl",
        "https://",
        "path\nwith-newline",
        "path\x00null",
        "/definitely/not/a/directory/anywhere",
        "x" * 1025,
    ],
)
def test_bad_repositories_are_refused_before_use(value: str) -> None:
    with pytest.raises(security.InvalidInputError):
        security.validate_repo(value)


def test_a_directory_that_is_not_a_repository_is_refused(tmp_path: Path) -> None:
    with pytest.raises(security.InvalidInputError):
        security.validate_repo(str(tmp_path))


def test_a_local_git_directory_and_an_https_url_are_accepted(git_dir: Path) -> None:
    assert security.validate_repo(f" {git_dir} ") == str(git_dir)
    assert (
        security.validate_repo("https://github.com/curl/curl.git") == "https://github.com/curl/curl"
    )


def test_the_real_demo_repository_is_accepted(vulnlab_repo: Path) -> None:
    assert security.validate_repo(str(vulnlab_repo)) == str(vulnlab_repo)


@pytest.mark.parametrize(
    "value",
    ["--upload-pack=calc", "-x", "1.2.0; rm -rf /", "$(id)", "`id`", "a b", "v1\n2", "x" * 101],
)
def test_bad_versions_and_refs_are_refused(value: str) -> None:
    with pytest.raises(security.InvalidInputError):
        security.validate_version(value)
    with pytest.raises(security.InvalidInputError):
        security.validate_ref(value)


@pytest.mark.parametrize("value", ["8.5.0", "v1.2.0", "release/1.2", "1.2.0+build.7", "abc123"])
def test_plain_versions_and_refs_are_accepted(value: str) -> None:
    assert security.validate_version(value) == value
    assert security.validate_ref(value) == value


def test_empty_optional_fields_mean_not_given() -> None:
    assert security.validate_version("") is None
    assert security.validate_ref("  ") is None
    assert security.validate_product(None) is None


@pytest.mark.parametrize("value", ["curl;id", "a b", "-curl", "<curl>", "x" * 65])
def test_bad_product_names_are_refused(value: str) -> None:
    with pytest.raises(security.InvalidInputError):
        security.validate_product(value)


def test_the_pipeline_never_runs_on_an_invalid_repository(
    client: TestClient, token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []

    def spy(path: Path, **options: Any) -> CheckReport:
        calls.append(options)
        return fake_check_report(path, **options)

    monkeypatch.setattr(webapp, "check_report", spy)
    for repo in ("git://github.com/curl/curl", "/no/such/dir", "--upload-pack=calc", ""):
        response = client.post(
            url("/checks", token),
            data={"report_text": "hdr_get", "repo": repo, "version": "--evil"},
            headers=post_headers(),
            follow_redirects=False,
        )
        assert response.status_code == 400, repo
    assert calls == []


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\report.md", "report.md"),
        ('"><img src=x onerror=alert(1)>.md', "___img_src_x_onerror_alert_1__.md"),
        ("", "pasted report"),
        ("   ", "pasted report"),
        ("\u202ereport.md", "_report.md"),
    ],
)
def test_upload_names_are_reduced_to_a_safe_basename(given: str, expected: str) -> None:
    assert security.display_name(given) == expected


def test_only_known_extensions_steer_the_intake_format() -> None:
    assert security.suffix_for("report.MD") == ".md"
    assert security.suffix_for("report.html") == ".html"
    assert security.suffix_for("report.exe") == ""
    assert security.suffix_for("report") == ""


@pytest.mark.parametrize("entry_id", ["../1", "1e3", "-1", "1 ", "0x1", "x" * 10, "1234567890"])
def test_history_ids_that_are_not_ids_are_not_found(
    client: TestClient, token: str, entry_id: str
) -> None:
    response = client.get(url(f"/results/{entry_id}", token))
    assert response.status_code == 404
    assert security.validate_entry_id(entry_id) is None


# --- escaping and confidentiality ---------------------------------------------------------


def test_hostile_report_text_never_becomes_markup_in_the_ui(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir, text=HOSTILE).status_code == 303
    for path in ("/results/1", "/history"):
        html = client.get(url(path, token)).text
        doc = parse(html)
        assert [s for s in doc.tags("script") if not s.get("src")] == []
        assert doc.tags("img") == [] and doc.tags("svg") == [] and doc.tags("style") == []
        assert "<script>alert" not in html
        assert "onerror=" not in html


def test_hostile_form_values_are_echoed_only_as_text(client: TestClient, token: str) -> None:
    response = client.post(
        url("/checks", token),
        data={"report_text": HOSTILE, "repo": HOSTILE, "version": HOSTILE, "product": HOSTILE},
        headers=post_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 400
    doc = parse(response.text)
    assert [s for s in doc.tags("script") if not s.get("src")] == []
    assert doc.tags("img") == [] and doc.tags("svg") == []
    assert not any(k.startswith("on") for _, attrs in doc.elements for k in attrs)
    assert "<script>alert" not in response.text
    assert "".join(doc.text).count("alert(1)") >= 2, "the payload must survive as text"


def test_a_hostile_upload_name_is_shown_only_as_text(
    client: TestClient, token: str, git_dir: Path
) -> None:
    response = client.post(
        url("/checks", token),
        data={"repo": str(git_dir)},
        files={"report_file": ('"><img src=x onerror=alert(1)>.md', b"hdr_get\n", "text/markdown")},
        headers=post_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 303
    for path in ("/results/1", "/history"):
        doc = parse(client.get(url(path, token)).text)
        assert doc.tags("img") == []


def test_a_hostile_pipeline_message_is_shown_only_as_text(
    client: TestClient, token: str, git_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(path: Path, **options: Any) -> CheckReport:
        raise NikashaError(f"could not resolve {HOSTILE}")

    monkeypatch.setattr(webapp, "check_report", failing)
    response = submit(client, token, git_dir)
    assert response.status_code == 400
    doc = parse(response.text)
    assert [s for s in doc.tags("script") if not s.get("src")] == []
    assert doc.tags("img") == []
    assert "could not resolve" in "".join(doc.text)


def test_report_contents_are_never_logged(
    client: TestClient,
    token: str,
    git_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = "SECRET-MARKER-9f3a7c"

    def exploding(path: Path, **options: Any) -> CheckReport:
        raise RuntimeError("boom: " + Path(path).read_text(encoding="utf-8"))

    monkeypatch.setattr(webapp, "check_report", exploding)
    with caplog.at_level("DEBUG"):
        response = submit(client, token, git_dir, text=f"embargoed {marker}\n")
    assert response.status_code == 500
    assert marker not in response.text
    assert marker not in caplog.text
    assert "RuntimeError" in caplog.text


def test_the_result_json_carries_no_temporary_path(
    client: TestClient, token: str, git_dir: Path
) -> None:
    assert submit(client, token, git_dir).status_code == 303
    payload = json.loads(client.get(url("/results/1/result.json", token)).text)
    assert payload["report"]["source"]["uri"] == "pasted report"
    assert "nikasha-web-" not in json.dumps(payload)


def test_the_temporary_report_file_is_gone_after_the_check(
    client: TestClient, token: str, git_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Path] = []

    def spy(path: Path, **options: Any) -> CheckReport:
        seen.append(Path(path))
        assert Path(path).is_file()
        return fake_check_report(path, **options)

    monkeypatch.setattr(webapp, "check_report", spy)
    assert submit(client, token, git_dir).status_code == 303
    (path,) = seen
    assert not path.exists()
    assert not path.parent.exists()


def test_reproduction_cannot_be_requested_from_the_form(
    client: TestClient, token: str, git_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PoCs run only in the sandbox and only with --repro (P5); the UI has no such path."""
    calls: list[Any] = []
    monkeypatch.setattr(webapp, "check_report", lambda path, **o: calls.append(o))
    response = client.post(
        url("/checks", token),
        data={"report_text": "hdr_get", "repo": str(git_dir), "repro": "1"},
        headers=post_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "M5" in response.text
    assert calls == []
    form = client.get(url("/", token)).text
    assert re.search(r'<input[^>]*name="repro"[^>]*disabled', form)


def test_the_web_extra_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(NikashaError, match=r"nikasha\[web\]"):
        web_pkg.serve_forever(port=0)


# --- review findings (each fixed; each pinned here) -----------------------------------------


def test_a_post_without_content_length_is_refused(client: TestClient, token: str) -> None:
    """A chunked body would be spooled to disk before any upload cap applied."""

    def chunks() -> Iterator[bytes]:
        yield b"report_text=x&repo=y"

    response = client.post(url("/checks", token), content=chunks(), headers=post_headers())
    assert response.status_code == 411
    assert response.text == "Length Required"


def test_the_report_frame_does_not_share_the_ui_origin(
    client: TestClient, token: str, git_dir: Path
) -> None:
    """allow-scripts plus allow-same-origin would let the framed page lift the sandbox
    and read the parent's token-bearing links."""
    assert submit(client, token, git_dir).status_code == 303
    doc = parse(client.get(url("/results/1", token)).text)
    (frame,) = doc.tags("iframe")
    assert "allow-same-origin" not in frame["sandbox"]
    assert "allow-scripts" in frame["sandbox"]


@pytest.mark.parametrize("repo", [r"\attacker.example\share\repo", "//attacker.example/share"])
def test_a_unc_repository_path_is_refused_before_it_is_touched(repo: str) -> None:
    with pytest.raises(security.InvalidInputError):
        security.validate_repo(repo)


def test_an_empty_history_passed_in_is_the_one_used() -> None:
    history = webapp.History()
    tok = security.make_token()
    client = TestClient(create_app(token=tok, port=PORT, history=history), base_url=ORIGIN)
    history.add(_outcome())
    page = client.get(url("/history", tok)).text
    assert "nikasha-test-source" in page


def _outcome() -> webapp.CheckOutcome:
    return webapp.CheckOutcome(
        source="nikasha-test-source",
        verdict="GROUNDED",
        score=80,
        confidence="high",
        rule="R",
        repo="",
        ref="",
        commit="",
        html="<p></p>",
        json="{}",
        report_csp="default-src 'none'",
    )
