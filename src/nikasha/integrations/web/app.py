# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The local web UI (SPEC §16.4): three pages over the `nikasha check` pipeline.

* **New check** (``/``): paste or upload a report, name the repository and version, run.
* **Result** (``/results/<id>``): the verdict, downloads, and the self-contained HTML
  report from :mod:`nikasha.render.html` in a frame.
* **History** (``/history``): this session's results, in memory only, with a purge button.

A check is a **synchronous POST**: the pipeline runs in a worker thread while the browser
waits, and the response redirects to the result (POST, redirect, GET). Progress over
Server-Sent Events (a SHOULD in SPEC §16.4) is not done: the pipeline exposes no stage
callback, so a stream could only say "still running", which the browser's own spinner
already says. When the pipeline grows a progress hook the stream can be added without
changing the pages.

Who may talk to this server is decided in :mod:`nikasha.integrations.web.security`. This
module only renders pages, with Jinja autoescaping on and nothing input-derived ever marked
safe. Report contents are never logged: errors are logged by type, never by message.
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

from nikasha.errors import NikashaError
from nikasha.fuse.scoring import Ledger
from nikasha.ingest import InputFormat
from nikasha.integrations.web import security
from nikasha.integrations.web.security import InvalidInputError
from nikasha.model.result import Result
from nikasha.pipeline import check_report
from nikasha.render.html import render_html_result
from nikasha.render.html.components.hero import VERDICT_CLASS
from nikasha.render.html.excerpts import repo_excerpts
from nikasha.render.html.page import BASE_CSS
from nikasha.version import __version__

log = logging.getLogger(__name__)

TEMPLATES = Path(__file__).resolve().parent / "templates"

#: Results kept per session. Each holds a rendered report (SPEC §15.2 caps it at 1.5 MB).
MAX_HISTORY = 25

INPUT_FORMATS: tuple[InputFormat, ...] = ("auto", "markdown", "text", "html")

#: The report page's own policy, as :func:`nikasha.render.html.page.build_page` wrote it.
_META_CSP_RE = re.compile(
    r'<meta http-equiv="Content-Security-Policy" content="([^"]{1,4096})">',
)
_FALLBACK_REPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
_CHUNK = 1024 * 1024
_TOO_LARGE = f"The report is larger than the intake limit of {security.MAX_UPLOAD_BYTES:,} bytes."

#: The UI stylesheet: the report's base sheet (light and dark) plus the form and table.
UI_CSS = (
    BASE_CSS
    + """
.topbar { display: flex; flex-wrap: wrap; gap: 16px; align-items: baseline;
  padding: 16px 0; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
.topbar .brand { font-weight: 700; font-size: 18px; color: var(--fg); text-decoration: none; }
.topbar nav a { margin-right: 12px; }
.topbar nav a[aria-current="page"] { font-weight: 600; text-decoration: none; color: var(--fg); }
.topbar .spacer { flex: 1; }
.form-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 14px; max-width: 900px; }
.form-grid label { display: block; font-weight: 600; margin-bottom: 4px; }
.form-grid label.inline { display: flex; gap: 8px; align-items: center; font-weight: 400; }
.form-grid input[type="text"], .form-grid select, .form-grid textarea {
  width: 100%; font: inherit; color: var(--fg); background: var(--bg);
  border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 10px; }
.form-grid textarea { font-family: var(--mono); font-size: 13px; min-height: 260px; }
button { font: inherit; padding: 8px 16px; border-radius: var(--radius);
  border: 1px solid var(--border); background: var(--panel); color: var(--fg); cursor: pointer; }
button.primary { background: var(--link); color: #fff; border-color: var(--link); }
button:disabled { opacity: .6; cursor: progress; }
.hint { color: var(--muted); font-size: 13px; margin: 2px 0 0; }
.notice { margin: 0 0 16px; }
.notice.error { border-left: 4px solid var(--bad); }
table.history { width: 100%; border-collapse: collapse; }
table.history th, table.history td { text-align: left; padding: 8px;
  border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: anywhere; }
iframe.report { width: 100%; height: calc(100vh - 280px); min-height: 480px;
  border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg); }
.actions { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 12px 0; }
dl.facts { display: grid; grid-template-columns: max-content minmax(0, 1fr);
  gap: 4px 16px; margin: 0; }
dl.facts dt { color: var(--muted); }
dl.facts dd { margin: 0; overflow-wrap: anywhere; }
"""
)

#: The one script. No inline handlers anywhere: the policy is ``script-src 'self'``.
UI_JS = """
(function () {
  "use strict";
  var form = document.getElementById("check-form");
  if (form) {
    form.addEventListener("submit", function () {
      var button = document.getElementById("submit");
      var status = document.getElementById("status");
      if (button) { button.disabled = true; button.textContent = "Checking\\u2026"; }
      if (status) {
        status.textContent = "Resolving, indexing and checking. A large repository " +
          "can take a minute the first time.";
      }
    });
  }
  var purge = document.getElementById("purge-form");
  if (purge) {
    purge.addEventListener("submit", function (event) {
      if (!window.confirm("Forget every result of this session?")) { event.preventDefault(); }
    });
  }
})();
"""


class TooLargeError(InvalidInputError):
    """The report exceeds the intake cap (HTTP 413)."""


@dataclass(frozen=True, slots=True)
class CheckRequest:
    """One validated submission of the New check form."""

    data: bytes
    name: str
    suffix: str
    repo: str
    version: str | None
    ref: str | None
    product: str | None
    input_format: InputFormat
    online: bool


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    """What one check produced, ready to show and to download."""

    source: str
    verdict: str
    score: int | None
    confidence: str
    rule: str
    repo: str
    ref: str
    commit: str
    html: str
    json: str
    report_csp: str

    @property
    def css_class(self) -> str:
        return VERDICT_CLASS.get(self.verdict, "unknown")


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    id: str
    outcome: CheckOutcome


class History:
    """This session's results, in memory only, newest first (SPEC §16.4)."""

    def __init__(self, limit: int = MAX_HISTORY) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, HistoryEntry] = OrderedDict()
        self._next = 1

    def add(self, outcome: CheckOutcome) -> HistoryEntry:
        with self._lock:
            entry = HistoryEntry(id=str(self._next), outcome=outcome)
            self._next += 1
            self._entries[entry.id] = entry
            while len(self._entries) > self.limit:
                self._entries.popitem(last=False)
            return entry

    def get(self, entry_id: str) -> HistoryEntry | None:
        with self._lock:
            return self._entries.get(entry_id)

    def entries(self) -> list[HistoryEntry]:
        with self._lock:
            return list(reversed(self._entries.values()))

    def purge(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# --- running a check ------------------------------------------------------------------------


def run_check(request: CheckRequest, *, runner: Callable[..., Any] | None = None) -> CheckOutcome:
    """Run the pipeline over one submission. Blocking; called from a worker thread.

    The report is written to a private temporary directory only because the pipeline reads
    a path, and that directory is removed before this returns. The result's recorded
    source is the display name, never the temporary path, so two runs on the same paste
    produce the same JSON (P2).
    """
    check = runner or check_report
    workdir = Path(tempfile.mkdtemp(prefix="nikasha-web-"))
    try:
        path = workdir / f"report{request.suffix}"
        path.write_bytes(request.data)
        checked = check(
            path,
            repo=request.repo,
            ref=request.ref,
            version=request.version,
            product=request.product,
            input_format=request.input_format,
            online=request.online,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    result = _with_source_name(checked.result, request.name)
    html = _render(result, checked.ledger, request.name)
    verdict = result.verdict
    target = result.target
    return CheckOutcome(
        source=request.name,
        verdict=verdict.label if verdict else "ERROR",
        score=verdict.score if verdict else None,
        confidence=verdict.confidence if verdict else "low",
        rule=(verdict.rule or "") if verdict else "",
        repo=target.repo_url if target else "",
        ref=(target.ref_name or "") if target else "",
        commit=(target.commit or "") if target else "",
        html=html,
        json=result.to_json(),
        report_csp=report_policy(html),
    )


def _with_source_name(result: Result, name: str) -> Result:
    source = result.report.source.model_copy(update={"uri": name})
    report = result.report.model_copy(update={"source": source})
    return result.model_copy(update={"report": report})


def _render(result: Result, ledger: Ledger | None, source: str) -> str:
    """The HTML report, with code excerpts when the repository can be reopened."""
    repo_url = result.target.repo_url if result.target else ""
    try:
        with repo_excerpts(repo_url) as excerpts:
            return render_html_result(result, ledger=ledger, excerpts=excerpts, source=source)
    except NikashaError:
        return render_html_result(result, ledger=ledger, source=source)


def report_policy(html: str) -> str:
    """The report page's policy as a header, plus permission to be framed by this UI.

    The rendered page already carries its policy in a ``<meta>`` element (one hashed
    script, no fetches). Sending the same policy as a header means the browser enforces
    it before parsing a byte, and ``frame-ancestors`` only works as a header anyway.
    """
    match = _META_CSP_RE.search(html)
    base = match.group(1) if match else _FALLBACK_REPORT_CSP
    return f"{base}; frame-ancestors 'self'"


# --- the form -------------------------------------------------------------------------------

EMPTY_FORM: dict[str, str] = {
    "report_text": "",
    "repo": "",
    "version": "",
    "ref": "",
    "product": "",
    "input_format": "auto",
    "online": "",
}


def _field(form: FormData, key: str) -> str:
    value = form.get(key)
    return value if isinstance(value, str) else ""


def _echo(form: FormData) -> dict[str, str]:
    """The typed fields, to put back into the form after a validation error."""
    return {key: _field(form, key) for key in EMPTY_FORM}


async def _read_capped(upload: UploadFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(_CHUNK):
        total += len(chunk)
        if total > security.MAX_UPLOAD_BYTES:
            raise TooLargeError(_TOO_LARGE)
        chunks.append(chunk)
    return b"".join(chunks)


async def read_check_form(form: FormData) -> CheckRequest:
    """Validate every field before anything is used (security rule 6)."""
    if _field(form, "repro"):
        raise InvalidInputError(
            "Reproduction runs only inside the sandbox and arrives in milestone M5; "
            "leave that option off."
        )
    text = _field(form, "report_text")
    upload = form.get("report_file")
    data = b""
    name = "pasted report"
    if isinstance(upload, UploadFile) and upload.filename:
        data = await _read_capped(upload)
        name = security.display_name(upload.filename)
    if data and text.strip():
        raise InvalidInputError("Paste a report or upload one, not both.")
    if not data:
        data = text.encode("utf-8")
        if len(data) > security.MAX_UPLOAD_BYTES:
            raise TooLargeError(_TOO_LARGE)
    if not data.strip():
        raise InvalidInputError("Paste a report or upload one.")
    fmt = _field(form, "input_format") or "auto"
    if fmt not in INPUT_FORMATS:
        raise InvalidInputError("The format must be auto, markdown, text or html.")
    input_format: InputFormat = fmt
    return CheckRequest(
        data=data,
        name=name,
        suffix=security.suffix_for(name),
        repo=security.validate_repo(_field(form, "repo")),
        version=security.validate_version(_field(form, "version")),
        ref=security.validate_ref(_field(form, "ref")),
        product=security.validate_product(_field(form, "product")),
        input_format=input_format,
        online=_field(form, "online") == "1",
    )


# --- the application ------------------------------------------------------------------------


@dataclass
class _State:
    token: str
    port: int
    history: History
    env: Environment
    check_lock: threading.Lock

    def href(self, path: str) -> str:
        """A same-origin link that carries the access token."""
        return f"{path}?{security.TOKEN_QUERY}={quote(self.token, safe='')}"

    def page(self, template: str, *, status: int = 200, **context: object) -> HTMLResponse:
        html = self.env.get_template(template).render(
            href=self.href,
            tool_version=__version__,
            max_upload_bytes=security.MAX_UPLOAD_BYTES,
            **context,
        )
        return HTMLResponse(html, status_code=status)

    def error(self, status: int, title: str, message: str) -> HTMLResponse:
        return self.page(
            "error.html", status=status, page=None, title=title, message=message, code=status
        )


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=True,
        undefined=StrictUndefined,
        auto_reload=False,
    )


def create_app(*, token: str, port: int, history: History | None = None) -> FastAPI:
    """Build the application for one run: one token, one port, one in-memory history."""
    state = _State(
        token=token,
        port=port,
        history=history if history is not None else History(),
        env=_environment(),
        check_lock=threading.Lock(),
    )
    # No generated API docs: they would load Swagger UI from a CDN, and there is no API.
    app = FastAPI(title="Nikasha", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(security.HardeningMiddleware, token=token, port=port)

    def entry_or_none(entry_id: str) -> HistoryEntry | None:
        valid = security.validate_entry_id(entry_id)
        return state.history.get(valid) if valid else None

    def not_found() -> HTMLResponse:
        return state.error(404, "Not found", "There is no such result in this session.")

    def locked_check(check: CheckRequest) -> CheckOutcome:
        """One check at a time (they share the repository index). Runs in a worker thread,
        so the lock waits there and never blocks the event loop."""
        with state.check_lock:
            return run_check(check)

    _install_support_routes(app, state)

    @app.get("/")
    async def new_check() -> Response:
        return state.page("new.html", page="new", form=EMPTY_FORM, error=None)

    @app.post("/checks")
    async def submit_check(request: Request) -> Response:
        try:
            form = await request.form(
                max_files=2, max_fields=16, max_part_size=security.MAX_REQUEST_BYTES
            )
        except Exception as exc:  # multipart errors come in several classes
            log.info("a form could not be parsed (%s)", type(exc).__name__)
            return state.error(400, "Bad request", "The form could not be read.")
        echo = _echo(form)
        try:
            check = await read_check_form(form)
        except TooLargeError as exc:
            return state.error(413, "Too large", str(exc))
        except InvalidInputError as exc:
            return state.page("new.html", status=400, page="new", form=echo, error=str(exc))
        finally:
            await form.close()
        try:
            outcome = await run_in_threadpool(locked_check, check)
        except NikashaError as exc:
            return state.page("new.html", status=400, page="new", form=echo, error=str(exc))
        except Exception as exc:  # never the message: it may quote the report
            log.warning("a check failed with %s", type(exc).__name__)
            return state.error(500, "Check failed", "The check could not be completed.")
        entry = state.history.add(outcome)
        return RedirectResponse(state.href(f"/results/{entry.id}"), status_code=303)

    @app.get("/results/{entry_id}")
    async def result_page(entry_id: str) -> Response:
        entry = entry_or_none(entry_id)
        if entry is None:
            return not_found()
        return state.page("result.html", page="result", entry=entry)

    @app.get("/results/{entry_id}/report")
    async def report_page(entry_id: str) -> Response:
        entry = entry_or_none(entry_id)
        if entry is None:
            return not_found()
        return HTMLResponse(
            entry.outcome.html, headers=security.security_headers(entry.outcome.report_csp)
        )

    @app.get("/results/{entry_id}/report.html")
    async def report_download(entry_id: str) -> Response:
        entry = entry_or_none(entry_id)
        if entry is None:
            return not_found()
        return HTMLResponse(
            entry.outcome.html,
            headers={
                "content-disposition": f'attachment; filename="nikasha-result-{entry.id}.html"',
                **security.security_headers(entry.outcome.report_csp),
            },
        )

    @app.get("/results/{entry_id}/result.json")
    async def json_download(entry_id: str) -> Response:
        entry = entry_or_none(entry_id)
        if entry is None:
            return not_found()
        return Response(
            entry.outcome.json,
            media_type="application/json",
            headers={
                "content-disposition": f'attachment; filename="nikasha-result-{entry.id}.json"'
            },
        )

    @app.get("/history")
    async def history_page() -> Response:
        return state.page("history.html", page="history", entries=state.history.entries())

    @app.post("/history/purge")
    async def purge_history() -> Response:
        state.history.purge()
        return RedirectResponse(state.href("/history"), status_code=303)

    return app


def _install_support_routes(app: FastAPI, state: _State) -> None:
    """The static assets and the two error handlers (generic pages, nothing echoed)."""

    @app.get("/static/ui.css")
    async def stylesheet() -> Response:
        return Response(UI_CSS, media_type="text/css; charset=utf-8")

    @app.get("/static/ui.js")
    async def script() -> Response:
        return Response(UI_JS, media_type="text/javascript; charset=utf-8")

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError) -> Response:
        return state.error(400, "Bad request", "The request could not be read.")

    @app.exception_handler(Exception)
    async def server_error(request: Request, exc: Exception) -> Response:
        log.warning("unhandled %s while serving %s", type(exc).__name__, request.url.path)
        return state.error(500, "Server error", "Something went wrong on this machine.")


__all__ = [
    "EMPTY_FORM",
    "INPUT_FORMATS",
    "MAX_HISTORY",
    "UI_CSS",
    "UI_JS",
    "CheckOutcome",
    "CheckRequest",
    "History",
    "HistoryEntry",
    "TooLargeError",
    "create_app",
    "read_check_form",
    "report_policy",
    "run_check",
]
