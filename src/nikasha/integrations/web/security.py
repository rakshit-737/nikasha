# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Hardening for the local web UI (SPEC §16.4, §19.2).

The lesson is the MCP Inspector RCE (CVE-2025-49596): a development server bound to
localhost, with no authentication and no ``Origin`` check, so any web page the user had
open could reach it, by a plain cross-site request or by rebinding an attacker's hostname
onto ``127.0.0.1``. "It only listens on localhost" is not a boundary: every browser tab on
the machine is on localhost too.

Six rules, each with a test in ``tests/security/test_web_hardening.py``:

1. **Loopback only.** The socket is bound to ``127.0.0.1`` on a random free port. There is
   no option to bind anywhere else.
2. **An access token in the URL.** ``secrets.token_urlsafe(32)`` per run, printed once.
   Every request must present it (query string or header), compared in constant time. A
   missing or wrong token is a 403 that says nothing more than "Forbidden".
3. **The Host header must be ours.** ``127.0.0.1:<port>`` or ``localhost:<port>``, else
   421. A DNS-rebound hostname fails here before anything else is looked at.
4. **Every POST needs a same-origin Origin.** The Origin must be exactly ``http://<Host>``;
   missing or foreign is a 403. Cookies are never used, so a browser cannot be tricked
   into presenting a credential it does not know it has.
5. **Security headers on every response**: a ``default-src 'none'`` policy, ``nosniff``,
   ``no-referrer`` (the token is in the URL, so the referrer must never leave the page),
   ``Cross-Origin-Opener-Policy: same-origin`` and ``no-store``.
6. **Caps and validation before use.** Upload and paste sizes match the intake limits; a
   repository is a local git directory or an ``https://`` URL and nothing else; versions,
   refs and product names must fit conservative patterns.

This module imports no web framework, so the rules can be read and tested on their own.
The middleware is plain ASGI for the same reason.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote

from nikasha.code.gitio import safe_rev
from nikasha.errors import ForbiddenCommandError, NikashaError
from nikasha.ingest import MAX_INPUT_BYTES
from nikasha.ingest.attachments import sanitize_name
from nikasha.resolve.repo import canonical_url

#: The only address the server ever binds. Not configurable, on purpose.
LOOPBACK = "127.0.0.1"

#: Host names a browser may use to reach the loopback server.
ALLOWED_HOSTNAMES = ("127.0.0.1", "localhost")

#: Where a request presents the access token (these are parameter names, not secrets).
TOKEN_QUERY = "token"  # noqa: S105
TOKEN_HEADER = "x-nikasha-token"  # noqa: S105

#: The upload cap is the intake cap; the request cap leaves room for the other fields.
MAX_UPLOAD_BYTES = MAX_INPUT_BYTES
MAX_FORM_OVERHEAD = 64 * 1024
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + MAX_FORM_OVERHEAD

#: The policy for the UI's own pages: same-origin assets only, no inline script, no
#: framing by anyone else. The framed report page gets its own policy (see ``app``).
UI_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "frame-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

#: File extensions the intake recognises (``nikasha.ingest.detect_format``); anything
#: else is sniffed from the content.
KNOWN_SUFFIXES = (".md", ".markdown", ".mdown", ".txt", ".text", ".log", ".html", ".htm")

MAX_REPO_LEN = 1024
_PRINTABLE = 0x20
_VERSION_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+/-]{0,99}\Z")
_PRODUCT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_ENTRY_ID_RE = re.compile(r"\A[0-9]{1,9}\Z")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class InvalidInputError(NikashaError):
    """A form field failed validation. The message is safe to show back to the user."""


# --- tokens, hosts and origins ------------------------------------------------------------


def make_token() -> str:
    """A fresh access token: 32 random bytes, URL-safe, never derived from anything."""
    return secrets.token_urlsafe(32)


def token_ok(presented: str | None, expected: str) -> bool:
    """Constant-time comparison; an absent token never matches."""
    if not presented or not expected:
        return False
    return secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def allowed_hosts(port: int) -> frozenset[str]:
    """The exact ``Host`` header values this server answers to."""
    hosts = {f"{name}:{port}" for name in ALLOWED_HOSTNAMES}
    if port == 80:  # noqa: PLR2004 - the one port a browser omits from Host
        hosts.update(ALLOWED_HOSTNAMES)
    return frozenset(hosts)


def host_ok(host: str | None, port: int) -> bool:
    """Is ``host`` one of ours? Case-insensitive on the name, exact on the port."""
    if not host:
        return False
    return host.strip().lower() in allowed_hosts(port)


def origin_ok(origin: str | None, host: str | None, port: int) -> bool:
    """Is ``origin`` exactly the page's own origin, ``http://<Host>``?

    The scheme is always plain ``http``: the server never speaks TLS, and a browser does
    not send an ``https`` origin to it. ``null`` (sandboxed frames, ``file://`` pages,
    redirects across sites) is foreign.
    """
    if not origin or host is None or not host_ok(host, port):
        return False
    return origin.strip().lower() == f"http://{host.strip().lower()}"


def build_url(port: int, token: str) -> str:
    """The one URL that is printed at start-up."""
    return f"http://{LOOPBACK}:{port}/?{TOKEN_QUERY}={quote(token, safe='')}"


def bind_loopback(port: int = 0) -> socket.socket:
    """Bind a listening socket to ``127.0.0.1`` (``port`` 0 lets the OS pick a free one)."""
    if not 0 <= port <= 65535:  # noqa: PLR2004
        raise NikashaError(f"port must be between 0 and 65535, not {port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            # Lets a restart reuse a port still in TIME_WAIT. Not on Windows, where the
            # same flag would let another process bind the same port.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOOPBACK, port))
        sock.listen(128)
    except OSError as exc:
        sock.close()
        raise NikashaError(f"cannot listen on {LOOPBACK}:{port}: {exc.strerror or exc}") from exc
    return sock


def security_headers(csp: str = UI_CSP) -> dict[str, str]:
    """The headers every response carries (rule 5)."""
    return {
        "content-security-policy": csp,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "x-frame-options": "DENY" if "frame-ancestors 'none'" in csp else "SAMEORIGIN",
        "cache-control": "no-store",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }


# --- the middleware ----------------------------------------------------------------------


def _headers_of(scope: Scope) -> dict[str, str]:
    """The request headers, lower-cased, first value wins (so a second Host cannot help)."""
    found: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", ()):
        name = bytes(raw_name).decode("latin-1").lower()
        if name not in found:
            found[name] = bytes(raw_value).decode("latin-1")
    return found


def _token_of(scope: Scope, headers: dict[str, str]) -> str | None:
    header = headers.get(TOKEN_HEADER)
    if header:
        return header
    query = bytes(scope.get("query_string", b"")).decode("latin-1")
    try:
        pairs = parse_qsl(query, keep_blank_values=False, max_num_fields=64)
    except ValueError:  # more fields than any page of ours sends
        return None
    for key, value in pairs:
        if key == TOKEN_QUERY:
            return value
    return None


def _content_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return -1


class HardeningMiddleware:
    """Rules 2 to 5 as one plain ASGI layer in front of the application.

    Checks run in the order an attacker meets them: Host first (a rebound name is refused
    before anything is looked at), then the token, then the method and the Origin.
    Refusals are short plain-text responses with no detail and no template.
    """

    def __init__(self, app: ASGIApp, *, token: str, port: int) -> None:
        self.app = app
        self.token = token
        self.port = port

    def refusal(self, scope: Scope) -> tuple[int, str] | None:
        """``(status, reason)`` when the request must not reach the application."""
        headers = _headers_of(scope)
        host = headers.get("host")
        if not host_ok(host, self.port):
            return 421, "Misdirected Request"
        if not token_ok(_token_of(scope, headers), self.token):
            return 403, "Forbidden"
        method = str(scope.get("method", "")).upper()
        if method not in ("GET", "HEAD", "POST"):
            return 405, "Method Not Allowed"
        return _post_refusal(headers, host, self.port) if method == "POST" else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(scope, receive, send)
            return
        if kind != "http":
            # No WebSockets: nothing in the UI needs one, so nothing may open one.
            await send({"type": "websocket.close", "code": 1008})
            return
        refused = self.refusal(scope)
        if refused is not None:
            await _refuse(send, *refused)
            return

        async def send_with_headers(message: Message) -> None:
            if message.get("type") == "http.response.start":
                raw = list(message.get("headers", []))
                present = {bytes(name).decode("latin-1").lower() for name, _ in raw}
                for name, value in security_headers().items():
                    if name not in present:
                        raw.append((name.encode("latin-1"), value.encode("latin-1")))
                message["headers"] = raw
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _post_refusal(headers: dict[str, str], host: str | None, port: int) -> tuple[int, str] | None:
    """Rule 4, plus the request-size cap, for a POST that already passed rules 2 and 3."""
    if not origin_ok(headers.get("origin"), host, port):
        return 403, "Forbidden"
    site = headers.get("sec-fetch-site")
    if site is not None and site.strip().lower() not in ("same-origin", "none"):
        return 403, "Forbidden"
    length = _content_length(headers)
    if length is None:
        # Browsers always send Content-Length with a form post. Without it (chunked
        # transfer) the multipart parser would spool an unbounded body to disk before the
        # upload cap is ever applied, so a POST without a declared length is refused.
        return 411, "Length Required"
    if length < 0 or length > MAX_REQUEST_BYTES:
        return 413, "Payload Too Large"
    return None


async def _refuse(send: Send, status: int, reason: str) -> None:
    body = reason.encode("ascii")
    headers = [
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    headers += [(k.encode("latin-1"), v.encode("latin-1")) for k, v in security_headers().items()]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


# --- input validation (rule 6) ---------------------------------------------------------------


def _has_controls(value: str) -> bool:
    return any(ord(ch) < _PRINTABLE or ch == "\x7f" for ch in value)


def _looks_like_git_dir(path: Path) -> bool:
    if (path / "HEAD").is_file() and (path / "objects").is_dir():
        return True
    dot_git = path / ".git"
    return dot_git.is_dir() or dot_git.is_file()


def validate_repo(value: str) -> str:
    """A local git directory or an ``https://`` URL; anything else is refused before use.

    The path is checked for existence and shape here so the pipeline never runs against
    a name that was never a repository; the URL goes through the same canonicaliser the
    clone cache uses, so ``file:``, ``ssh:``, ``git@`` and friends never reach git.
    """
    repo = value.strip()
    if not repo:
        raise InvalidInputError("A repository is required: a local path or an https:// URL.")
    if len(repo) > MAX_REPO_LEN or _has_controls(repo):
        raise InvalidInputError("The repository field is too long or contains control characters.")
    if repo.startswith("-"):
        raise InvalidInputError("A repository path may not start with '-'.")
    lowered = repo.lower()
    if "://" in repo or lowered.startswith(("git@", "ssh:", "file:", "javascript:", "data:")):
        if not lowered.startswith("https://"):
            raise InvalidInputError("Only https:// repository URLs are accepted.")
        try:
            return canonical_url(repo)
        except NikashaError as exc:
            raise InvalidInputError(str(exc)) from exc
    if repo.startswith(("\\\\", "//")):
        # A UNC path makes Windows open an SMB connection (and offer NTLM credentials)
        # to whatever host it names, just by checking whether it exists.
        raise InvalidInputError("Network (UNC) paths are not accepted; use a local path.")
    path = Path(repo).expanduser()
    if not path.is_dir():
        raise InvalidInputError("The repository path does not exist or is not a directory.")
    if not _looks_like_git_dir(path):
        raise InvalidInputError("The path is not a git repository (no HEAD and objects, no .git).")
    return str(path)


def validate_version(value: str | None) -> str | None:
    """A release string such as ``8.5.0`` or ``v1.2.0``; empty means "not given"."""
    version = (value or "").strip()
    if not version:
        return None
    if not _VERSION_RE.match(version):
        raise InvalidInputError(
            "The version may only contain letters, digits and . _ + / - and must not "
            "start with '-'."
        )
    return version


def validate_ref(value: str | None) -> str | None:
    """A git ref; the same rule as :func:`validate_version` plus the git-argv rule."""
    ref = validate_version(value)
    if ref is None:
        return None
    try:
        safe_rev(ref)
    except ForbiddenCommandError as exc:
        raise InvalidInputError("That git ref is not acceptable.") from exc
    return ref


def validate_product(value: str | None) -> str | None:
    product = (value or "").strip()
    if not product:
        return None
    if not _PRODUCT_RE.match(product):
        raise InvalidInputError("The product name may only contain letters, digits and . _ -.")
    return product


def validate_entry_id(value: str) -> str | None:
    """A history id, or ``None`` when the path segment is not one."""
    return value if _ENTRY_ID_RE.match(value) else None


def display_name(filename: str | None) -> str:
    """A safe display name for an uploaded report (never a path, never control characters)."""
    if not filename or not filename.strip():
        return "pasted report"
    return sanitize_name(filename.strip())


def suffix_for(name: str) -> str:
    """The extension the intake will recognise, or ``""`` to let it sniff the content."""
    suffix = Path(name).suffix.lower()
    return suffix if suffix in KNOWN_SUFFIXES else ""


__all__ = [
    "ALLOWED_HOSTNAMES",
    "KNOWN_SUFFIXES",
    "LOOPBACK",
    "MAX_REQUEST_BYTES",
    "MAX_UPLOAD_BYTES",
    "TOKEN_HEADER",
    "TOKEN_QUERY",
    "UI_CSP",
    "HardeningMiddleware",
    "InvalidInputError",
    "allowed_hosts",
    "bind_loopback",
    "build_url",
    "display_name",
    "host_ok",
    "make_token",
    "origin_ok",
    "security_headers",
    "suffix_for",
    "token_ok",
    "validate_entry_id",
    "validate_product",
    "validate_ref",
    "validate_repo",
    "validate_version",
]
