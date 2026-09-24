# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Email intake (SPEC §8, §16.5): one ``.eml`` message becomes a :class:`Report`.

The stdlib ``email`` package with ``policy=email.policy.default`` does the parsing; nothing
here is rendered or executed. The rules:

* **Body.** Every inline ``text/plain`` leaf is used (joined by a blank line, in message
  order); when there is none, the first ``text/html`` leaves go through the HTML intake.
  Nested ``message/rfc822`` parts (forwarded reports) are walked like any other container.
  The :class:`~nikasha.model.report.SourceMap` maps back to the *decoded* text of those
  parts, not to the raw ``.eml`` bytes (transfer encodings make raw offsets meaningless).
* **Headers.** ``Subject`` is the title and ``Date`` is ``reported_at``. **The sender's
  identity is never stored** (SPEC §7): ``From``, ``To``, ``Cc``, ``Reply-To``, ``Sender``,
  ``Message-ID`` and every other header are not read at all, so nothing can leak into the
  result even by accident.
* **Attachments.** Every other leaf, and every text leaf that carries a filename or an
  ``attachment`` disposition, goes through :mod:`nikasha.ingest.attachments` with its
  size caps and filename sanitisation. Archives are never extracted here.
* **``git format-patch`` mails** are recognised (a ``[PATCH …]`` subject or a ``---``
  separator, plus a ``diff --git`` line) and their diff becomes a ``patch`` code block so
  the patch extractor sees the whole diff, even if a mail client ate the context spaces.

Hostile input (P7) is the normal case: oversized or absurdly many parts are capped, bogus
``Content-Type`` values fall back to ``text/plain``/UTF-8, undecodable bytes become U+FFFD,
and header values are flattened to one printable line so an encoded-word cannot smuggle a
line break into a title. Nothing here depends on the clock or on the environment.
"""

from __future__ import annotations

import codecs
import email
import email.errors
import email.policy
import email.utils
import hashlib
import re
import shutil
from dataclasses import dataclass, field
from datetime import date
from email.message import Message
from pathlib import Path

from nikasha.config import cache_dir, ensure_private_dir
from nikasha.errors import NikashaError
from nikasha.ingest.attachments import AttachmentLimits, store_attachments
from nikasha.ingest.html import ingest_html
from nikasha.ingest.markdown import ingest_markdown
from nikasha.ingest.text import MAX_BODY_CHARS, ingest_text, report_id
from nikasha.model.report import Attachment, CodeBlock, Report, ReportSource

#: Raw ``.eml`` input larger than this is refused (same cap as every other intake).
MAX_EML_BYTES = 20 * 1024 * 1024
#: Leaf parts beyond this many are ignored with a warning (a multipart bomb is cheap to send).
MAX_PARTS = 500
#: A header value longer than this is cut (titles are read by humans, not parsed).
MAX_HEADER_CHARS = 500
#: Containers nested deeper than this are not walked (a forwarding chain is a few levels).
MAX_DEPTH = 32
#: Parts that exist only to carry headers (bounces, read receipts, forwarded header blocks).
#: They hold addresses and ``Received`` lines, so they are dropped, never stored (SPEC §7).
HEADER_ONLY_TYPES = frozenset(
    {
        "text/rfc822-headers",
        "message/rfc822-headers",
        "message/delivery-status",
        "message/global-delivery-status",
        "message/global-headers",
        "message/disposition-notification",
        "message/global-disposition-notification",
        "message/feedback-report",
    }
)

_HEADER_ERRORS = (
    email.errors.MessageError,
    ValueError,
    LookupError,
    TypeError,
    IndexError,
    AttributeError,
    UnicodeError,
)
_BODY_TYPES = frozenset({"text/plain", "text/html"})
_PATCH_SUBJECT_RE = re.compile(r"\A\s{0,20}\[(?:[^\]\n]{0,60}?\s)?PATCH\b", re.IGNORECASE)
_DIFF_GIT_RE = re.compile(r"^diff --git ", re.MULTILINE)
_SEPARATOR_RE = re.compile(r"^---[ \t]{0,10}$", re.MULTILINE)
_SIGNATURE_RE = re.compile(r"^-- $", re.MULTILINE)


@dataclass(slots=True)
class _Parts:
    texts: list[tuple[str, str]] = field(default_factory=list)  # (content type, decoded text)
    attachments: list[tuple[str, bytes]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# --- header helpers ----------------------------------------------------------------------------


def _one_line(value: str, limit: int = MAX_HEADER_CHARS) -> str:
    """Collapse whitespace (including any CR/LF an encoded word smuggled in) and drop every
    non-printable character, so a header can only ever be a single readable line."""
    flat = " ".join(value.split())
    printable = "".join(ch for ch in flat if ch == " " or ch.isprintable())
    return printable[:limit].strip()


def header_text(msg: Message, name: str) -> str | None:
    """One decoded, single-line header value, or ``None`` when absent or unparsable."""
    try:
        value = msg.get(name)
        text = None if value is None else str(value)
    except _HEADER_ERRORS:
        return None
    if text is None:
        return None
    return _one_line(text) or None


def header_date(msg: Message) -> date | None:
    """The ``Date`` header as a date (the sender's own calendar day; never the clock)."""
    raw = header_text(msg, "Date")
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None
    return parsed.date()


# --- part helpers ------------------------------------------------------------------------------


def _content_type(part: Message) -> str:
    try:
        return part.get_content_type().lower()
    except _HEADER_ERRORS:
        return "text/plain"


def _disposition(part: Message) -> str | None:
    try:
        value = part.get_content_disposition()
    except _HEADER_ERRORS:
        return None
    return value.lower() if isinstance(value, str) else None


def _filename(part: Message) -> str | None:
    try:
        value = part.get_filename()
    except _HEADER_ERRORS:
        return None
    if not isinstance(value, str):
        return None
    return _one_line(value, 255) or None


def _charset(part: Message) -> str:
    try:
        value = part.get_content_charset()
    except _HEADER_ERRORS:
        return "utf-8"
    if not isinstance(value, str) or not value:
        return "utf-8"
    try:
        codecs.lookup(value)
    except LookupError:
        return "utf-8"
    return value


def _payload(part: Message) -> bytes | None:
    """The transfer-decoded bytes of a leaf part, or ``None`` when they cannot be produced."""
    try:
        raw = part.get_payload(decode=True)
    except _HEADER_ERRORS:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return None


def _decode_text(data: bytes, charset: str) -> str:
    if charset.replace("_", "-").lower() in ("utf-8", "utf8"):
        charset = "utf-8-sig"
    return data.decode(charset, errors="replace")


#: Extensions for unnamed parts. A fixed table, not :mod:`mimetypes`, whose answers depend on
#: the machine's registry; an attachment name is part of the output and must not.
_EXTENSIONS: dict[str, str] = {
    "text/plain": ".txt",
    "text/html": ".html",
    "text/x-diff": ".diff",
    "text/x-patch": ".patch",
    "application/json": ".json",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/gzip": ".gz",
    "application/x-tar": ".tar",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
}


def _synthesized_name(index: int, content_type: str) -> str:
    return f"part-{index}{_EXTENSIONS.get(content_type, '.bin')}"


def _children(part: Message) -> list[Message]:
    try:
        if not part.is_multipart():
            return []
        payload = part.get_payload()
    except _HEADER_ERRORS:
        return []
    if not isinstance(payload, list):
        return []
    return [child for child in payload if isinstance(child, Message)]


def _walk(msg: Message, warnings: list[str]) -> list[tuple[Message, bool]]:
    """Every part in message order, iteratively (``Message.walk`` recurses), with a depth
    cap. Each entry says whether the part is a container."""
    found: list[tuple[Message, bool]] = []
    stack: list[tuple[Message, int]] = [(msg, 0)]
    too_deep = False
    while stack:
        part, depth = stack.pop()
        if _content_type(part) in HEADER_ONLY_TYPES:
            found.append((part, False))
            continue
        children = _children(part)
        try:
            container = part.is_multipart()
        except _HEADER_ERRORS:
            container = False
        found.append((part, container))
        if not container:
            continue
        if depth >= MAX_DEPTH:
            too_deep = True
            continue
        stack.extend((child, depth + 1) for child in reversed(children))
        if len(found) > 4 * MAX_PARTS:
            warnings.append(f"email has more than {4 * MAX_PARTS} parts; the rest were ignored")
            break
    if too_deep:
        warnings.append(f"email nests parts deeper than {MAX_DEPTH} levels; those were ignored")
    return found


def collect_parts(msg: Message) -> _Parts:
    """Split a parsed message into body texts and attachment payloads (message order)."""
    parts = _Parts()
    seen = 0
    dropped_headers = 0
    for part, container in _walk(msg, parts.warnings):
        if container:
            continue
        seen += 1
        if seen > MAX_PARTS:
            parts.warnings.append(f"email has more than {MAX_PARTS} parts; the rest were ignored")
            break
        content_type = _content_type(part)
        if content_type in HEADER_ONLY_TYPES:
            dropped_headers += 1
            continue
        payload = _payload(part)
        if payload is None:
            parts.warnings.append(f"part {seen} ({content_type}) could not be decoded; skipped")
            continue
        filename = _filename(part)
        inline_text = (
            content_type in _BODY_TYPES and _disposition(part) != "attachment" and filename is None
        )
        if inline_text:
            text = _decode_text(payload, _charset(part))
            if text.strip():
                parts.texts.append((content_type, text))
            continue
        parts.attachments.append((filename or _synthesized_name(seen, content_type), payload))
    if dropped_headers:
        parts.warnings.append(
            f"{dropped_headers} header-only part(s) (delivery or header reports) were not "
            "stored: they carry addresses"
        )
    return parts


# --- body construction ------------------------------------------------------------------------


def is_format_patch(subject: str | None, text: str) -> bool:
    """``git format-patch`` output: a ``diff --git`` line plus a patch subject or a ``---``
    separator before the diff."""
    diff = _DIFF_GIT_RE.search(text)
    if diff is None:
        return False
    if subject and _PATCH_SUBJECT_RE.match(subject):
        return True
    return _SEPARATOR_RE.search(text, 0, diff.start()) is not None


def _patch_block(report: Report) -> CodeBlock | None:
    body = report.body
    diff = _DIFF_GIT_RE.search(body)
    if diff is None:
        return None
    start = diff.start()
    signature = _SIGNATURE_RE.search(body, start)
    end = signature.start() if signature is not None else len(body)
    while end > start and body[end - 1] == "\n":
        end -= 1
    if end <= start:
        return None
    content = body[start:end]
    return CodeBlock(
        span=report.span(start, end), lang_hint="diff", content=content, role_guess="patch"
    )


def _base_report(parts: _Parts, subject: str | None, uri: str | None, max_chars: int) -> Report:
    """Intake of the chosen body text through the matching ingester (kind fixed up later)."""
    from nikasha.ingest import detect_format  # noqa: PLC0415 - avoids an import cycle

    plain = [text for content_type, text in parts.texts if content_type == "text/plain"]
    if plain:
        text = "\n\n".join(plain)
        if is_format_patch(subject, text):
            base = ingest_text(text, uri=uri, max_chars=max_chars)
            block = _patch_block(base)
            return base if block is None else base.model_copy(update={"code_blocks": (block,)})
        if detect_format(text) == "markdown":
            return ingest_markdown(text, uri=uri, max_chars=max_chars)
        return ingest_text(text, uri=uri, max_chars=max_chars)
    html = [text for content_type, text in parts.texts if content_type == "text/html"]
    if html:
        return ingest_html("\n".join(html), uri=uri, max_chars=max_chars)
    base = ingest_text("", uri=uri, max_chars=max_chars)
    return base.model_copy(update={"warnings": ("email has no text part",)})


def default_run_dir(data: bytes) -> Path:
    """A private, content-addressed directory for this message's attachments.

    The same message always maps to the same directory; a previous run's copy is replaced.
    """
    digest = hashlib.sha256(data).hexdigest()[:16]
    root = ensure_private_dir(cache_dir() / "attachments")
    run_dir = root / f"eml-{digest}"
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
    return run_dir


def ingest_eml(
    data: bytes,
    *,
    uri: str | None = None,
    run_dir: Path | None = None,
    max_chars: int = MAX_BODY_CHARS,
    limits: AttachmentLimits = AttachmentLimits(),  # noqa: B008  (immutable dataclass)
) -> Report:
    """Build a :class:`Report` from raw RFC 5322 bytes.

    ``run_dir`` receives the attachments (created 0700, files 0600); by default a
    content-addressed directory under the cache is used.
    """
    if len(data) > MAX_EML_BYTES:
        raise NikashaError(f"email is {len(data):,} bytes; the limit is {MAX_EML_BYTES:,} bytes")
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except RecursionError as exc:
        raise NikashaError("email nests its parts too deeply to parse; refused") from exc
    subject = header_text(msg, "Subject")
    reported_at = header_date(msg)
    parts = collect_parts(msg)
    base = _base_report(parts, subject, uri, max_chars)
    warnings = list(base.warnings) + parts.warnings
    stored: tuple[Attachment, ...] = ()
    if parts.attachments:
        target = run_dir if run_dir is not None else default_run_dir(data)
        stored, skipped = store_attachments(parts.attachments, target, limits)
        warnings.extend(skipped)
    return Report(
        id=report_id("eml", base.body),
        source=ReportSource(kind="eml", uri=uri),
        title=subject or base.title,
        body=base.body,
        source_map=base.source_map,
        code_blocks=base.code_blocks,
        attachments=stored,
        reported_at=reported_at,
        warnings=tuple(warnings),
    )


def load_eml(
    source: str | Path,
    *,
    run_dir: Path | None = None,
    max_chars: int = MAX_BODY_CHARS,
    limits: AttachmentLimits = AttachmentLimits(),  # noqa: B008  (immutable dataclass)
) -> Report:
    """Load one ``.eml`` file. The recorded URI is the path exactly as given."""
    path = Path(source)
    try:
        size = path.stat().st_size
        if size > MAX_EML_BYTES:
            raise NikashaError(f"{source} is {size:,} bytes; the limit is {MAX_EML_BYTES:,}")
        data = path.read_bytes()
    except OSError as exc:
        raise NikashaError(f"cannot read {source}: {exc.strerror or exc}") from exc
    return ingest_eml(data, uri=str(source), run_dir=run_dir, max_chars=max_chars, limits=limits)


__all__ = [
    "HEADER_ONLY_TYPES",
    "MAX_DEPTH",
    "MAX_EML_BYTES",
    "MAX_PARTS",
    "collect_parts",
    "default_run_dir",
    "header_date",
    "header_text",
    "ingest_eml",
    "is_format_patch",
    "load_eml",
]
