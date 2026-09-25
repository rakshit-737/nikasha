# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Email intake (SPEC §8, §16.5): stdlib parsing, no sender identity, capped attachments,
and hostile messages that never crash."""

from __future__ import annotations

import hashlib
import itertools
from datetime import date
from email.message import EmailMessage
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nikasha.errors import NikashaError
from nikasha.extract import extract_claims
from nikasha.ingest import email as eml
from nikasha.ingest.attachments import AttachmentLimits
from nikasha.ingest.email import ingest_eml, is_format_patch, load_eml
from nikasha.model.claims import PatchClaim
from nikasha.model.report import Report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "email"

#: Header values from the fixtures that must never reach a result (SPEC §7).
IDENTITIES = {
    "simple.eml": [
        "Alice Reporter",
        "alice.reporter@example.org",
        "security@libhdr.example",
        "Bob Triager",
        "bob.triager@example.net",
        "20260115102030.1234@mail.example.org",
        "Example Mailer",
    ],
    "multipart.eml": [
        "Carol Reporter",
        "carol.reporter@example.org",
        "dave.triager@example.net",
        "multipart-0001@mail.example.org",
    ],
    "html_only.eml": ["Erin Reporter", "erin.reporter@example.org", "html-0001@mail"],
    "hostile.eml": [
        "Mallory Reporter",
        "mallory.reporter@example.org",
        "grace.triager@example.net",
        "hostile-0001@mail.example.org",
        "Forwarded Person",
        "forwarded.person@example.org",
    ],
}


def _load(name: str, tmp_path: Path, **kwargs: object) -> Report:
    return load_eml(FIXTURES / name, run_dir=tmp_path / "attachments", **kwargs)  # type: ignore[arg-type]


class TestFixtures:
    def test_plain_text_message(self, tmp_path: Path) -> None:
        report = _load("simple.eml", tmp_path)
        assert report.source.kind == "eml"
        assert report.source.uri is not None and report.source.uri.endswith("simple.eml")
        assert report.title == "Heap overflow in hdr_decode_chunked_value() (libhdr 1.2.0)"
        assert report.reported_at == date(2026, 1, 15)
        assert "`hdr_decode_chunked_value()`" in report.body
        assert "src/hdr.c line 412" in report.body
        # The fenced block is found because the plain part is sniffed as Markdown.
        (block,) = report.code_blocks
        assert "AddressSanitizer" in block.span.text
        assert report.attachments == ()
        assert report.warnings == ()

    @pytest.mark.parametrize("name", sorted(IDENTITIES))
    def test_sender_identity_is_never_stored(self, name: str, tmp_path: Path) -> None:
        report = _load(name, tmp_path)
        dumped = report.model_dump_json()
        for needle in IDENTITIES[name]:
            assert needle not in dumped, needle
            assert needle not in report.body
        assert "stored_path" not in dumped

    def test_multipart_prefers_plain_text_and_stores_attachments(self, tmp_path: Path) -> None:
        report = _load("multipart.eml", tmp_path)
        assert report.title == "PoC: crash in hdr_parse — libhdr 1.2.0"
        assert report.reported_at == date(2026, 1, 16)
        assert "crashes in hdr_parse():" in report.body
        assert "Café is fine here." in report.body
        assert "<html" not in report.body
        assert "alert(1)" not in report.body
        # The text attachment (asan.log) is a file, not part of the body.
        assert "==4121==ERROR" not in report.body
        names = [a.name_sanitized for a in report.attachments]
        assert names == ["poc.c", "crash.zip", "asan.log"]
        poc = report.attachments[0]
        assert poc.sha256 == hashlib.sha256(b"int main(void) { return 0; }\n").hexdigest()
        assert poc.size == 29
        assert poc.stored_path is not None
        stored = Path(poc.stored_path)
        assert stored.parent == tmp_path / "attachments"
        assert stored.read_bytes() == b"int main(void) { return 0; }\n"
        assert (tmp_path / "attachments" / "crash.zip").is_file()
        assert report.warnings == ()

    def test_html_only_falls_back_to_the_html_intake(self, tmp_path: Path) -> None:
        report = _load("html_only.eml", tmp_path)
        assert report.title == "Stack overflow in hdr_parse (libhdr 1.1.0)"  # Subject wins
        assert "Ignored by the Subject" not in report.body
        assert report.reported_at == date(2026, 1, 17)
        assert "`hdr_parse()`" in report.body
        assert "résumé" in report.body  # quoted-printable + iso-8859-1 decoded
        assert "alert(1)" not in report.body
        assert "color:red" not in report.body
        (block,) = report.code_blocks
        assert block.lang_hint == "c"
        assert block.span.text == "char buf[32];\nstrcpy(buf, in);"

    def test_format_patch_mail_becomes_a_patch_block(self, tmp_path: Path) -> None:
        report = _load("format_patch.eml", tmp_path)
        assert report.title is not None and report.title.startswith("[PATCH 1/1] hdr: bound")
        assert report.reported_at == date(2026, 1, 17)
        (block,) = report.code_blocks
        assert block.role_guess == "patch"
        assert block.lang_hint == "diff"
        assert block.span.text.startswith("diff --git a/src/hdr.c b/src/hdr.c\n")
        assert block.span.text.endswith(" }")
        assert "2.43.0" not in block.span.text  # the signature is not part of the diff
        patches = [c for c in extract_claims(report).claims if isinstance(c, PatchClaim)]
        assert len(patches) == 1
        assert patches[0].files == ("src/hdr.c",)
        assert patches[0].hunks[0].source_start == 410

    def test_hostile_message_is_tamed(self, tmp_path: Path) -> None:
        report = _load("hostile.eml", tmp_path)
        # An encoded-word CR/LF cannot add a header line to the title.
        assert report.title == "Bug report Bcc: injected@example.org"
        assert "\n" not in (report.title or "")
        assert report.reported_at is None  # "not a date at all"
        # The forwarded (nested) message's text is the body; its HTML twin is not used.
        assert "Inner report text: hdr_parse overflows in libhdr 1.2.0." in report.body
        assert "alert(1)" not in report.body
        names = sorted(a.name_sanitized for a in report.attachments)
        assert names == ["evil.exe", "part-4.bin"]
        raw = next(a for a in report.attachments if a.name_sanitized == "part-4.bin")
        assert raw.stored_path is not None
        assert Path(raw.stored_path).read_bytes().startswith(b"\xff\xfe\x00raw bytes")
        assert all(
            Path(a.stored_path or "").parent == tmp_path / "attachments" for a in report.attachments
        )


class TestLimits:
    def test_attachment_caps_apply(self, tmp_path: Path) -> None:
        msg = EmailMessage()
        msg["Subject"] = "big"
        msg.set_content("body\n")
        msg.add_attachment(b"A" * 5000, maintype="application", subtype="octet-stream",
                           filename="big.bin")  # fmt: skip
        msg.add_attachment(b"B" * 10, maintype="application", subtype="octet-stream",
                           filename="small.bin")  # fmt: skip
        report = ingest_eml(
            msg.as_bytes(), run_dir=tmp_path, limits=AttachmentLimits(per_file_bytes=1000)
        )
        assert [a.name_sanitized for a in report.attachments] == ["small.bin"]
        assert any("big.bin" in w and "per-file cap" in w for w in report.warnings)
        assert not (tmp_path / "big.bin").exists()

    def test_part_bomb_is_capped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(eml, "MAX_PARTS", 5)
        msg = EmailMessage()
        msg["Subject"] = "many"
        msg.make_mixed()
        for i in range(8):
            part = EmailMessage()
            part.set_content(f"part {i}\n")
            msg.attach(part)
        report = ingest_eml(msg.as_bytes(), run_dir=tmp_path)
        assert any("more than 5 parts" in w for w in report.warnings)
        assert "part 4" in report.body
        assert "part 5" not in report.body

    def test_header_only_parts_are_never_stored(self, tmp_path: Path) -> None:
        # Bounces and forwarded header blocks carry addresses and Received lines (SPEC §7).
        data = (
            b"From: a@example.org\nSubject: s\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/report; report-type=delivery-status; boundary="b"\n\n'
            b"--b\nContent-Type: text/plain\n\nbody text\n"
            b"--b\nContent-Type: message/delivery-status\n\n"
            b"Reporting-MTA: dns; mx.example.org\n\nFinal-Recipient: rfc822; victim@example.org\n\n"
            b"--b\nContent-Type: text/rfc822-headers\n\n"
            b"From: Secret Person <secret@example.org>\nReceived: from relay.example.org\n\n"
            b"--b--\n"
        )
        report = ingest_eml(data, run_dir=tmp_path)
        assert report.attachments == ()
        assert list(tmp_path.iterdir()) == []
        dumped = report.model_dump_json()
        for needle in ("victim@", "secret@", "Secret Person", "relay.example.org", "mx.example"):
            assert needle not in dumped
        assert any("header-only" in w for w in report.warnings)

    @staticmethod
    def _nested(levels: int) -> bytes:
        data = b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="b0"\n\n'
        for i in range(levels):
            data += b'--b%d\nContent-Type: multipart/mixed; boundary="b%d"\n\n' % (i, i + 1)
        return data + b"--b%d\nContent-Type: text/plain\n\ndeep text\n" % levels

    def test_deep_nesting_is_capped(self, tmp_path: Path) -> None:
        report = ingest_eml(self._nested(eml.MAX_DEPTH + 20), run_dir=tmp_path)
        assert "deep text" not in report.body
        assert any("deeper than" in w for w in report.warnings)
        shallow = ingest_eml(self._nested(5), run_dir=tmp_path / "s")
        assert "deep text" in shallow.body

    def test_nesting_that_breaks_the_parser_is_refused_cleanly(self, tmp_path: Path) -> None:
        with pytest.raises(NikashaError, match="too deeply"):
            ingest_eml(self._nested(5000), run_dir=tmp_path)

    def test_size_cap(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(eml, "MAX_EML_BYTES", 10)
        with pytest.raises(NikashaError, match="limit"):
            ingest_eml(b"x" * 11, run_dir=tmp_path)
        big = tmp_path / "big.eml"
        big.write_bytes(b"Subject: x\n\n" + b"y" * 20)
        with pytest.raises(NikashaError, match="limit"):
            load_eml(big, run_dir=tmp_path / "run")

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(NikashaError, match="cannot read"):
            load_eml(tmp_path / "nope.eml", run_dir=tmp_path / "run")

    def test_body_truncation_is_reported(self, tmp_path: Path) -> None:
        data = b"Subject: long\n\n" + b"z" * 500
        report = ingest_eml(data, run_dir=tmp_path, max_chars=100)
        assert len(report.body) == 100
        assert any("truncated" in w for w in report.warnings)


class TestShapes:
    def test_no_text_part_warns(self, tmp_path: Path) -> None:
        msg = EmailMessage()
        msg["Subject"] = "only a file"
        msg.make_mixed()
        msg.add_attachment(b"data", maintype="application", subtype="octet-stream",
                           filename="poc.bin")  # fmt: skip
        report = ingest_eml(msg.as_bytes(), run_dir=tmp_path)
        assert report.body == ""
        assert report.title == "only a file"
        assert "email has no text part" in report.warnings
        assert [a.name_sanitized for a in report.attachments] == ["poc.bin"]

    def test_empty_and_garbage_input_do_not_crash(self, tmp_path: Path) -> None:
        assert ingest_eml(b"", run_dir=tmp_path / "a").body == ""
        report = ingest_eml(b"\x00\xff\xfe garbage \x1b[31m", run_dir=tmp_path / "b")
        assert report.source.kind == "eml"
        assert "garbage" in report.body  # no headers: the whole input is the body
        assert "\0" not in report.body and "\x1b" not in report.body

    def test_crlf_and_lf_give_the_same_report(self, tmp_path: Path) -> None:
        data = (FIXTURES / "simple.eml").read_bytes()
        assert b"\r\n" not in data
        lf = ingest_eml(data, run_dir=tmp_path / "lf")
        crlf = ingest_eml(data.replace(b"\n", b"\r\n"), run_dir=tmp_path / "crlf")
        assert crlf.body == lf.body
        assert crlf.id == lf.id
        assert "\r" not in crlf.body

    def test_same_bytes_same_json(self, tmp_path: Path) -> None:
        data = (FIXTURES / "multipart.eml").read_bytes()
        first = ingest_eml(data, run_dir=tmp_path / "1").model_dump_json()
        second = ingest_eml(data, run_dir=tmp_path / "2").model_dump_json()
        assert first == second

    def test_folded_subject_is_one_line(self, tmp_path: Path) -> None:
        data = b"Subject: first line\n  second line\n\nbody\n"
        assert ingest_eml(data, run_dir=tmp_path).title == "first line second line"

    def test_unparsable_date_is_none(self, tmp_path: Path) -> None:
        assert ingest_eml(b"Date: 2026-01-15\n\nx\n", run_dir=tmp_path).reported_at is None
        good = ingest_eml(b"Date: Mon, 2 Feb 2026 01:02:03 -0000\n\nx\n", run_dir=tmp_path)
        assert good.reported_at == date(2026, 2, 2)

    def test_text_attachment_with_filename_is_not_body(self, tmp_path: Path) -> None:
        data = (
            b"Subject: s\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="b"\n\n'
            b"--b\nContent-Type: text/plain\n\nthe body\n"
            b'--b\nContent-Type: text/plain; name="notes.txt"\n\nnot the body\n--b--\n'
        )
        report = ingest_eml(data, run_dir=tmp_path)
        assert report.body == "the body"
        assert [a.name_sanitized for a in report.attachments] == ["notes.txt"]

    def test_default_run_dir_is_private_and_content_addressed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
        data = (FIXTURES / "multipart.eml").read_bytes()
        first = ingest_eml(data)
        second = ingest_eml(data)  # the previous copy is replaced, not duplicated
        assert first.attachments[0].stored_path == second.attachments[0].stored_path
        assert Path(first.attachments[0].stored_path or "").is_relative_to(tmp_path / "cache")
        assert eml.default_run_dir(data).name == eml.default_run_dir(data).name


@pytest.mark.parametrize(
    ("subject", "text", "expected"),
    [
        ("[PATCH] fix", "diff --git a/x b/x\n", True),
        ("[PATCH v2 3/7] fix", "diff --git a/x b/x\n", True),
        ("[RFC PATCH] fix", "diff --git a/x b/x\n", True),
        ("[libhdr PATCH] fix", "diff --git a/x b/x\n", True),
        (None, "msg\n---\n stat\n\ndiff --git a/x b/x\n", True),
        ("Re: crash", "diff --git a/x b/x\n", False),
        ("[PATCH] fix", "no diff here\n", False),
        ("patch", "--- a/x\n+++ b/x\n", False),
    ],
)
def test_is_format_patch(subject: str | None, text: str, expected: bool) -> None:
    assert is_format_patch(subject, text) is expected


_runs = itertools.count()


@given(data=st.binary(max_size=1500))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_never_crashes_on_random_bytes(data: bytes, tmp_path: Path) -> None:
    prefix = b'Subject: s\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="b"\n\n--b\n'
    for raw in (data, prefix + data):
        report = ingest_eml(raw, run_dir=tmp_path / f"run-{next(_runs)}")
        assert report.source.kind == "eml"
        assert "\r" not in report.body
