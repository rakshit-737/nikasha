# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""ADR 0007 decision 4: one git invocation, one machine-independent ``CommandRecord``.

Two properties matter more than the rest, and both are about what happens *after* the
record is written. A record travels inside a result someone may forward, so it must name no
directory on this machine (P3); and it lands inside ``Evidence``, which ``Result.to_json``
must serialize byte-identically for identical inputs (P2), so nothing in it may come from
the clock or from where the clone happens to live.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from nikasha.checks.base import make_evidence
from nikasha.code.gitio import (
    DURATION_NOT_MEASURED,
    EMPTY_SHA256,
    REDACTED_PATH,
    REDACTED_USERINFO,
    GitRepo,
    GitResult,
    build_argv,
    command_record,
    record_command,
    redact_argv,
)
from nikasha.model.claims import FileClaim
from nikasha.model.evidence import CommandRecord
from nikasha.model.report import Span

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: sha256 of a handful of known byte strings, so the test does not merely re-run the
#: implementation's own call to hashlib.
HELLO_SHA256 = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
WARNING_SHA256 = "3a93b871cf29bc33ca8ba2591de757e6e249a332c2c3825cf117b11a62819454"
EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def result(
    argv: tuple[str, ...],
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    duration_ms: int = 0,
) -> GitResult:
    return GitResult(
        argv=argv, returncode=returncode, stdout=stdout, stderr=stderr, duration_ms=duration_ms
    )


def looks_absolute(arg: str) -> bool:
    """A POSIX, UNC or drive-letter path, judged the same way on every platform."""
    return arg.startswith(("/", "\\\\")) or arg[1:3] in (":/", ":\\")


def json_spellings(local: Path) -> tuple[str, ...]:
    """Every form in which ``local`` could appear inside serialized JSON.

    ``model_dump_json`` escapes backslashes, so on Windows ``str(path)`` never matches its
    own JSON form and an assertion on it alone would be vacuous; the JSON-encoded spelling
    and the forward-slash spelling are checked too.
    """
    return (str(local), json.dumps(str(local))[1:-1], local.as_posix())


# --- redaction -------------------------------------------------------------------------------


@needs_git
def test_the_clone_cache_path_never_survives_redaction(tmp_path: Path) -> None:
    """The three places ``build_argv`` writes the local clone path are all removed."""
    clone = tmp_path / "cache" / "nikasha" / "repos" / "github.com" / "libhdr.git"
    clone.mkdir(parents=True)
    argv = build_argv(["grep", "-I", "-F", "-e", "hdr_decode", "HEAD"], git_dir=clone)

    # Every one of them is in the argv that actually ran...
    assert any(arg.startswith("--git-dir=") for arg in argv)
    assert any(arg.startswith("safe.directory=") for arg in argv)
    assert str(clone.resolve()) in " ".join(argv)

    redacted = command_record(result(tuple(argv))).argv

    # ...and none of them is in the record.
    joined = " ".join(redacted)
    assert "--git-dir" not in joined
    assert "safe.directory" not in joined
    assert clone.name not in joined
    assert str(clone.resolve()) not in joined
    assert "-c" not in redacted


@needs_git
def test_redaction_keeps_the_command_re_runnable(tmp_path: Path) -> None:
    """P6: what is left is exactly what a reader types inside their own clone."""
    clone = tmp_path / "libhdr.git"
    clone.mkdir()
    argv = build_argv(["grep", "-I", "-F", "-e", "hdr_decode", "HEAD"], git_dir=clone)
    # ``--no-textconv`` is the guard gitio inserts for grep; it changes the output, so it
    # stays. The executable's own path does not, so it becomes plain "git".
    assert command_record(result(tuple(argv))).argv == (
        "git",
        "grep",
        "--no-textconv",
        "-I",
        "-F",
        "-e",
        "hdr_decode",
        "HEAD",
    )


@pytest.mark.parametrize(
    "local",
    [
        "/home/rakshit/.cache/nikasha/repos/libhdr.git",
        "/var/tmp/nikasha/libhdr.git",
        "D:/Academics/nikasha/.cache/libhdr.git",
        "C:\\Users\\Rakshit\\.cache\\nikasha\\libhdr.git",
        "\\\\server\\share\\libhdr.git",
    ],
)
def test_no_absolute_path_survives_in_any_position(local: str) -> None:
    redacted = command_record(
        result(("/usr/lib/git-core/git", "log", "-1", "--format=%H", local))
    ).argv
    assert redacted == ("git", "log", "-1", "--format=%H", REDACTED_PATH)
    assert local not in " ".join(redacted)


def test_dash_c_and_the_other_location_options_are_dropped_with_their_value() -> None:
    argv = (
        "/usr/bin/git",
        "--no-pager",
        "-C",
        "/home/rakshit/clones/libhdr",
        "--work-tree=/home/rakshit/wt",
        "--git-dir",
        "/home/rakshit/clones/libhdr/.git",
        "rev-parse",
        "--verify",
        "HEAD",
    )
    assert command_record(result(argv)).argv == ("git", "rev-parse", "--verify", "HEAD")


def test_report_derived_arguments_are_left_alone() -> None:
    """A pickaxe term and a pathspec are the report's content, not this machine's layout."""
    argv = (
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "core.bare=true",
        "--git-dir=/tmp/clone.git",
        "log",
        "--no-ext-diff",
        "--no-textconv",
        "--all",
        "-1",
        "-Smemcpy(dst, /etc/passwd, n)",
        "--",
        ":(literal)src/hdr.c",
    )
    assert command_record(result(argv)).argv == (
        "git",
        "log",
        "--no-ext-diff",
        "--no-textconv",
        "--all",
        "-1",
        "-Smemcpy(dst, /etc/passwd, n)",
        "--",
        ":(literal)src/hdr.c",
    )


def test_an_empty_argv_redacts_to_nothing() -> None:
    assert command_record(result(())).argv == ()


def test_redaction_is_idempotent() -> None:
    """A redacted argv is a fixed point, so re-recording stored evidence changes nothing."""
    argv = (
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "safe.directory=/home/rakshit/.cache/nikasha/repos/libhdr.git",
        "--git-dir=/home/rakshit/.cache/nikasha/repos/libhdr.git",
        "grep",
        "--no-textconv",
        "-e",
        "hdr_decode",
        "v1.2.0",
        "--",
        "/home/rakshit/pathspec",
    )
    once = redact_argv(argv)
    assert once == (
        "git",
        "grep",
        "--no-textconv",
        "-e",
        "hdr_decode",
        "v1.2.0",
        "--",
        REDACTED_PATH,
    )
    assert redact_argv(once) == once


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://rakshit:ghp_secret_token@github.com/libhdr/libhdr.git",
            f"https://{REDACTED_USERINFO}@github.com/libhdr/libhdr.git",
        ),
        (
            "https://x-access-token:ghs_secret_token@github.com/libhdr/libhdr.git",
            f"https://{REDACTED_USERINFO}@github.com/libhdr/libhdr.git",
        ),
        # An ``@`` inside the password: everything up to the *last* one is the userinfo.
        (
            "https://rakshit:p@ss_secret_token@host.example/libhdr.git",
            f"https://{REDACTED_USERINFO}@host.example/libhdr.git",
        ),
        # Even a harmless login is not the reader's business; ``git@`` goes too.
        (
            "ssh://git@github.com/libhdr/libhdr.git",
            f"ssh://{REDACTED_USERINFO}@github.com/libhdr/libhdr.git",
        ),
    ],
)
def test_url_credentials_never_survive_redaction(url: str, expected: str) -> None:
    """A clone or fetch is never recorded today; the helper does not rely on that."""
    argv = (
        "/usr/bin/git",
        "--no-pager",
        "clone",
        "--bare",
        "--quiet",
        url,
        "/home/rakshit/.cache/nikasha/repos/github.com/libhdr/libhdr.git",
    )
    redacted = redact_argv(argv)
    assert redacted == ("git", "clone", "--bare", "--quiet", expected, REDACTED_PATH)
    assert "secret" not in " ".join(redacted)
    assert redact_argv(redacted) == redacted


def test_a_url_without_credentials_is_left_alone() -> None:
    argv = ("git", "clone", "--bare", "https://github.com/libhdr/libhdr.git")
    assert redact_argv(argv) == argv


def test_credentials_inside_a_search_term_are_scrubbed_too() -> None:
    """Report text may quote ``http://admin:admin@device/``; the record still carries none."""
    term = "-Shttp://admin:admin@192.168.1.1/cgi-bin/luci and https://a:b@x.example/?q=1#f"
    redacted = redact_argv(("git", "log", "--no-ext-diff", "--all", "-1", term))
    assert redacted == (
        "git",
        "log",
        "--no-ext-diff",
        "--all",
        "-1",
        f"-Shttp://{REDACTED_USERINFO}@192.168.1.1/cgi-bin/luci"
        f" and https://{REDACTED_USERINFO}@x.example/?q=1#f",
    )
    assert "admin" not in " ".join(redacted)


@needs_git
def test_a_record_inside_evidence_serializes_with_no_local_path(tmp_path: Path) -> None:
    """P3 at the level that matters: the JSON someone forwards names no directory here."""
    clone = tmp_path / "cache" / "nikasha" / "repos" / "libhdr.git"
    clone.mkdir(parents=True)
    argv = build_argv(["log", "--all", "-1", "--format=%H", "-Shdr_decode"], git_dir=clone)
    evidence = make_evidence(
        check_id="C06",
        group="code_quotes",
        claims=[_claim()],
        outcome="NEUTRAL",
        strength=0.0,
        summary="the quoted line is not at v1.2.0",
        commands=[command_record(result(tuple(argv), returncode=0))],
    )
    text = evidence.model_dump_json()
    for local in (clone.resolve(), tmp_path):
        for spelling in json_spellings(local):
            assert spelling not in text
    assert clone.name not in text  # the one path segment every platform spells alike
    for arg in evidence.commands[0].argv:
        assert not arg.startswith(("/", "\\\\")), arg
        assert arg[1:3] not in (":/", ":\\"), arg
    for leak in ("--git-dir", "safe.directory", "--no-pager"):
        assert leak not in text
    assert "-Shdr_decode" in text
    # And the parsed record, independent of how JSON happens to escape a path.
    recorded = evidence.commands[0].argv
    assert "-c" not in recorded
    assert not any(looks_absolute(arg) for arg in recorded), recorded


# --- hashes ----------------------------------------------------------------------------------


def test_hashes_are_sha256_hex_of_the_exact_bytes() -> None:
    record = command_record(
        result(("git", "grep", "x"), returncode=1, stdout=b"hello\n", stderr=b"warning: nothing\n")
    )
    assert record.stdout_sha256 == HELLO_SHA256
    assert record.stderr_sha256 == WARNING_SHA256
    assert record.exit_code == 1


def test_no_output_hashes_to_the_empty_digest() -> None:
    """The commonest case by far: a search that found nothing and said nothing."""
    record = command_record(result(("git", "grep", "nothing"), returncode=1))
    assert record.stdout_sha256 == EMPTY_DIGEST
    assert record.stderr_sha256 == EMPTY_DIGEST
    assert EMPTY_SHA256 == EMPTY_DIGEST


def test_a_hash_is_over_bytes_not_decoded_text() -> None:
    """Repository content is not always UTF-8, and the record must not depend on a decode."""
    payload = b"\xff\xfe\x00invalid utf-8\n"
    record = command_record(result(("git", "show", "HEAD"), stdout=payload))
    assert record.stdout_sha256 == hashlib.sha256(payload).hexdigest()


def test_stdout_and_stderr_are_hashed_separately() -> None:
    """A change on one stream moves only that stream's hash."""
    quiet = command_record(result(("git", "log"), stdout=b"hello\n", stderr=b"a\n"))
    noisy = command_record(result(("git", "log"), stdout=b"hello\n", stderr=b"b\n"))
    assert quiet.stdout_sha256 == noisy.stdout_sha256 == HELLO_SHA256
    assert quiet.stderr_sha256 != noisy.stderr_sha256
    assert len(quiet.stderr_sha256) == len(noisy.stderr_sha256) == 64


# --- determinism -----------------------------------------------------------------------------


def test_the_duration_is_not_recorded_by_default() -> None:
    """P2: wall-clock time differs between two runs, and a record is serialized as evidence."""
    fast = command_record(result(("git", "log"), duration_ms=3))
    slow = command_record(result(("git", "log"), duration_ms=9001))
    # No measured figure survives: the sentinel is what the model admits for "not measured".
    assert fast.duration_ms is None
    assert fast.duration_ms is DURATION_NOT_MEASURED
    assert '"duration_ms":null' in fast.model_dump_json()
    assert fast == slow


def test_the_duration_can_be_asked_for_explicitly() -> None:
    record = command_record(result(("git", "log"), duration_ms=42), include_duration=True)
    assert record.duration_ms == 42


@needs_git
def test_two_runs_of_the_same_command_produce_the_same_record(vulnlab_repo: Path) -> None:
    """The whole point: same report, same repository, same bytes — on any machine."""
    with GitRepo(vulnlab_repo) as repo:
        first: list[CommandRecord] = []
        second: list[CommandRecord] = []
        repo.run(["rev-parse", "--verify", "--quiet", "--end-of-options", "v1.2.0"], record=first)
        repo.run(["rev-parse", "--verify", "--quiet", "--end-of-options", "v1.2.0"], record=second)
    assert first == second
    assert first[0].duration_ms is None
    assert first[0].argv[:2] == ("git", "rev-parse")


@needs_git
def test_two_clones_of_one_repository_record_the_same_command(
    vulnlab_repo: Path, tmp_path: Path
) -> None:
    """Standing in for two machines: the same history under a different path on disk."""
    elsewhere = tmp_path / "another" / "place" / "libhdr.git"
    elsewhere.parent.mkdir(parents=True)
    shutil.copytree(vulnlab_repo, elsewhere)
    records: list[list[CommandRecord]] = []
    for git_dir in (vulnlab_repo, elsewhere):
        sink: list[CommandRecord] = []
        with GitRepo(git_dir) as repo:
            repo.grep("hdr_decode", ["v1.2.0"], files_only=True, record=sink)
        records.append(sink)
    assert records[0] == records[1]
    assert records[0], "the grep should have been recorded"


# --- the sink --------------------------------------------------------------------------------


def test_record_command_does_nothing_without_a_sink() -> None:
    record_command(None, result(("git", "log")))  # must not raise


def test_record_command_appends_one_entry_per_call() -> None:
    sink: list[CommandRecord] = []
    record_command(sink, result(("git", "log"), stdout=b"hello\n"))
    record_command(sink, result(("git", "grep", "x"), returncode=1), truncated=True)
    assert [r.exit_code for r in sink] == [0, 1]
    assert [r.truncated for r in sink] == [False, True]


@needs_git
def test_grep_marks_the_record_truncated_when_the_hit_cap_stops_it(vulnlab_repo: Path) -> None:
    sink: list[CommandRecord] = []
    with GitRepo(vulnlab_repo) as repo:
        hits = repo.grep("hdr", ["v1.2.0"], max_hits=1, record=sink)
    assert len(hits) == 1
    assert sink and sink[-1].truncated is True


# --- the identity payload (ADR 0007 decision 4: durations must not reach an evidence id) ------


def _claim() -> FileClaim:
    return FileClaim(
        id="claim-1",
        spans=(Span(start=0, end=9, text="src/hdr.c"),),
        extractor="test",
        confidence=1.0,
        provenance="project_attributed",
        path="src/hdr.c",
    )


def test_commands_never_change_an_evidence_id() -> None:
    """``make_evidence`` hashes claims, outcome, strength, summary, details and locations.

    ``commands`` is deliberately outside that payload, so adopting command records cannot
    move an existing evidence ID, and a duration could not reach one even if one were
    recorded. This test fails the moment that stops being true.
    """
    claim = _claim()
    bare = make_evidence(
        check_id="C13",
        group="info",
        claims=[claim],
        outcome="NEUTRAL",
        strength=0.0,
        summary="src/hdr.c was modified after the claimed version",
        details={"outcome": "modified_after"},
    )
    with_command = make_evidence(
        check_id="C13",
        group="info",
        claims=[claim],
        outcome="NEUTRAL",
        strength=0.0,
        summary="src/hdr.c was modified after the claimed version",
        details={"outcome": "modified_after"},
        commands=[
            command_record(
                result(("git", "log", "-1"), stdout=b"hello\n", duration_ms=17),
                include_duration=True,
            )
        ],
    )
    assert bare.id == with_command.id
    assert with_command.commands[0].duration_ms == 17
