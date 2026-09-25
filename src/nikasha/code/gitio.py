# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The single hardened entry point for running git (SPEC §19.3).

Every git invocation in Nikasha MUST go through :func:`run_git`, which a test enforces by
scanning the source tree. Repositories are attacker-controlled input, so the wrapper:

* allows only a fixed set of read-mostly plumbing subcommands;
* overrides risky repository config on the command line (``-c`` beats repo config);
* disables external diff drivers and textconv on commands that could invoke them;
* scrubs inherited ``GIT_*`` variables and ignores system and global config by default.

Because this is the only module that composes a git argv, it is also the only one that can
strip the local clone path back out of it: :func:`command_record` turns a :class:`GitResult`
into the :class:`~nikasha.model.evidence.CommandRecord` that evidence carries (ADR 0007
decision 4), and the ``record`` argument on :class:`GitRepo`'s search methods collects one
per invocation.

Verified against git 2.55 docs and source on 2026-09-23 (see
``docs/research/2026-09-23-m0-verification.md``). ``-c diff.external=`` is deliberately
*not* used: an empty value does not disable external diff, ``--no-ext-diff`` does.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from collections.abc import Mapping, MutableSequence, Sequence
from dataclasses import dataclass
from pathlib import Path

from nikasha.errors import ExternalToolError, ForbiddenCommandError
from nikasha.model.evidence import CommandRecord

#: Subcommands production code may run.
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "cat-file",
        "clone",
        "fetch",
        "for-each-ref",
        "grep",
        "log",
        "ls-tree",
        "rev-list",
        "rev-parse",
        "show",
        "tag",
    }
)

#: Subcommands only the test-suite may run (``allow_test_only=True``).
TEST_ONLY_SUBCOMMANDS: frozenset[str] = frozenset({"apply", "worktree"})

#: Config overrides applied to every invocation. Command-line ``-c`` takes precedence
#: over repository, global and system config.
HARDENING_CONFIG: tuple[str, ...] = (
    "core.bare=true",  # no worktree: ignores core.worktree and worktree .gitattributes
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.pager=cat",
    "core.sshCommand=false",
    "credential.helper=",
    "protocol.file.allow=never",
    "protocol.ext.allow=never",  # ext:: remotes run arbitrary commands
    "protocol.git.allow=never",  # unauthenticated git:// (and core.gitProxy commands)
    "submodule.recurse=false",
)

#: Extra flags inserted right after the subcommand, for subcommands that can run
#: external diff drivers or textconv filters configured by the repository.
_SUBCOMMAND_GUARDS: Mapping[str, tuple[str, ...]] = {
    "log": ("--no-ext-diff", "--no-textconv"),
    "show": ("--no-ext-diff", "--no-textconv"),
    "grep": ("--no-textconv",),
}

#: Options that make git execute a program or rewrite config; never allowed in an argv.
_DANGEROUS_OPTIONS: tuple[str, ...] = (
    "--upload-pack",
    "--receive-pack",
    "--exec",
    "--remote",
    "--config",
    "--template",
    "--open-files-in-pager",
    "--ext-diff",
    "--textconv",
    "--filters",
)

DEFAULT_TIMEOUT_S = 30.0
MAX_REV_LEN = 256
_PRINTABLE = 0x20


@dataclass(frozen=True, slots=True)
class GitResult:
    """Outcome of one git invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


#: Where a caller collects one :class:`CommandRecord` per git invocation it made. A plain
#: ``list`` is the usual sink; a check builds one per evidence item.
CommandSink = MutableSequence[CommandRecord]

#: What replaces an argument that named an absolute location on this machine.
REDACTED_PATH = "<path>"

#: What replaces the ``user:token`` part of any URL an argument carries.
REDACTED_USERINFO = "<credentials>"
_URL_SCHEME_SEP = "://"
_AUTHORITY_END = "/?#"

#: What ``CommandRecord.duration_ms`` carries when the clock was not consulted: no figure
#: at all, so a renderer shows no duration rather than an unmeasured ``0 ms`` (P6).
DURATION_NOT_MEASURED: None = None

#: Global options that point git at one particular clone. Dropped **with their value**.
_LOCAL_PATH_OPTIONS: frozenset[str] = frozenset({"-C", "--git-dir", "--work-tree", "--exec-path"})
_LOCAL_PATH_PREFIXES: tuple[str, ...] = ("--git-dir=", "--work-tree=", "--exec-path=")

#: sha256 of no bytes: the stdout hash of every command that printed nothing.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_DRIVE_LETTER_LEN = 3


def git_executable() -> str | None:
    """Return the path of the git executable on ``PATH``, or ``None``."""
    return shutil.which("git")


def _is_absolute_path(arg: str) -> bool:
    """Whether a whole argument is an absolute path (POSIX, UNC or ``C:\\``)."""
    if arg.startswith(("/", "\\\\")):
        return True
    drive = arg[:_DRIVE_LETTER_LEN]
    return len(drive) == _DRIVE_LETTER_LEN and drive[0].isalpha() and drive[1:] in (":/", ":\\")


def _redact_userinfo(arg: str) -> str:
    """Replace the userinfo of every URL inside ``arg``: ``https://user:token@host/…``
    becomes ``https://<credentials>@host/…``.

    A remote URL reaches an argv through ``clone`` and ``fetch``, whose results no check
    records today; this keeps a credential out of every future recorder without relying on
    that. The scan is a plain left-to-right walk (no regex), linear in ``len(arg)``, and
    its output is a fixed point of itself.
    """
    if _URL_SCHEME_SEP not in arg:
        return arg
    out: list[str] = []
    rest = arg
    while True:
        head, sep, tail = rest.partition(_URL_SCHEME_SEP)
        out.append(head)
        if not sep:
            return "".join(out)
        out.append(sep)
        end = len(tail)
        for offset, ch in enumerate(tail):
            if ch in _AUTHORITY_END or ch.isspace():
                end = offset
                break
        authority, rest = tail[:end], tail[end:]
        if "@" in authority:
            authority = f"{REDACTED_USERINFO}@{authority.rsplit('@', 1)[-1]}"
        out.append(authority)


def redact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Rewrite a git argv into the machine-independent form that goes into evidence.

    :func:`build_argv` composes ``<abs path to git> --no-pager -c <hardening> ...
    -c safe.directory=<clone> --git-dir=<clone> <subcommand> <guards> <args>``. Three parts
    of that are properties of *this* machine, not of the report, so they are removed:

    * **argv[0]**, the absolute path of the git executable, becomes plain ``git``;
    * **every ``-c <setting>`` pair**, including ``safe.directory=<clone cache>``. The
      hardening settings say how Nikasha protected itself from a hostile repository; they
      do not change what git reports, and one of them names the local clone (P3);
    * **``--git-dir=``, ``--work-tree=``, ``--exec-path=`` and ``-C <dir>``**, which all
      name the clone cache directory, and ``--no-pager``, which only affects a terminal.

    Any remaining argument that is *entirely* an absolute path becomes
    :data:`REDACTED_PATH`, and the ``user:token@`` part of any URL inside an argument
    becomes :data:`REDACTED_USERINFO` (``https://<credentials>@host/…``). Both are
    deliberately conservative: they can blunt a search term that happens to be nothing but
    a path, or one that quotes a URL with a login in it, but they guarantee that a record
    forwarded with a report carries neither this machine's filesystem layout nor a
    credential, and that two machines checking the same report produce the same bytes
    (P2, P3, P7).

    What survives is the subcommand, its guards (``--no-ext-diff``, ``--no-textconv``) and
    its arguments — revisions, ``--format``, the ``-e`` pattern, pathspecs — which is what a
    reader needs to re-run the command inside their own clone of the repository (P6).
    """
    if not argv:
        return ()
    out: list[str] = ["git"]
    rest = list(argv[1:])
    index = 0
    while index < len(rest):  # the global option area, up to the subcommand
        arg = rest[index]
        if arg == "-c" or arg in _LOCAL_PATH_OPTIONS:
            index += 2  # the option and the value it consumes
            continue
        if arg == "--no-pager" or arg.startswith(_LOCAL_PATH_PREFIXES):
            index += 1
            continue
        if not arg.startswith("-"):
            break
        out.append(arg)
        index += 1
    out += [
        REDACTED_PATH if _is_absolute_path(arg) else _redact_userinfo(arg) for arg in rest[index:]
    ]
    return tuple(out)


def command_record(
    result: GitResult, *, truncated: bool = False, include_duration: bool = False
) -> CommandRecord:
    """Turn one git invocation into the :class:`CommandRecord` evidence carries (P6).

    The argv is redacted by :func:`redact_argv`, and stdout and stderr are hashed with
    sha256 rather than stored: the bytes may be megabytes of a hostile repository's
    contents, while the hash is enough to prove that a re-run produced the same output.

    ``duration_ms`` carries **no measurement unless ``include_duration`` is asked for**.
    Wall-clock time differs between two runs on the same input, and a record lives inside
    ``Evidence``, which ``Result.to_json`` must serialize byte-identically (P2);
    ``Result.timings`` is where a duration belongs. "Not measured" is ``None``
    (:data:`DURATION_NOT_MEASURED`), which renderers show as no duration at all rather
    than as an invented ``0 ms`` (P6). The duration is not part of the evidence identity
    either — see ``checks/base.make_evidence``, which hashes claims, outcome, strength,
    summary, details and locations, and never ``commands`` — so recording a command can
    never move an evidence ID.

    ``truncated`` says that the caller stopped reading before the search was exhausted (a
    hit cap), not that the hashed bytes are partial.
    """
    return CommandRecord(
        argv=redact_argv(result.argv),
        exit_code=result.returncode,
        stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
        duration_ms=result.duration_ms if include_duration else DURATION_NOT_MEASURED,
        truncated=truncated,
    )


def record_command(sink: CommandSink | None, result: GitResult, *, truncated: bool = False) -> None:
    """Append ``result`` to ``sink`` as a redacted record, doing nothing without a sink."""
    if sink is not None:
        sink.append(command_record(result, truncated=truncated))


def hardened_env(*, use_user_config: bool = False, online: bool = False) -> dict[str, str]:
    """Build the environment for a git child process.

    Inherited ``GIT_*`` variables are dropped (they could redirect the repository, the
    pager, ssh or diff drivers). System config is always ignored; global config is
    ignored unless ``use_user_config`` is set (``--git-use-user-config``). Unless
    ``online``, ``GIT_NO_LAZY_FETCH`` stops a partial clone from silently fetching missing
    objects over the network (P3: no network without ``--online``).
    """
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    if not online:
        env["GIT_NO_LAZY_FETCH"] = "1"
    if not use_user_config:
        env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def build_argv(
    args: Sequence[str],
    *,
    git_dir: Path | None = None,
    allow_test_only: bool = False,
) -> list[str]:
    """Return the full, hardened argv for ``git <args>`` without running it."""
    if not args:
        raise ForbiddenCommandError("empty git command")
    subcommand, *rest = args
    allowed = ALLOWED_SUBCOMMANDS | (TEST_ONLY_SUBCOMMANDS if allow_test_only else frozenset())
    if subcommand not in allowed:
        raise ForbiddenCommandError(f"git subcommand not allowed: {subcommand!r}")

    exe = git_executable()
    if exe is None:
        raise ExternalToolError("git was not found on PATH")

    argv = [exe, "--no-pager"]
    for setting in HARDENING_CONFIG:
        argv += ["-c", setting]
    if git_dir is not None:
        resolved = str(git_dir.resolve())
        argv += ["-c", f"safe.directory={resolved}", f"--git-dir={resolved}"]
    for arg in _option_positions(subcommand, rest):
        if arg.startswith(_DANGEROUS_OPTIONS) or arg in ("-u", "-c", "-O"):
            raise ForbiddenCommandError(f"git option not allowed: {arg!r}")
    argv.append(subcommand)
    argv += _SUBCOMMAND_GUARDS.get(subcommand, ())
    argv += rest
    return argv


def _option_positions(subcommand: str, rest: Sequence[str]) -> list[str]:
    """The arguments git may parse as options: not ``grep``'s pattern after ``-e``, and nothing
    after a bare ``--`` (pathspecs). Both are data to git, and may legitimately quote text such
    as ``--upload-pack=…`` from a report. Every other position stays checked."""
    out: list[str] = []
    after_e = False
    for arg in rest:
        if arg == "--":
            break
        if after_e:
            after_e = False
            continue
        out.append(arg)
        after_e = subcommand == "grep" and arg == "-e"
    return out


def safe_rev(rev: str) -> str:
    """Validate a revision that may come from report text before it reaches an argv.

    Rejects option-looking values (``--upload-pack=…``), control characters and absurd
    lengths. Callers must still put revisions after ``--end-of-options``.
    """
    if not rev or rev.startswith("-") or len(rev) > MAX_REV_LEN:
        raise ForbiddenCommandError(f"unsafe revision: {rev[:80]!r}")
    if any(ord(ch) < _PRINTABLE or ch == "\x7f" for ch in rev):
        raise ForbiddenCommandError("revision contains control characters")
    return rev


def run_git(
    args: Sequence[str],
    *,
    git_dir: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    stdin: bytes | None = None,
    use_user_config: bool = False,
    allow_test_only: bool = False,
    online: bool = False,
) -> GitResult:
    """Run ``git <args>`` with every hardening measure applied.

    Raises :class:`ForbiddenCommandError` for subcommands outside the allowlist and
    :class:`ExternalToolError` when git is missing or times out. A non-zero exit status is
    *not* an exception; callers inspect :attr:`GitResult.returncode`.
    """
    argv = build_argv(args, git_dir=git_dir, allow_test_only=allow_test_only)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            env=hardened_env(use_user_config=use_user_config, online=online),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"git {args[0]} timed out after {timeout:g}s") from exc
    return GitResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def git_version() -> str | None:
    """Return git's version string (e.g. ``"2.55.0"``), or ``None`` if git is unavailable."""
    exe = git_executable()
    if exe is None:
        return None
    try:
        proc = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_S,
            env=hardened_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout.decode("utf-8", "replace").strip()
    prefix = "git version "
    return text[len(prefix) :] if text.startswith(prefix) else text


class CatFileBatch:
    """A persistent ``git cat-file --batch`` process for fast blob and tree reads (§11.1).

    ``read`` returns ``(type, content)`` or ``None`` for a missing object. Objects larger
    than ``max_bytes`` are consumed (to keep the stream in sync) but returned as
    ``(type, None)``. Use as a context manager, or call :meth:`close`.
    """

    def __init__(self, git_dir: Path, *, max_bytes: int = 2 * 1024 * 1024) -> None:
        self._max_bytes = max_bytes
        argv = build_argv(["cat-file", "--batch"], git_dir=git_dir)
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=hardened_env(),
        )

    def __enter__(self) -> CatFileBatch:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def read(self, name: str) -> tuple[str, bytes | None] | None:
        """Read an object by SHA or ``<rev>:<path>`` (validated with :func:`safe_rev`)."""
        safe_rev(name)
        stdin, stdout = self._proc.stdin, self._proc.stdout
        if stdin is None or stdout is None or self._proc.poll() is not None:
            raise ExternalToolError("git cat-file --batch is not running")
        stdin.write(name.encode("utf-8") + b"\n")
        stdin.flush()
        header = stdout.readline().rstrip(b"\n").split(b" ")
        # "<sha> <type> <size>" on success; "<name> missing" / "<name> ambiguous" otherwise,
        # where <name> may itself contain spaces ("v1:a b" -> three tokens, last not a size).
        if len(header) != 3 or not header[2].isdigit():  # noqa: PLR2004
            return None
        obj_type, size = header[1].decode("ascii", "replace"), int(header[2])
        if size > self._max_bytes:
            remaining = size + 1
            while remaining:
                remaining -= len(stdout.read(min(remaining, 1 << 20)) or b"\0")
            return obj_type, None
        content = stdout.read(size)
        stdout.read(1)  # trailing newline
        return obj_type, content

    def close(self) -> None:
        if self._proc.poll() is None:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if self._proc.stdout is not None:
            self._proc.stdout.close()


@dataclass(frozen=True, slots=True)
class TagRef:
    name: str
    commit: str
    epoch: int  # tagger date for annotated tags, else commit date (Unix seconds)


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    sha: str
    size: int
    mode: str


@dataclass(frozen=True, slots=True)
class GrepHit:
    rev: str
    path: str
    line: int
    text: str


#: Keep batched command lines well under Windows' ~8k character limit (SPEC §11.4).
MAX_ARGV_CHARS = 6000
_PICKAXE_TIMEOUT_S = 20.0


class HistoryTimeoutError(ExternalToolError):
    """A history search exceeded its time budget, so history counts as *incomplete*."""


class HistoryUnavailableError(HistoryTimeoutError):
    """A history search failed (git exited with an error, e.g. a missing object), so
    history counts as *incomplete*, exactly as for a timeout (P4)."""


#: ``git grep`` exits 0 with matches and 1 without; anything else is a failure.
_GREP_OK_CODES = (0, 1)


class GitRepo:
    """Read-only, plumbing-only access to one repository (bare or not).

    Every method goes through :func:`run_git`, so all hardening applies. Revisions and
    paths that can come from report text are validated with :func:`safe_rev` and passed
    after ``--end-of-options`` or ``--``.
    """

    def __init__(
        self, git_dir: Path, *, online: bool = False, use_user_config: bool = False
    ) -> None:
        self.git_dir = git_dir
        self.online = online
        self.use_user_config = use_user_config
        self._batch: CatFileBatch | None = None

    # -- plumbing ---------------------------------------------------------------------
    def run(
        self,
        args: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        record: CommandSink | None = None,
    ) -> GitResult:
        """Run one plumbing command; ``record`` collects it (see :func:`command_record`)."""
        result = run_git(
            args,
            git_dir=self.git_dir,
            timeout=timeout,
            online=self.online,
            use_user_config=self.use_user_config,
        )
        record_command(record, result)
        return result

    def close(self) -> None:
        if self._batch is not None:
            self._batch.close()
            self._batch = None

    def __enter__(self) -> GitRepo:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- refs -------------------------------------------------------------------------
    def rev_parse(
        self, rev: str, *, kind: str = "commit", record: CommandSink | None = None
    ) -> str | None:
        """Full SHA of ``rev`` peeled to ``kind`` (``commit`` or ``tree``), or ``None``."""
        safe_rev(rev)
        result = self.run(
            ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{rev}^{{{kind}}}"],
            record=record,
        )
        out = result.stdout.decode("ascii", "replace").strip()
        return out if result.returncode == 0 and out else None

    def has_commit(self, sha: str) -> bool:
        return self.rev_parse(sha) is not None

    def is_shallow(self) -> bool:
        result = self.run(["rev-parse", "--is-shallow-repository"])
        return result.stdout.strip() == b"true"

    def default_branch(self) -> str | None:
        result = self.run(["rev-parse", "--abbrev-ref", "HEAD"])
        name = result.stdout.decode("utf-8", "replace").strip()
        return name if result.returncode == 0 and name and name != "HEAD" else None

    def tags(self) -> list[TagRef]:
        """Every tag peeled to its commit, sorted by name. Tags pointing at non-commits are
        skipped."""
        fmt = (
            "%(refname:strip=2)%00%(objecttype)%00%(objectname)%00"
            "%(*objecttype)%00%(*objectname)%00%(creatordate:unix)"
        )
        result = self.run(["for-each-ref", f"--format={fmt}", "refs/tags"], timeout=60)
        tags: list[TagRef] = []
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\0")
            if len(parts) != 6:  # noqa: PLR2004
                continue
            name, otype, oid, ptype, poid, epoch = parts
            commit = (
                poid if otype == "tag" and ptype == "commit" else oid if otype == "commit" else ""
            )
            if commit:
                tags.append(TagRef(name, commit, int(epoch or 0)))
        return sorted(tags, key=lambda t: t.name)

    def commit_epoch(self, rev: str) -> int | None:
        safe_rev(rev)
        result = self.run(["log", "-1", "--format=%ct", "--end-of-options", rev])
        text = result.stdout.strip()
        return int(text) if result.returncode == 0 and text.isdigit() else None

    def tip_before(self, branch: str, epoch: int) -> str | None:
        """The last commit on ``branch`` at or before ``epoch`` (``rev-list -1 --before``)."""
        safe_rev(branch)
        result = self.run(["rev-list", "-1", f"--before={int(epoch)}", "--end-of-options", branch])
        sha = result.stdout.decode("ascii", "replace").strip()
        return sha if result.returncode == 0 and sha else None

    # -- trees and blobs --------------------------------------------------------------
    def ls_tree(self, rev: str) -> list[TreeEntry]:
        """Every blob in the tree of ``rev`` (``ls-tree -r -z --long``)."""
        safe_rev(rev)
        result = self.run(["ls-tree", "-r", "-z", "--long", "--end-of-options", rev], timeout=120)
        entries: list[TreeEntry] = []
        for record in result.stdout.split(b"\0"):
            if not record:
                continue
            meta, _, path = record.partition(b"\t")
            fields = meta.split()
            if len(fields) != 4 or fields[1] != b"blob":  # noqa: PLR2004
                continue
            size = int(fields[3]) if fields[3].isdigit() else 0
            entries.append(
                TreeEntry(
                    path.decode("utf-8", "replace"),
                    fields[2].decode("ascii"),
                    size,
                    fields[0].decode("ascii"),
                )
            )
        return entries

    def read_blob(self, sha: str, *, max_bytes: int = 2 * 1024 * 1024) -> bytes | None:
        if self._batch is None:
            self._batch = CatFileBatch(self.git_dir, max_bytes=max_bytes)
        found = self._batch.read(sha)
        if found is None or found[0] != "blob":
            return None
        return found[1]

    def read_file(self, rev: str, path: str) -> bytes | None:
        """Content of ``path`` at ``rev`` (``None`` if absent or too large)."""
        safe_rev(rev)
        if "\n" in path or path.startswith("-"):
            raise ForbiddenCommandError("unsafe path")
        return self.read_blob(f"{rev}:{path}")

    # -- search -----------------------------------------------------------------------
    def grep(
        self,
        pattern: str,
        revs: Sequence[str],
        *,
        pathspecs: Sequence[str] = (),
        word: bool = False,
        files_only: bool = False,
        max_hits: int = 1000,
        timeout: float = 60.0,
        record: CommandSink | None = None,
    ) -> list[GrepHit]:
        """Fixed-string search across one or more trees, batched to keep argv short.

        ``record`` collects one :class:`CommandRecord` per batch, the last one marked
        ``truncated`` when the hit cap stopped the search early.
        """
        if not pattern or "\n" in pattern:
            return []
        flags = (
            ["-I", "-F", "--full-name", "-z"]
            + (["-w"] if word else [])
            + (["-l"] if files_only else ["-n"])
        )
        hits: list[GrepHit] = []
        for batch in _batches([safe_rev(r) for r in revs], MAX_ARGV_CHARS - len(pattern)):
            argv = ["grep", *flags, "-e", pattern, *batch, "--", *pathspecs]
            result = self.run(argv, timeout=timeout)
            if result.returncode not in _GREP_OK_CODES:
                # A bad revision or a broken object store is not "no match": returning
                # nothing here would read as absence and could refute a true claim (P4).
                record_command(record, result)
                raise ExternalToolError(f"git grep failed with exit code {result.returncode}")
            hits += _parse_grep(result.stdout, batch, files_only=files_only)
            capped = len(hits) >= max_hits
            record_command(record, result, truncated=capped)
            if capped:
                return hits[:max_hits]
        return hits

    def pickaxe_first(
        self,
        text: str,
        *,
        timeout: float = _PICKAXE_TIMEOUT_S,
        record: CommandSink | None = None,
    ) -> str | None:
        """A commit on any ref whose diff adds or removes ``text`` (``log --all -S``), or
        ``None`` if history never contained it. Raises :class:`HistoryTimeoutError` when
        the budget runs out, and its subclass :class:`HistoryUnavailableError` when git
        fails or ``text`` is empty or holds control characters other than tab, so callers
        can report incomplete history (SPEC §12 C03).

        Nothing is appended to ``record`` when the search times out: there is no exit code
        and no output to hash, and inventing either would be a lie about what ran (P6)."""
        if not text or any((ord(ch) < _PRINTABLE and ch != "\t") or ch == "\x7f" for ch in text):
            # Unsearchable is not "never in history": returning ``None`` here would let a
            # caller refute a genuine quote (P4). Tabs are ordinary source indentation.
            raise HistoryUnavailableError("text cannot be searched in history")
        try:
            result = self.run(
                ["log", "--all", "-1", "--format=%H", f"-S{text}"], timeout=timeout, record=record
            )
        except ExternalToolError as exc:
            raise HistoryTimeoutError(str(exc)) from exc
        if result.returncode != 0:
            # An empty stdout from a failed log is not "never in history" (P4).
            raise HistoryUnavailableError(f"git log -S failed with exit code {result.returncode}")
        sha = result.stdout.decode("ascii", "replace").strip()
        return sha or None

    def export_tree(self, rev: str, dest: Path, *, max_total_bytes: int = 512 * 1024 * 1024) -> int:
        """Write the files of ``rev`` under ``dest`` using plumbing only; return the count.

        ``git archive`` is deliberately **not** used: it pipes its output through a
        ``tar.<format>.command`` taken from the repository's own config (found by the
        git-hazard canary test; see docs/research). Symlinks and submodules are skipped,
        paths are validated so nothing escapes ``dest``, and executable bits are kept.
        """
        root = dest.resolve()
        written = 0
        total = 0
        for entry in self.ls_tree(rev):
            if entry.mode not in ("100644", "100755"):
                continue  # symlinks (120000) and anything unusual are not materialized
            target = (root / entry.path).resolve()
            if not target.is_relative_to(root) or ".." in Path(entry.path).parts:
                raise ForbiddenCommandError(f"unsafe path in tree: {entry.path!r}")
            content = self.read_blob(entry.sha, max_bytes=max_total_bytes)
            if content is None:
                continue
            total += len(content)
            if total > max_total_bytes:
                raise ExternalToolError("tree is larger than the export limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            if entry.mode == "100755":
                target.chmod(0o755)
            written += 1
        return written


def _batches(items: Sequence[str], budget: int) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    used = 0
    for item in items:
        if current and used + len(item) + 1 > budget:
            batches.append(current)
            current, used = [], 0
        current.append(item)
        used += len(item) + 1
    if current:
        batches.append(current)
    return batches


def _split_rev(prefix: str, revs: Sequence[str]) -> tuple[str, str]:
    """Split ``rev:path`` using the known revisions (a tag name may itself contain ``:``)."""
    for rev in sorted(revs, key=len, reverse=True):
        if prefix.startswith(rev + ":"):
            return rev, prefix[len(rev) + 1 :]
    rev, _, path = prefix.partition(":")
    return rev, path


def _parse_grep(output: bytes, revs: Sequence[str], *, files_only: bool) -> list[GrepHit]:
    """Parse ``git grep -z`` output: ``rev:path NUL line NUL text`` per line, or
    ``rev:path NUL`` per file with ``-l``."""
    hits: list[GrepHit] = []
    if files_only:
        for record in output.split(b"\0"):
            rev, path = _split_rev(record.decode("utf-8", "replace"), revs)
            if path:
                hits.append(GrepHit(rev, path, 0, ""))
        return hits
    for raw in output.split(b"\n"):
        parts = raw.split(b"\0", 2)
        if len(parts) != 3 or not parts[1].isdigit():  # noqa: PLR2004
            continue
        rev, path = _split_rev(parts[0].decode("utf-8", "replace"), revs)
        hits.append(GrepHit(rev, path, int(parts[1]), parts[2].decode("utf-8", "replace")))
    return hits
