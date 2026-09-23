# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The per-repository code index (SPEC §11.3): SQLite in WAL mode, keyed by blob SHA.

A file that never changes is parsed once across every release. Trees are recorded per commit
(``trees``, ``tree_files``), and parse results per blob (``blobs``, ``symbols``, ``calls``,
``addr_taken``, ``macros``). The schema is versioned; a mismatch rebuilds the database.
The database lives in the private cache (0700 directory, 0600 file) because an index of a
private repository is as sensitive as the repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from nikasha.code.facts import CallSite, FileFacts, MacroDef, SymbolDef
from nikasha.code.gitio import GitRepo
from nikasha.code.languages import Lang, detect_language
from nikasha.config import cache_dir, ensure_private_dir

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
_MEMO_SIZE = 8192  # parse results kept in memory (LRU), including "not a source file"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blobs (
    sha TEXT PRIMARY KEY, lang TEXT NOT NULL, n_lines INTEGER NOT NULL,
    parsed_ok INTEGER NOT NULL, error_nodes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS symbols (
    blob_sha TEXT NOT NULL, name TEXT NOT NULL, qname TEXT NOT NULL, kind TEXT NOT NULL,
    start INTEGER NOT NULL, "end" INTEGER NOT NULL, flags TEXT NOT NULL, sig TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS calls (
    blob_sha TEXT NOT NULL, caller_qname TEXT, callee TEXT NOT NULL, line INTEGER NOT NULL,
    indirect INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS addr_taken (blob_sha TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS macros (
    blob_sha TEXT NOT NULL, name TEXT NOT NULL, line INTEGER NOT NULL, calls_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trees (commit_sha TEXT PRIMARY KEY, tree_sha TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree_files (
    tree_sha TEXT NOT NULL, path TEXT NOT NULL, blob_sha TEXT NOT NULL, size INTEGER NOT NULL,
    PRIMARY KEY (tree_sha, path));
CREATE TABLE IF NOT EXISTS indexed_trees (tree_sha TEXT PRIMARY KEY);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS symbols_blob ON symbols(blob_sha);
CREATE INDEX IF NOT EXISTS calls_blob ON calls(blob_sha);
CREATE INDEX IF NOT EXISTS tree_files_blob ON tree_files(blob_sha);
"""


@dataclass(frozen=True, slots=True)
class FileEntry:
    path: str
    blob: str
    size: int


@dataclass(frozen=True, slots=True)
class IndexStats:
    commit: str
    files: int
    source_files: int
    parsed_now: int
    seconds: float


def default_db_path(git_dir: Path) -> Path:
    key = hashlib.sha256(str(git_dir.resolve()).encode("utf-8")).hexdigest()[:16]
    return cache_dir() / "index" / f"{git_dir.name.removesuffix('.git') or 'repo'}-{key}.sqlite"


class CodeIndex:
    """Parse results and trees for one repository, cached on disk."""

    def __init__(
        self, repo: GitRepo, db_path: Path | None = None, *, headers_are_cpp: bool = False
    ) -> None:
        self.repo = repo
        self.headers_are_cpp = headers_are_cpp
        self._trees: dict[str, str] = {}  # commit -> tree, memoised
        self._recorded: set[str] = set()  # trees whose listing is in tree_files
        self._memo: OrderedDict[tuple[str, str], FileFacts | None] = OrderedDict()
        path = db_path or default_db_path(repo.git_dir)
        ensure_private_dir(path.parent)
        fresh = not path.exists()
        self.db = sqlite3.connect(path, isolation_level=None)
        if fresh and os.name == "posix":
            path.chmod(0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._ensure_schema()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> CodeIndex:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- schema -----------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        self.db.executescript(_SCHEMA)
        row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        if row is not None and row[0] != str(SCHEMA_VERSION):
            for table in ("blobs", "symbols", "calls", "addr_taken", "macros", "trees",
                          "tree_files", "indexed_trees", "meta"):  # fmt: skip
                self.db.execute(f"DROP TABLE IF EXISTS {table}")
            self.db.executescript(_SCHEMA)
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),)
        )

    # -- trees ------------------------------------------------------------------------
    def tree_of(self, commit: str) -> str | None:
        if commit in self._trees:
            return self._trees[commit]
        row = self.db.execute("SELECT tree_sha FROM trees WHERE commit_sha=?", (commit,)).fetchone()
        if row:
            tree = str(row[0])
        else:
            found = self.repo.rev_parse(commit, kind="tree")
            if found is None:
                return None
            tree = found
            self.db.execute("INSERT OR REPLACE INTO trees VALUES (?, ?)", (commit, tree))
        self._trees[commit] = tree
        return tree

    def _record_tree(self, tree: str) -> None:
        """Store the listing of ``tree`` in ``tree_files`` once.

        Checked once per process: re-reading a whole listing per file lookup made the lazy
        timeline quadratic in tree size (58 of 70 s on 20 curl releases, ADR 0004).
        """
        if tree in self._recorded:
            return
        known = self.db.execute(
            "SELECT 1 FROM tree_files WHERE tree_sha=? LIMIT 1", (tree,)
        ).fetchone()
        if known is None:
            entries = self.repo.ls_tree(tree)
            with self._transaction():
                self.db.executemany(
                    "INSERT OR IGNORE INTO tree_files VALUES (?, ?, ?, ?)",
                    [(tree, e.path, e.sha, e.size) for e in entries],
                )
        self._recorded.add(tree)

    def files(self, commit: str) -> list[FileEntry]:
        """Every blob in the tree of ``commit`` (recorded once per tree), sorted by path."""
        tree = self.tree_of(commit)
        if tree is None:
            return []
        self._record_tree(tree)
        rows = self.db.execute(
            "SELECT path, blob_sha, size FROM tree_files WHERE tree_sha=? ORDER BY path", (tree,)
        ).fetchall()
        return [FileEntry(p, b, s) for p, b, s in rows]

    def file_at(self, commit: str, path: str) -> FileEntry | None:
        tree = self.tree_of(commit)
        if tree is None:
            return None
        self._record_tree(tree)
        row = self.db.execute(
            "SELECT path, blob_sha, size FROM tree_files WHERE tree_sha=? AND path=?", (tree, path)
        ).fetchone()
        return FileEntry(*row) if row else None

    # -- facts ------------------------------------------------------------------------
    def language_of(self, path: str, head: bytes = b"") -> Lang | None:
        return detect_language(path, head, headers_are_cpp=self.headers_are_cpp)

    def facts(self, blob: str, path: str) -> FileFacts | None:
        """Parse results for ``blob`` at ``path`` (parsed and stored on first use)."""
        key = (blob, path)
        if key in self._memo:
            self._memo.move_to_end(key)
            return self._memo[key]
        result = self._facts_uncached(blob, path)
        self._memo[key] = result
        if len(self._memo) > _MEMO_SIZE:
            self._memo.popitem(last=False)
        return result

    def _facts_uncached(self, blob: str, path: str) -> FileFacts | None:
        cached = self._load_facts(blob)
        if cached is not None:
            return cached
        content = self.repo.read_blob(blob, max_bytes=MAX_FILE_BYTES)
        if content is None or b"\0" in content[:8000]:
            return None  # too large, missing, or binary
        lang = self.language_of(path, content[:65536])
        if lang is None:
            return None
        from nikasha.code.parser import parse_file  # noqa: PLC0415 (tree-sitter loads lazily)

        facts = parse_file(lang, content)
        self._store_facts(blob, facts)
        return facts

    def facts_at(self, commit: str, path: str) -> FileFacts | None:
        entry = self.file_at(commit, path)
        return self.facts(entry.blob, entry.path) if entry else None

    def index_commit(self, commit: str) -> IndexStats:
        """Parse every source file in ``commit`` (unchanged blobs are reused)."""
        started = time.monotonic()
        files = self.files(commit)
        known = {row[0] for row in self.db.execute("SELECT sha FROM blobs")}
        sources = [f for f in files if f.size <= MAX_FILE_BYTES and self.language_of(f.path)]
        parsed = 0
        with self._transaction():
            for entry in sources:
                if entry.blob not in known:
                    self.facts(entry.blob, entry.path)
                    known.add(entry.blob)
                    parsed += 1
            tree = self.tree_of(commit)
            self.db.execute("INSERT OR IGNORE INTO indexed_trees VALUES (?)", (tree,))
        return IndexStats(commit, len(files), len(sources), parsed, time.monotonic() - started)

    def is_indexed(self, commit: str) -> bool:
        tree = self.tree_of(commit)
        return (
            tree is not None
            and self.db.execute("SELECT 1 FROM indexed_trees WHERE tree_sha=?", (tree,)).fetchone()
            is not None
        )

    def definitions(self, commit: str, name: str) -> list[tuple[str, SymbolDef]]:
        """Where ``name`` (or a qualified name) is defined at ``commit``.

        Uses the full index when the commit is indexed; otherwise greps for the name and
        parses only the matching files (lazy strategy).
        """
        if self.is_indexed(commit):
            tree = self.tree_of(commit)
            rows = self.db.execute(
                'SELECT tf.path, s.name, s.qname, s.kind, s.start, s."end", s.flags, s.sig '
                "FROM tree_files tf JOIN symbols s ON s.blob_sha = tf.blob_sha "
                "WHERE tf.tree_sha=? AND (s.name=? OR s.qname=?) ORDER BY tf.path, s.start",
                (tree, name, name),
            ).fetchall()
            return [(r[0], _symbol(r[1:])) for r in rows]
        bare = name.replace("::", ".").rsplit(".", 1)[-1]
        found: list[tuple[str, SymbolDef]] = []
        for hit in self.repo.grep(bare, [commit], word=True, files_only=True, max_hits=500):
            facts = self.facts_at(commit, hit.path)
            if facts is not None:
                found += [(hit.path, s) for s in facts.definitions(name)]
        return sorted(found, key=lambda t: (t[0], t[1].start_line))

    # -- storage ----------------------------------------------------------------------
    def _store_facts(self, blob: str, facts: FileFacts) -> None:
        db = self.db
        db.execute("DELETE FROM blobs WHERE sha=?", (blob,))
        for table in ("symbols", "calls", "addr_taken", "macros"):
            db.execute(f"DELETE FROM {table} WHERE blob_sha=?", (blob,))  # noqa: S608
        db.execute(
            "INSERT INTO blobs VALUES (?, ?, ?, ?, ?)",
            (blob, facts.lang, facts.n_lines, int(facts.parsed_ok), facts.error_nodes),
        )
        db.executemany(
            "INSERT INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    blob,
                    s.name,
                    s.qname,
                    s.kind,
                    s.start_line,
                    s.end_line,
                    ",".join(sorted(s.flags)),
                    s.signature_hash,
                )
                for s in facts.symbols
            ],
        )
        db.executemany(
            "INSERT INTO calls VALUES (?, ?, ?, ?, ?)",
            [(blob, c.caller_qname, c.callee, c.line, int(c.indirect)) for c in facts.calls],
        )
        db.executemany(
            "INSERT INTO addr_taken VALUES (?, ?)", [(blob, n) for n in sorted(facts.addr_taken)]
        )
        db.executemany(
            "INSERT INTO macros VALUES (?, ?, ?, ?)",
            [(blob, m.name, m.line, json.dumps(list(m.calls))) for m in facts.macros],
        )

    def _load_facts(self, blob: str) -> FileFacts | None:
        row = self.db.execute(
            "SELECT lang, n_lines, parsed_ok, error_nodes FROM blobs WHERE sha=?", (blob,)
        ).fetchone()
        if row is None:
            return None
        symbols = tuple(
            _symbol(r)
            for r in self.db.execute(
                'SELECT name, qname, kind, start, "end", flags, sig FROM symbols '
                "WHERE blob_sha=? ORDER BY rowid",
                (blob,),
            )
        )
        calls = tuple(
            CallSite(r[0], r[1], r[2], bool(r[3]))
            for r in self.db.execute(
                "SELECT caller_qname, callee, line, indirect FROM calls WHERE blob_sha=? "
                "ORDER BY rowid",
                (blob,),
            )
        )
        addr = frozenset(
            r[0] for r in self.db.execute("SELECT name FROM addr_taken WHERE blob_sha=?", (blob,))
        )
        macros = tuple(
            MacroDef(r[0], r[1], tuple(json.loads(r[2])))
            for r in self.db.execute(
                "SELECT name, line, calls_json FROM macros WHERE blob_sha=? ORDER BY rowid", (blob,)
            )
        )
        return FileFacts(
            lang=row[0], n_lines=row[1], parsed_ok=bool(row[2]), symbols=symbols, calls=calls,
            addr_taken=addr, macros=macros, error_nodes=row[3],
        )  # fmt: skip

    def _transaction(self) -> _Transaction:
        return _Transaction(self.db)


class _Transaction:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        self.depth_owner = False

    def __enter__(self) -> None:
        if not self.db.in_transaction:
            self.db.execute("BEGIN")
            self.depth_owner = True

    def __exit__(self, exc_type: object, *_: object) -> None:
        if self.depth_owner:
            self.db.execute("ROLLBACK" if exc_type else "COMMIT")


def _symbol(row: Sequence[object]) -> SymbolDef:
    name, qname, kind, start, end, flags, sig = row
    return SymbolDef(
        name=str(name),
        qname=str(qname),
        kind=str(kind),  # type: ignore[arg-type]
        start_line=int(start),  # type: ignore[call-overload]
        end_line=int(end),  # type: ignore[call-overload]
        flags=frozenset(f for f in str(flags).split(",") if f),
        signature_hash=str(sig),
    )
