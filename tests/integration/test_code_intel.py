# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Code intelligence end to end on the vulnlab history (SPEC §11): index, timeline, call graph,
trace forensics and the CLI. Every expected value comes from examples/vulnlab/README.md."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nikasha.cli import app
from nikasha.code.callgraph import edge
from nikasha.code.gitio import GitRepo
from nikasha.code.index import SCHEMA_VERSION, CodeIndex
from nikasha.code.timeline import build_timeline
from nikasha.code.trace_forensics import analyze_trace, bare_function
from nikasha.extract import extract_claims
from nikasha.ingest import load_report
from nikasha.model.claims import Frame, TraceClaim, TraceData
from nikasha.resolve.refs import ReleaseList

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = json.loads((ROOT / "examples" / "vulnlab" / "expected.json").read_text())
REPORTS = ROOT / "examples" / "reports"
ASAN = ROOT / "tests" / "fixtures" / "traces" / "asan"


@pytest.fixture
def idx(vulnlab_repo, tmp_path):
    repo = GitRepo(vulnlab_repo)
    with repo, CodeIndex(repo, tmp_path / "index.sqlite") as index:
        yield index


@pytest.fixture
def releases(vulnlab_repo):
    with GitRepo(vulnlab_repo) as repo:
        return ReleaseList.from_tags(repo.tags())


def _trace(path: Path) -> TraceClaim:
    claims = extract_claims(load_report(path)).claims
    return next(c for c in claims if isinstance(c, TraceClaim))


class TestIndex:
    def test_index_and_reuse(self, idx):
        first = idx.index_commit(EXPECTED["v1.2.0"])
        assert first.source_files >= 5
        assert first.parsed_now == first.source_files
        again = idx.index_commit(EXPECTED["v1.2.0"])
        assert again.parsed_now == 0
        # v1.2.1 changes only comments in hdr.c/util.c: most blobs are reused.
        shifted = idx.index_commit(EXPECTED["v1.2.1"])
        assert 0 < shifted.parsed_now < shifted.source_files

    def test_facts_and_definitions(self, idx):
        commit = EXPECTED["v1.2.0"]
        facts = idx.facts_at(commit, "src/util.c")
        assert facts is not None
        (sym,) = facts.definitions("util_copy_value")
        assert (sym.start_line, sym.end_line) == (8, 18)
        lazy = idx.definitions(commit, "util_copy_value")
        idx.index_commit(commit)
        full = idx.definitions(commit, "util_copy_value")
        assert lazy == full
        assert [p for p, _ in full] == ["src/util.c"]
        assert idx.definitions(commit, "hdr_decode_chunked_value") == []

    def test_lookups_do_not_reread_trees_or_facts(self, idx, monkeypatch):
        # Regression (ADR 0004): file_at once re-read the whole tree listing per call, which
        # made the lazy timeline quadratic in tree size.
        commit = EXPECTED["v1.2.0"]
        listings, full_reads, loads = [], [], []
        ls_tree, files, load = idx.repo.ls_tree, idx.files, idx._load_facts
        monkeypatch.setattr(idx.repo, "ls_tree", lambda t: listings.append(t) or ls_tree(t))
        monkeypatch.setattr(idx, "files", lambda c: full_reads.append(c) or files(c))
        monkeypatch.setattr(idx, "_load_facts", lambda b: loads.append(b) or load(b))
        for _ in range(50):
            assert idx.facts_at(commit, "src/util.c") is not None
            assert idx.file_at(commit, "no/such/file.c") is None
        assert len(listings) == 1  # the tree is listed from git once
        assert full_reads == []  # single-file lookups never load the whole listing
        assert len(loads) == 1  # parse results come from memory after the first load

    def test_database_is_private_and_versioned(self, vulnlab_repo, tmp_path):
        path = tmp_path / "x.sqlite"
        with GitRepo(vulnlab_repo) as repo, CodeIndex(repo, path) as index:
            index.db.execute("UPDATE meta SET value='0' WHERE key='schema'")
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        with GitRepo(vulnlab_repo) as repo, CodeIndex(repo, path) as index:
            row = index.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            assert row[0] == str(SCHEMA_VERSION)


class TestTimeline:
    @pytest.mark.parametrize("strategy", ["lazy", "full"])
    @pytest.mark.parametrize(
        ("symbol", "runs"),
        [
            ("util_copy_value", [("v1.1.0", "v1.3.0")]),
            ("hdr_get", [("v1.0.0", "v1.2.1")]),
            ("hdr_find", [("v1.3.0", "v1.3.0")]),
            ("util_trim", [("v1.0.0", "v1.0.0")]),
            ("util_strip", [("v1.1.0", "v1.3.0")]),
            ("hdr_parse_block", [("v1.1.0", "v1.3.0")]),
        ],
    )
    def test_runs(self, idx, releases, symbol, runs, strategy):
        tl = build_timeline(idx, releases, symbol, strategy=strategy)
        assert tl.runs == runs

    def test_fabricated_symbol_never_existed(self, idx, releases):
        tl = build_timeline(idx, releases, "hdr_decode_chunked_value")
        assert not tl.ever_defined
        assert tl.history_complete
        assert tl.never_in_history is True

    def test_mentioned_but_not_defined(self, idx, releases):
        # memcpy appears in util.c from v1.1.0 but is never *defined* in libhdr.
        tl = build_timeline(idx, releases, "memcpy")
        assert not tl.ever_defined
        assert any(p.referenced for p in tl.presence)
        assert tl.never_in_history is False


HIDDEN_V1 = b"""int ok(void)
{
  return 0;
}

int hidden_fn(int *data)
{
#if V >= 2
  if(data[0]) {
#else
  if(data[1]) {
#endif
    return 1;
  }
  return 0;
}
"""
HIDDEN_V2 = b"int hidden_fn(int *data)\n{\n  return data[0];\n}\n"


def _make_repo(work: Path, releases: list[tuple[str, dict[str, bytes]]]) -> Path:
    """A small git repository with one tagged commit per release; returns its git dir."""
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    work.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(work), *args], env=env, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    for tag, files in releases:
        for name, content in files.items():
            (work / name).parent.mkdir(parents=True, exist_ok=True)
            (work / name).write_bytes(content)
            git("add", name)
        git("commit", "-q", "-m", tag)
        git("tag", tag)
    return work / ".git"


@pytest.fixture
def hidden_repo(tmp_path):
    """v1.0.0 defines hidden_fn behind a body-level #if that tree-sitter cannot parse."""
    return _make_repo(
        tmp_path / "w", [("v1.0.0", {"hidden.c": HIDDEN_V1}), ("v1.1.0", {"hidden.c": HIDDEN_V2})]
    )


class TestUncertainAbsence:
    """P4: a definition the parser may have missed is never reported as absent."""

    @pytest.mark.parametrize("strategy", ["lazy", "full"])
    def test_partially_parsed_mention_is_uncertain(self, hidden_repo, tmp_path, strategy):
        with GitRepo(hidden_repo) as repo, CodeIndex(repo, tmp_path / "i.sqlite") as index:
            releases = ReleaseList.from_tags(repo.tags())
            tl = build_timeline(index, releases, "hidden_fn", strategy=strategy)
        first, second = tl.presence
        assert (first.release, first.defined, first.referenced) == ("v1.0.0", False, True)
        assert first.partial == ("hidden.c",)
        assert first.uncertain
        assert (second.defined, second.uncertain) == (True, False)
        assert tl.uncertain_releases == ["v1.0.0"]
        assert tl.runs == [("v1.1.0", "v1.1.0")]

    def test_clean_absence_is_certain(self, idx, releases):
        tl = build_timeline(idx, releases, "memcpy")
        assert tl.uncertain_releases == []


_STEPS = "\n".join(f"    step{i}(p);" for i in range(32))
GRAPH_C = f"""#define LOG_AND_FREE(p) do {{ log_it(p); release(p); }} while (0)

struct ops {{
    void (*run)(char *);
}};

static void release(char *p)
{{
    free(p);
}}

static void log_it(char *p)
{{
    (void)p;
}}

static inline void helper(char *p)
{{
    release(p);
}}

static void big_helper(char *p)
{{
{_STEPS}
    release(p);
}}

static void (*hook)(char *) = release;

void direct_call(char *p)
{{
    release(p);
}}

void via_macro(char *p)
{{
    LOG_AND_FREE(p);
}}

void via_inline(char *p)
{{
    helper(p);
}}

void via_big(char *p)
{{
    big_helper(p);
}}

void via_pointer(struct ops *o, char *p)
{{
    o->run(p);
}}
""".encode()


class TestEdgeKinds:
    """Every edge kind of SPEC §11.4, with the evidence that justifies it."""

    @pytest.fixture
    def graph(self, tmp_path):
        git_dir = _make_repo(tmp_path / "g", [("v1.0.0", {"graph.c": GRAPH_C})])
        with GitRepo(git_dir) as repo, CodeIndex(repo, tmp_path / "i.sqlite") as index:
            yield index, repo.rev_parse("v1.0.0")

    @pytest.mark.parametrize(
        ("caller", "kind", "note"),
        [
            ("direct_call", "direct", "direct call"),
            ("via_macro", "macro", "via macro LOG_AND_FREE (graph.c:1)"),
            ("via_inline", "inlined_2hop", "via helper (graph.c:17)"),
            ("via_pointer", "indirect_possible", "indirect call via run"),
            # big_helper is 36 lines and not inline: a real call would leave its own frame.
            ("via_big", "none", None),
        ],
    )
    def test_kinds(self, graph, caller, kind, note):
        index, commit = graph
        result = edge(index, commit, caller, "release")
        assert result.kind == kind, result
        if note is None:
            assert result.evidence == []
            assert result.caller_calls == ["big_helper"]
        else:
            assert [e.note for e in result.evidence] == [note]
            assert result.evidence[0].path == "graph.c"

    def test_indirect_needs_an_address_taken_callee(self, graph):
        index, commit = graph
        # log_it is never address-taken, so o->run(p) cannot be claimed to reach it.
        assert edge(index, commit, "via_pointer", "log_it").kind == "none"

    def test_macro_edge_to_the_other_call_in_the_macro(self, graph):
        index, commit = graph
        assert edge(index, commit, "via_macro", "log_it").kind == "macro"


class TestCallGraph:
    @pytest.mark.parametrize(
        ("caller", "callee", "kind"),
        [
            ("hdr_parse_line", "util_copy_value", "direct"),
            ("hdr_parse_block", "hdr_parse_line", "direct"),
            ("main", "hdr_parse_block", "direct"),
            ("hdr_get", "util_copy_value", "none"),
        ],
    )
    def test_edges_at_v1_2_0(self, idx, caller, callee, kind):
        result = edge(idx, EXPECTED["v1.2.0"], caller, callee)
        assert result.kind == kind, result
        if kind == "direct":
            assert result.evidence
        else:
            assert "hdr_find_line" in result.caller_calls

    def test_unknown_caller(self, idx):
        result = edge(idx, EXPECTED["v1.2.0"], "hdr_decode_chunked_value", "memcpy")
        assert not result.caller_found
        assert result.kind == "none"


class TestTraceForensics:
    def test_genuine_trace_fits_its_version(self, idx):
        analysis = analyze_trace(
            idx, EXPECTED["v1.2.0"], _trace(REPORTS / "genuine_hdr_overflow.md")
        )
        assert analysis.ratio == 1.0
        assert [f.resolved_path for f in analysis.frames] == [
            "src/util.c", "src/hdr.c", "src/hdr.c", "tools/hdrcat.c",
        ]  # fmt: skip
        assert all(e.kind == "direct" for e in analysis.edges)
        assert len(analysis.edges) == 3

    @pytest.mark.parametrize("tag", ["v1.1.0", "v1.2.1"])
    def test_genuine_trace_does_not_fit_other_versions(self, idx, tag):
        analysis = analyze_trace(idx, EXPECTED[tag], _trace(REPORTS / "genuine_hdr_overflow.md"))
        assert analysis.ratio is not None
        assert analysis.ratio < 1.0

    def test_v1_2_1_trace_fits_v1_2_1(self, idx):
        analysis = analyze_trace(
            idx, EXPECTED["v1.2.1"], _trace(ASAN / "02-vulnlab-heap-overflow-v1.2.1.txt")
        )
        assert analysis.ratio == 1.0

    def test_fabricated_trace(self, idx):
        analysis = analyze_trace(
            idx, EXPECTED["v1.2.0"], _trace(REPORTS / "fabricated_hdr_overflow.md")
        )
        by_function = {f.function: f for f in analysis.frames}
        hdr_get = by_function["hdr_get"]
        assert hdr_get.resolved_path == "src/hdr.c"
        assert hdr_get.line_in_bounds is False  # hdr.c:412 is past the end
        assert by_function["util_copy_value"].line_in_bounds is False  # util.c:77 too
        kinds = {(e.caller, e.callee): e.kind for e in analysis.edges}
        assert kinds[("hdr_get", "util_copy_value")] == "none"
        assert analysis.ratio is not None
        assert analysis.ratio < 0.5


class TestTraceEdgeCases:
    """Ambiguous paths, generated files and pathless frames (SPEC §11.4, §11.5)."""

    @pytest.fixture
    def repo_commit(self, tmp_path):
        files = {
            "a/util.c": b"int foo(void)\n{\n  return bar();\n}\n",
            "b/util.c": b"int bar(void)\n{\n  return 1;\n}\n",
            "lib/parse.y": b"%%\nstart: ;\n%%\n",
        }
        git_dir = _make_repo(tmp_path / "t", [("v1.0.0", files)])
        with GitRepo(git_dir) as repo, CodeIndex(repo, tmp_path / "i.sqlite") as index:
            yield index, repo.rev_parse("v1.0.0")

    def test_trace(self, repo_commit):
        index, commit = repo_commit
        frames = (
            Frame(index=0, function="bar", path="/build/util.c", line=3, raw="#0 bar"),
            Frame(index=1, function="foo", path="/build/util.c", line=3, raw="#1 foo"),
            Frame(index=2, function="yyparse", path="/src/lib/parse.c", line=120, raw="#2"),
            Frame(index=3, function="main", raw="#3 main"),
        )
        analysis = analyze_trace(index, commit, TraceData(format="asan", frames=frames))
        bar, foo, yyparse, main = analysis.frames
        # Two files end in util.c: the one defining the frame's function wins.
        assert (bar.resolved_path, bar.function_matches) == ("b/util.c", True)
        assert (foo.resolved_path, foo.function_matches) == ("a/util.c", True)
        # parse.c is generated from parse.y and not in git: not checkable, never "missing".
        assert yyparse.generated is not None
        assert yyparse.file_exists is None
        assert not yyparse.checkable
        assert not main.checkable
        assert analysis.ratio == 1.0
        # Edges touching the generated or pathless frame are skipped, not judged.
        assert [(e.caller, e.callee, e.kind) for e in analysis.edges] == [("foo", "bar", "direct")]


@pytest.mark.parametrize(
    ("name", "bare"),
    [
        ("ns::Parser::read_line(char const*) const", "read_line"),
        ("main.(*registry).add", "add"),
        ("CausedBy.readPort", "readPort"),
        ("std::vector<int>::push_back", "push_back"),
        ("util_copy_value", "util_copy_value"),
    ],
)
def test_bare_function(name, bare):
    assert bare_function(name) == bare


class TestCli:
    runner = CliRunner()

    def test_index(self, vulnlab_repo, tmp_path, monkeypatch):
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path))
        result = self.runner.invoke(app, ["index", "--repo", str(vulnlab_repo), "--history"])
        assert result.exit_code == 0, result.output
        assert "v1.3.0" in result.output

    def test_timeline_json_and_suggestions(self, vulnlab_repo, tmp_path, monkeypatch):
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path))
        result = self.runner.invoke(
            app, ["timeline", "util_copy_value", "--repo", str(vulnlab_repo), "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["runs"] == [["v1.1.0", "v1.3.0"]]
        typo = self.runner.invoke(app, ["timeline", "hdr_prase_line", "--repo", str(vulnlab_repo)])
        assert typo.exit_code == 0
        assert "did you mean: hdr_parse_line" in typo.output

    def test_timeline_reports_uncertainty(self, hidden_repo, tmp_path, monkeypatch):
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
        args = ["timeline", "hidden_fn", "--repo", str(hidden_repo)]
        text = self.runner.invoke(app, args, env={"COLUMNS": "160"})
        assert text.exit_code == 0, text.output
        assert "[?█]" in text.output
        assert "uncertain in 1 release(s)" in text.output
        data = json.loads(self.runner.invoke(app, [*args, "--json"]).stdout)
        assert data["uncertain_releases"] == ["v1.0.0"]
        assert data["presence"][0]["partial"] == ["hidden.c"]

    def test_trace(self, vulnlab_repo, tmp_path, monkeypatch):
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path))
        args = [
            "trace",
            str(ASAN / "01-vulnlab-heap-overflow-v1.2.0.txt"),
            "--repo",
            str(vulnlab_repo),
        ]
        result = self.runner.invoke(app, [*args, "--version", "1.2.0"], env={"COLUMNS": "160"})
        assert result.exit_code == 0, result.output
        assert "consistent frames: 100%" in result.output
        missing = self.runner.invoke(app, args)
        assert missing.exit_code == 1

    def test_offline_uncached_repo_is_a_clean_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path))
        result = self.runner.invoke(app, ["timeline", "x", "--repo", "https://example.org/a/b"])
        assert result.exit_code == 1
        assert "--online" in result.output
