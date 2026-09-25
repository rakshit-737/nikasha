# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The XSS, CSP and offline tests for the HTML report (SPEC §15.2, P3, P7).

The report is a single file a maintainer opens while triaging an embargoed report, built
entirely out of text a stranger wrote and out of a repository that stranger chose. Two
things must hold no matter what that text says.

**Nothing executes.** One script element, pinned by the SHA-256 the Content-Security-Policy
names, and no other executable construct anywhere: no second script, no ``onclick=``, no
``javascript:`` href, no attribute broken out of by a quote in a symbol name.

**Nothing is fetched.** ``default-src 'none'`` says so and this file checks it: no CDN, no
web font, no ``@import``, no external image. A document that phones home tells an observer
which vulnerability is being triaged, and when. Upstream permalinks in the ``href`` of a
plain ``<a>`` are the one exception, because they are the whole point of the report -- and
the tests below assert that *distinction* rather than banning URLs outright.

Two properties of these tests matter as much as what they assert.

*They are computed from the document.* The CSP test re-derives the hash from the ``<script>``
element the page actually served, not from :data:`~nikasha.render.html.page.BASE_JS`, so a
component that smuggles JS into the page is caught even though it also changed the constant.

*They run over whatever components exist.* Components are discovered, not registered
(:func:`~nikasha.render.html.component_modules`), so every loop here iterates over the
discovered set. A view added next week is covered by this file without anyone editing it.

Parsing is done with :mod:`html.parser` from the standard library: an escaping bug has to
be visible to a *parser*, since a substring search cannot tell an inert ``&lt;img&gt;`` in
a summary from a live ``<img>`` in the markup.

Note: this file carries no pytest marker. ``pyproject.toml`` defines ``sandbox``,
``network`` and ``slow`` only, ``--strict-markers`` is on, and these tests need none of
the three -- they are pure, fast and offline, so they run in the default suite.
"""

from __future__ import annotations

import base64
import hashlib
import re
from html.parser import HTMLParser
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.claims import (
    BehaviorClaim,
    ClaimBase,
    FileClaim,
    Frame,
    ImpactClaim,
    LineClaim,
    OptionClaim,
    PatchClaim,
    PatchHunk,
    PatchLine,
    PocClaim,
    ReferenceClaim,
    SnippetClaim,
    SymbolClaim,
    TraceClaim,
    VersionClaim,
)
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence
from nikasha.model.report import Span
from nikasha.model.result import Environment, ResolvedTarget, Result
from nikasha.model.verdict import Question, Verdict
from nikasha.render.html import component_modules, render_html_result
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.page import MAX_BYTES

# --- the payloads --------------------------------------------------------------------------

#: One payload per way out of a sink. Every string field of the fixture result carries the
#: whole set, so it does not matter which field a future component decides to render.
PAYLOADS = (
    "</script><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</style><style>@import url(https://evil.example/x)</style>",
    "</textarea></title></noscript></template>",
    "javascript:alert(1)",
    "<!--<script>",
    "'`--><svg/onload=alert(1)>",
    "\u202eannex/c.evil",
    "\u2066\u2067override\u2069\u2068",
    "\x00\x07\x1b[31mansi\x1b[0m\ufeff",
    "</script >",
    "]]><script>alert(1)</script>",
)
HOSTILE = " ".join(PAYLOADS)

#: Characters that must never survive into the document: they are invisible or they change
#: the reading direction, and this document exists to say what a path really is.
INVISIBLE = "\x00\x01\x07\x08\x0b\x0c\x0e\x1b\x1f\x7f\u200b\u200e\u202e\u2066\u2069\ufeff"

#: Attributes a browser fetches from. An external URL in any of these breaks P3.
FETCHING_ATTRS = frozenset(
    {
        "src",
        "srcset",
        "imagesrcset",
        "data",
        "poster",
        "action",
        "formaction",
        "background",
        "codebase",
        "manifest",
        "ping",
        "archive",
        "profile",
        "lowsrc",
        "dynsrc",
        "xlink:href",
    }
)

#: The only elements whose ``href`` may point off-box: an upstream permalink a maintainer
#: clicks on purpose. Everything else fetches on load.
LINK_TAGS = frozenset({"a", "area"})

#: Elements that execute, navigate, embed or submit. None of them belongs in this report,
#: and each is what an escaping bug turns report text into. ``img`` is deliberately absent:
#: an inline ``data:`` image is allowed by the policy, and :func:`allowed_data_uri` is what
#: keeps it honest.
FORBIDDEN_TAGS = frozenset(
    {
        "iframe",
        "frame",
        "frameset",
        "object",
        "embed",
        "applet",
        "portal",
        "base",
        "form",
        "input",
        "select",
        "keygen",
        "link",
        "video",
        "audio",
        "source",
        "track",
        "marquee",
        "plaintext",
        "xmp",
        "isindex",
        "math",
        "animate",
        "foreignobject",
    }
)

#: Elements that belong in ``<head>``. One of them appearing after ``<body>`` means some
#: content broke out of wherever it was written.
HEAD_ONLY_TAGS = frozenset({"meta", "title", "base", "link", "head"})

EXTERNAL_PREFIXES = ("http://", "https://", "//", "ftp://", "ws://", "wss://", "file://")
DANGEROUS_SCHEMES = ("javascript:", "vbscript:", "livescript:", "mocha:", "data:")

#: ``data:`` is in :data:`DANGEROUS_SCHEMES` because nothing from *input* may ever use it.
#: The page builds two of its own, and only these two shapes are allowed:
#:
#: * an inline image, which the policy permits with ``img-src data:``;
#: * the "download the JSON" link, which is a save rather than a navigation because of the
#:   ``download`` attribute -- and whose media type must be one a browser will not render
#:   as markup even if someone opens it directly.
INERT_MEDIA_TYPES = (
    "data:application/json,",
    "data:application/json;",
    "data:text/plain,",
    "data:text/plain;",
    "data:text/markdown,",
    "data:text/csv,",
    "data:application/octet-stream,",
    "data:application/octet-stream;",
)

#: Elements whose content is raw text or RCDATA: a payload that closed one of them early
#: would put the rest of itself into the document as markup.
RAW_TEXT_TAGS = ("script", "style", "textarea", "title", "noscript", "template", "xmp")

#: A browser ignores whitespace and control characters when it reads a URL's scheme.
_SQUASH = re.compile(r"[\s\x00-\x20]+")
_CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]{0,2048})")
_ATTR_NAME = re.compile(r"\A[A-Za-z][A-Za-z0-9:._-]{0,60}\Z")


def squash(value: str) -> str:
    """A URL as a browser reads it: no whitespace, no controls, lowercased."""
    return _SQUASH.sub("", value).lower()


def allowed_data_uri(tag: str, name: str, value: str, element: dict[str, str]) -> bool:
    """Whether this one ``data:`` URI is one of the two the page is allowed to build."""
    squashed = squash(value)
    if tag == "img" and name == "src":
        return squashed.startswith("data:image/")
    if tag in LINK_TAGS and name == "href":
        # A save, not a navigation, and of something no browser will parse as markup.
        return "download" in element and squashed.startswith(INERT_MEDIA_TYPES)
    return False


def bad_urls(document: Document) -> list[tuple[str, str, str]]:
    """Every attribute value that would fetch, navigate or execute something it must not."""
    offenders: list[tuple[str, str, str]] = []
    for tag, element in document.elements:
        for name, value in element.items():
            squashed = squash(value)
            if squashed.startswith(DANGEROUS_SCHEMES) and not allowed_data_uri(
                tag, name, value, element
            ):
                offenders.append((tag, name, value))
            fetching = name in FETCHING_ATTRS or (name == "href" and tag not in LINK_TAGS)
            if fetching and squashed.startswith(EXTERNAL_PREFIXES):
                offenders.append((tag, name, value))
    return offenders


# --- the parsed document -------------------------------------------------------------------


class Document(HTMLParser):
    """A parsed rendering: elements, attributes, script and style text, comments.

    ``convert_charrefs`` is on, so attribute values and character data arrive *decoded* --
    which is exactly right for these tests. An escaped payload comes back as its original
    text but as one inert value; an escaping bug comes back as extra elements and extra
    attributes. The difference is what every assertion below is looking at.
    """

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.html = html
        self.tags: list[str] = []
        #: Each start tag as ``(name, {attribute: value})``.
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.attributes: list[tuple[str, str, str]] = []
        self.scripts: list[str] = []
        self.styles: list[str] = []
        self.comments: list[str] = []
        self.declarations: list[str] = []
        self.instructions: list[str] = []
        self.texts: list[str] = []
        #: Elements that turned up after ``<body>`` started.
        self.in_body: list[str] = []
        self._cdata: str | None = None
        self._body = False
        self.feed(html)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.elements.append((tag, {name: value or "" for name, value in attrs}))
        for name, value in attrs:
            self.attributes.append((tag, name, value or ""))
        if self._body:
            self.in_body.append(tag)
        if tag == "body":
            self._body = True
        if tag in {"script", "style"}:
            self._cdata = tag

    def handle_endtag(self, tag: str) -> None:
        if tag == self._cdata:
            self._cdata = None

    def handle_data(self, data: str) -> None:
        if self._cdata == "script":
            self.scripts.append(data)
        elif self._cdata == "style":
            self.styles.append(data)
        else:
            self.texts.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)

    def handle_decl(self, decl: str) -> None:
        self.declarations.append(decl)

    def handle_pi(self, data: str) -> None:
        self.instructions.append(data)

    def unknown_decl(self, data: str) -> None:
        self.declarations.append(data)

    # --- views a test wants ----------------------------------------------------------------

    @property
    def script(self) -> str:
        """The one script element's text."""
        assert len(self.scripts) == 1, f"expected one script element, found {len(self.scripts)}"
        return self.scripts[0]

    @property
    def css(self) -> str:
        return "".join(self.styles)

    @property
    def text(self) -> str:
        return "".join(self.texts)

    def meta(self, key: str, value: str) -> dict[str, str]:
        """The attributes of the ``<meta>`` whose ``key`` attribute equals ``value``."""
        matches = [
            attrs
            for tag, attrs in self.elements
            if tag == "meta" and attrs.get(key, "").lower() == value.lower()
        ]
        assert matches, f"no <meta {key}={value!r}> in the document"
        assert len(matches) == 1, f"{len(matches)} <meta {key}={value!r}> elements"
        return matches[0]


def csp_of(document: Document) -> str:
    policy = document.meta("http-equiv", "Content-Security-Policy").get("content", "")
    assert policy, "the document has no Content-Security-Policy"
    return policy


# --- the fixtures ----------------------------------------------------------------------------


def hostile_span(body: str) -> Span:
    return Span(start=0, end=min(len(body), 24), text=body[: min(len(body), 24)])


def hostile_claims(span: Span) -> tuple[ClaimBase, ...]:
    """One claim of every kind, with every free-text field poisoned."""
    common: dict[str, Any] = {
        "spans": (span,),
        "extractor": HOSTILE,
        "confidence": 1.0,
        "role": "core",
        "provenance": "project_attributed",
    }
    return (
        VersionClaim(id="c01", raw=HOSTILE, product=HOSTILE, relation="tested_on", **common),
        SymbolClaim(id="c02", name=HOSTILE, context_path=HOSTILE, lang_hint="c", **common),
        FileClaim(id="c03", path=HOSTILE, **common),
        LineClaim(id="c04", path=HOSTILE, line=1, quoted_line=HOSTILE, **common),
        TraceClaim(
            id="c05",
            format="asan",
            bug_type=HOSTILE,
            message=HOSTILE,
            summary=HOSTILE,
            summary_path=HOSTILE,
            summary_function=HOSTILE,
            frames=(
                Frame(index=0, function=HOSTILE, path=HOSTILE, line=1, raw=HOSTILE),
                Frame(index=1, function=HOSTILE, path=HOSTILE, module=HOSTILE, raw=HOSTILE),
            ),
            **common,
        ),
        SnippetClaim(
            id="c06",
            code=HOSTILE,
            attributed_path=HOSTILE,
            attributed_function=HOSTILE,
            n_lines=1,
            **common,
        ),
        PatchClaim(
            id="c07",
            diff=f"--- a/{HOSTILE}\n+++ b/{HOSTILE}\n",
            files=(HOSTILE,),
            hunks=(
                PatchHunk(
                    path=HOSTILE,
                    source_start=1,
                    source_length=1,
                    target_start=1,
                    target_length=2,
                    section_header=HOSTILE,
                    lines=(PatchLine(op="+", text=HOSTILE), PatchLine(op="-", text=HOSTILE)),
                ),
            ),
            **common,
        ),
        PocClaim(id="c08", poc_kind="python", content=HOSTILE, entry=HOSTILE, **common),
        ReferenceClaim(
            id="c09", ref_kind="url", value=HOSTILE, repo_url="javascript:alert(1)", **common
        ),
        OptionClaim(id="c10", token=HOSTILE, option_kind="cli_flag", **common),
        ImpactClaim(id="c11", cvss_vector=HOSTILE, severity_word=HOSTILE, cwe=HOSTILE, **common),
        BehaviorClaim(
            id="c12",
            subject_symbol=HOSTILE,
            predicate="missing_bounds_check",
            object=HOSTILE,
            **common,
        ),
    )


def hostile_location(index: int) -> CodeLocation:
    return CodeLocation(
        repo=HOSTILE,
        ref=HOSTILE,
        commit="javascript:alert(1)",
        path=f"src/{HOSTILE}",
        start_line=index + 1,
        end_line=index + 3,
        excerpt=f"{HOSTILE}\n\t{HOSTILE}\n{HOSTILE}",
        permalink="javascript:alert(document.domain)",
    )


def hostile_evidence() -> tuple[Evidence, ...]:
    outcomes = ("REFUTES", "SUPPORTS", "NEUTRAL", "ERROR")
    groups = ("locus", "lines", "code_quotes", "trace", "version", "patch", "meta", "info")
    return tuple(
        Evidence(
            id=f"e{index:02d}",
            check_id=HOSTILE,
            claim_ids=(f"c{index + 1:02d}",),
            outcome=outcomes[index % len(outcomes)],  # type: ignore[arg-type]
            strength=-3.0 + index,
            group=groups[index % len(groups)],
            summary=HOSTILE,
            details={
                HOSTILE: HOSTILE,
                "nested": {"list": [HOSTILE, 1, None], "url": "javascript:alert(1)"},
                "count": index,
            },
            locations=(hostile_location(index),),
            commands=(
                CommandRecord(
                    argv=("git", "--no-pager", HOSTILE),
                    exit_code=1,
                    stdout_sha256="0" * 64,
                    stderr_sha256="1" * 64,
                    duration_ms=12,
                ),
            ),
        )
        for index in range(12)
    )


def hostile_result() -> Result:
    report = ingest_string(f"# {HOSTILE}\n\n{HOSTILE}\n", input_format="text")
    span = hostile_span(report.body)
    return Result(
        tool_version=HOSTILE,
        report=report,
        claims=hostile_claims(span),  # type: ignore[arg-type]
        target=ResolvedTarget(
            repo_url=HOSTILE,
            ref_name=HOSTILE,
            commit=HOSTILE,
            method=HOSTILE,
            confidence="low",
            alternatives=(HOSTILE, HOSTILE),
            warnings=(HOSTILE,),
        ),
        evidence=hostile_evidence(),
        verdict=Verdict(
            label="MIXED",
            score=37,
            confidence="low",
            key_evidence=("e00", "e01"),
            questions=(
                Question(text=HOSTILE, rationale=HOSTILE, evidence_ids=("e00",)),
                Question(text=HOSTILE, rationale=HOSTILE),
            ),
            notes=(HOSTILE, HOSTILE),
            rule=HOSTILE,
        ),
        timings={"xyzzy_timing_probe": 98765.4321},
        environment=Environment(
            mode="online",
            sandbox_engine=HOSTILE,
            llm=HOSTILE,
            fetched_urls=("https://fetched.example/report", HOSTILE),
        ),
    )


def benign_result() -> Result:
    """A report with a real upstream permalink, to prove external links are *kept*."""
    report = ingest_string("hdr_get reads past the end of the buffer.\n", input_format="text")
    span = report.span(0, 7)
    claim = SymbolClaim(
        id="c1", spans=(span,), extractor="test", confidence=1.0, role="core", name="hdr_get"
    )
    location = CodeLocation(
        repo="https://github.invalid/example/libhdr",
        ref="v1.2.0",
        commit="0123456789abcdef0123456789abcdef01234567",
        path="src/hdr.c",
        start_line=400,
        end_line=402,
        excerpt="    memcpy(dst, src, n);",
        permalink="https://github.invalid/example/libhdr/blob/v1.2.0/src/hdr.c#L400",
    )
    return Result(
        tool_version="0.0.0-test",
        report=report,
        claims=(claim,),
        target=ResolvedTarget(
            repo_url="https://github.invalid/example/libhdr",
            ref_name="v1.2.0",
            commit="0123456789abcdef0123456789abcdef01234567",
            method="declared version",
            confidence="high",
        ),
        evidence=(
            Evidence(
                id="e1",
                check_id="C03",
                claim_ids=("c1",),
                outcome="SUPPORTS",
                strength=2.0,
                group="locus",
                summary="hdr_get is defined at src/hdr.c:400",
                locations=(location,),
            ),
        ),
        verdict=Verdict(label="GROUNDED", score=88, confidence="high", rule="1a"),
    )


def large_result(count: int = 300) -> Result:
    """SPEC §15.2's size budget, exercised with a realistically large report."""
    report = ingest_string("a long report paragraph.\n" * 60, input_format="text")
    span = report.span(0, 24)
    excerpt = "\n".join(
        f"    if (offset + {line} > cap) return HDR_ERR_RANGE; /* bounds */" for line in range(12)
    )
    claims = tuple(
        SymbolClaim(
            id=f"c{index:04d}",
            spans=(span,),
            extractor="test",
            confidence=1.0,
            role="supporting",
            name=f"hdr_decode_chunked_value_{index}",
        )
        for index in range(count)
    )
    evidence = tuple(
        Evidence(
            id=f"e{index:04d}",
            check_id="C03",
            claim_ids=(f"c{index:04d}",),
            outcome="REFUTES",
            strength=-2.0,
            group="locus",
            summary=(
                f"hdr_decode_chunked_value_{index} is not defined in any release "
                f"between v1.0.0 and v1.3.0"
            ),
            details={"symbol": f"hdr_decode_chunked_value_{index}", "releases_searched": 14},
            locations=(
                CodeLocation(
                    repo="https://github.invalid/example/libhdr",
                    ref="v1.2.0",
                    commit="0123456789abcdef0123456789abcdef01234567",
                    path=f"src/hdr_{index}.c",
                    start_line=100,
                    end_line=112,
                    excerpt=excerpt,
                ),
            ),
        )
        for index in range(count)
    )
    return Result(
        tool_version="0.0.0-test",
        report=report,
        claims=claims,
        evidence=evidence,
        target=ResolvedTarget(
            repo_url="https://github.invalid/example/libhdr",
            ref_name="v1.2.0",
            commit="0123456789abcdef0123456789abcdef01234567",
            method="declared version",
            confidence="high",
        ),
        verdict=Verdict(label="UNGROUNDED", score=4, confidence="high", rule="3a"),
    )


@pytest.fixture(scope="module")
def hostile_html() -> str:
    return render_html_result(hostile_result(), source=HOSTILE, tool_version=HOSTILE)


@pytest.fixture(scope="module")
def hostile_document(hostile_html: str) -> Document:
    return Document(hostile_html)


@pytest.fixture(scope="module")
def benign_html() -> str:
    return render_html_result(benign_result(), source="report.md")


@pytest.fixture(scope="module")
def benign_document(benign_html: str) -> Document:
    return Document(benign_html)


# --- 1. the CSP hash is the hash of what was served -------------------------------------------


def test_the_csp_hash_is_recomputed_from_the_served_script(hostile_document: Document) -> None:
    """Derived from the document, never from the constants.

    This is the test that catches a component sneaking JavaScript into the page: the hash
    is taken from the ``<script>`` element as parsed out of the rendered HTML and compared
    with the one the policy names. Comparing
    :data:`~nikasha.render.html.page.BASE_JS` against ``script_hash(BASE_JS)`` would agree
    with itself no matter what the page contained.
    """
    served = hostile_document.script
    digest = hashlib.sha256(served.encode("utf-8")).digest()
    expected = "sha256-" + base64.b64encode(digest).decode("ascii")
    assert f"script-src '{expected}'" in csp_of(hostile_document), (
        "the policy pins a different script than the one the page serves"
    )


def test_the_policy_blocks_every_fetch(hostile_document: Document) -> None:
    policy = csp_of(hostile_document)
    assert policy.startswith("default-src 'none'")
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy
    for hatch in ("'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'"):
        assert hatch not in policy.split("script-src")[1]


def test_there_is_no_meta_refresh(hostile_document: Document) -> None:
    equivs = {
        value.lower() for _, name, value in hostile_document.attributes if name == "http-equiv"
    }
    assert "refresh" not in equivs


# --- 2. nothing is fetched ---------------------------------------------------------------------


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_no_element_fetches_anything_off_the_machine(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    document = hostile_document if which == "hostile" else benign_document
    offenders = [
        (tag, name, value)
        for tag, name, value in document.attributes
        if (name in FETCHING_ATTRS or (name == "href" and tag not in LINK_TAGS))
        and squash(value).startswith(EXTERNAL_PREFIXES)
    ]
    assert offenders == [], offenders


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_every_data_uri_is_one_the_page_built_itself(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    """The page makes its own ``data:`` URIs; it never trusts one from the report.

    Two shapes are legitimate: an inline image (``img-src data:`` allows it) and the JSON
    download, which is a save rather than a navigation and whose media type is one no
    browser parses as markup. A ``data:text/html`` or ``data:image/svg+xml`` in an
    ``href`` would be script execution with a different spelling.
    """
    document = hostile_document if which == "hostile" else benign_document
    found = 0
    for tag, element in document.elements:
        for name, value in element.items():
            if not squash(value).startswith("data:"):
                continue
            found += 1
            assert allowed_data_uri(tag, name, value, element), (tag, name, value[:120])
    if which == "benign":
        assert found, "the JSON download link is gone"


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_there_is_no_link_element_pulling_in_a_stylesheet_or_a_preload(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    document = hostile_document if which == "hostile" else benign_document
    links = [(tag, name, value) for tag, name, value in document.attributes if tag == "link"]
    assert links == [], links
    assert "link" not in document.tags


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_the_stylesheet_imports_and_fetches_nothing(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    css = (hostile_document if which == "hostile" else benign_document).css
    assert "@import" not in css.lower()
    assert "expression(" not in css.lower()
    assert "-moz-binding" not in css.lower()
    assert "@font-face" not in css.lower()
    for target in _CSS_URL.findall(css):
        # `img-src data:` is the only fetch the policy allows, so inline data URIs are the
        # only thing a `url()` may name.
        assert squash(target).startswith("data:"), f"CSS fetches {target!r}"


def test_the_script_fetches_nothing(hostile_document: Document) -> None:
    script = hostile_document.script.lower()
    for forbidden in ("fetch(", "xmlhttprequest", "importscripts", "navigator.sendbeacon"):
        assert forbidden not in script
    assert "http://" not in script
    assert "https://" not in script


def test_upstream_permalinks_are_the_one_allowed_external_url(benign_document: Document) -> None:
    """The distinction, not a blanket ban.

    A maintainer has to be able to click through to the line the evidence cites, so an
    external ``https://`` in the ``href`` of a plain ``<a>`` is correct and is asserted to
    still be there. The same URL in a ``src=`` would fetch on load and is banned above.
    """
    external = [
        (tag, value)
        for tag, name, value in benign_document.attributes
        if name == "href" and squash(value).startswith(("http://", "https://"))
    ]
    assert external, "the report dropped every upstream permalink"
    assert {tag for tag, _ in external} <= LINK_TAGS
    for _, value in external:
        assert "github.invalid/example/libhdr" in value


def test_external_links_do_not_leak_the_referrer(benign_document: Document) -> None:
    referrers = {
        value.lower()
        for _, name, value in benign_document.attributes
        if name in {"rel", "content"} and "referrer" in value.lower()
    }
    assert any("no-referrer" in value for value in referrers)


# --- 3. nothing executes -----------------------------------------------------------------------


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_no_inline_event_handler_anywhere(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    document = hostile_document if which == "hostile" else benign_document
    handlers = [
        (tag, name)
        for tag, name, _ in document.attributes
        if re.fullmatch(r"on[a-z]+", name, re.IGNORECASE)
    ]
    assert handlers == [], handlers


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_exactly_one_script_element(
    which: str, hostile_html: str, benign_html: str, hostile_document: Document
) -> None:
    html = hostile_html if which == "hostile" else benign_html
    document = Document(html)
    assert len(document.scripts) == 1
    assert document.tags.count("script") == 1
    # Counted in the raw text too: an escaped payload cannot inflate either count.
    assert len(re.findall(r"<\s*script", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*/\s*script", html, re.IGNORECASE)) == 1


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_exactly_one_style_element(which: str, hostile_html: str, benign_html: str) -> None:
    html = hostile_html if which == "hostile" else benign_html
    assert len(re.findall(r"<\s*style", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*/\s*style", html, re.IGNORECASE)) == 1


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_no_attribute_carries_a_dangerous_scheme(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    document = hostile_document if which == "hostile" else benign_document
    assert bad_urls(document) == []


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_no_element_that_executes_navigates_or_embeds(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    document = hostile_document if which == "hostile" else benign_document
    assert FORBIDDEN_TAGS.isdisjoint(document.tags), sorted(
        FORBIDDEN_TAGS.intersection(document.tags)
    )


def test_style_attributes_carry_nothing_derived_from_input(hostile_document: Document) -> None:
    for _, name, value in hostile_document.attributes:
        if name != "style":
            continue
        lowered = value.lower()
        for forbidden in ("url(", "expression(", "javascript:", "@import", "</", "/*"):
            assert forbidden not in lowered, value
        for payload in PAYLOADS:
            assert payload not in value


# --- 4. XSS through every input surface ----------------------------------------------------------


def test_the_fixture_actually_reaches_the_page(hostile_document: Document) -> None:
    """A guard on the tests below, not on the renderer.

    If no component ever rendered a poisoned field, every assertion in this section would
    pass vacuously. So: at least one payload has to come back out as character data.
    """
    data = hostile_document.text
    assert any(payload in data for payload in PAYLOADS[:7]), (
        "no hostile field reached the document; the fixture no longer exercises anything"
    )


def test_hostile_input_never_becomes_an_element(hostile_document: Document) -> None:
    """Every payload comes back as text, not as markup.

    The parser is the referee. ``&lt;img src=x onerror=alert(1)&gt;`` contains the literal
    substring ``onerror=alert(1)`` and is perfectly inert, so a substring search would be
    both wrong and alarming; what matters is that no ``img`` element and no ``onerror``
    attribute exist.
    """
    # `"><img src=x onerror=alert(1)>` would leave these fingerprints behind.
    assert "x" not in {value for _, name, value in hostile_document.attributes if name == "src"}
    assert "alert(1)" not in {value for _, _, value in hostile_document.attributes}
    assert "onload" not in {name for _, name, _ in hostile_document.attributes}
    assert "onerror" not in {name for _, name, _ in hostile_document.attributes}
    # `</textarea></title></noscript></template>` would leave these.
    assert "noscript" not in hostile_document.tags
    assert "template" not in hostile_document.tags


@pytest.mark.parametrize("which", ["hostile", "benign"])
def test_no_head_element_turns_up_in_the_body(
    which: str, hostile_document: Document, benign_document: Document
) -> None:
    """A ``<meta>`` or a ``<title>`` after ``<body>`` means something broke out."""
    document = hostile_document if which == "hostile" else benign_document
    stray = sorted(HEAD_ONLY_TAGS.intersection(document.in_body))
    assert stray == [], stray


def test_no_raw_text_element_is_closed_early(hostile_html: str) -> None:
    """``</textarea>``, ``</title>``, ``</style>``, ``</script>`` in a payload change nothing.

    Each of these elements ends at its own close tag whatever is nested inside, so a
    payload that carried one would end it early and the rest of the payload would be
    parsed as markup. The page legitimately uses some of them -- the questions block puts
    its copyable text in a ``<textarea>`` -- so the invariant is that opens and closes
    still balance, not that the elements are absent.
    """
    for tag in RAW_TEXT_TAGS:
        opens = len(re.findall(rf"<\s*{tag}\b", hostile_html, re.IGNORECASE))
        closes = len(re.findall(rf"<\s*/\s*{tag}\s*>", hostile_html, re.IGNORECASE))
        assert opens == closes, f"{opens} <{tag}> against {closes} </{tag}>"


def test_no_payload_survives_inside_the_script_or_the_stylesheet(
    hostile_document: Document,
) -> None:
    for blob in (hostile_document.script, hostile_document.css):
        for payload in PAYLOADS:
            assert payload not in blob
        assert re.search(r"</\s*script", blob, re.IGNORECASE) is None
        assert re.search(r"</\s*style", blob, re.IGNORECASE) is None
        assert "<!--" not in blob
        assert "alert(" not in blob


def test_the_document_contains_no_html_comment(hostile_document: Document) -> None:
    # `<!--` ends a script element for the HTML tokenizer, and a comment is a place to
    # hide markup that a later editor un-hides.
    assert hostile_document.comments == []
    assert hostile_document.instructions == []
    assert hostile_document.declarations == ["doctype html"]


def test_every_attribute_name_is_well_formed(hostile_document: Document) -> None:
    """The generic breakout detector.

    Any value that escaped its quotes shows up as extra attributes with names made of
    whatever followed the quote. Checking the shape of every attribute name in the
    document catches that without knowing which component produced it.
    """
    malformed = [
        (tag, name) for tag, name, _ in hostile_document.attributes if not _ATTR_NAME.match(name)
    ]
    assert malformed == [], malformed


def test_the_meta_description_is_not_broken_out_of(hostile_document: Document) -> None:
    description = hostile_document.meta("name", "description")
    assert set(description) == {"name", "content"}
    assert description["name"] == "description"


def test_no_invisible_or_bidi_character_reaches_the_document(hostile_html: str) -> None:
    present = sorted({char for char in INVISIBLE if char in hostile_html})
    assert present == [], [hex(ord(char)) for char in present]


def test_the_document_title_survives_a_payload(hostile_document: Document) -> None:
    # `</title>` in a payload would end the title early and put the rest in the document.
    assert hostile_document.tags.count("head") == 1
    assert hostile_document.tags.count("body") == 1
    assert hostile_document.tags.count("html") == 1


# --- 5. determinism (P2) ---------------------------------------------------------------------


def test_the_same_result_renders_byte_identical_html() -> None:
    result = hostile_result()
    first = render_html_result(result, source=HOSTILE, tool_version=HOSTILE)
    second = render_html_result(result, source=HOSTILE, tool_version=HOSTILE)
    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")


def test_two_equal_results_render_identically() -> None:
    assert render_html_result(benign_result()) == render_html_result(benign_result())


def test_timings_never_reach_the_page(hostile_html: str) -> None:
    """``timings`` is the one field allowed to differ between two runs, so it is not shown.

    The page may *say* that timings were omitted -- that is what makes the omission
    honest -- but no key and no measurement may appear, including inside the embedded
    JSON download, where they would be percent-encoded.
    """
    assert "xyzzy_timing_probe" not in hostile_html
    assert "98765" not in hostile_html
    assert '"timings"' not in hostile_html
    assert "%22timings%22" not in hostile_html


# --- 6. size (SPEC §15.2) ---------------------------------------------------------------------


def test_a_large_report_stays_within_the_size_budget() -> None:
    html = render_html_result(large_result())
    size = len(html.encode("utf-8"))
    assert size < MAX_BYTES, f"{size} bytes for 300 claims and 300 excerpts, budget {MAX_BYTES}"


def test_a_large_report_is_still_one_script_and_one_style() -> None:
    html = render_html_result(large_result(count=50))
    assert len(re.findall(r"<\s*script", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*style", html, re.IGNORECASE)) == 1


# --- 7. a broken component does not break the page -----------------------------------------------


def test_a_component_that_raises_costs_only_its_own_view(monkeypatch: pytest.MonkeyPatch) -> None:
    """One view failing must not cost the report.

    A maintainer who cannot open the file learns nothing; one missing the version chart
    still gets the verdict. The page has to *say* a view failed, though -- a hole that
    looks like "there was nothing to show" is worse than an error.
    """
    modules = component_modules()
    assert modules, "no HTML components were discovered"
    _order, name, module = modules[0]

    def boom(_ctx: HtmlContext) -> Fragment:
        raise RuntimeError('<img src=x onerror=alert(1)> in the message "too"')

    monkeypatch.setattr(module, "render", boom)
    html = render_html_result(benign_result())
    document = Document(html)

    assert "could not be rendered" in html
    assert name in html
    # The exception message is input-adjacent too, so it is escaped like everything else.
    assert "img" not in document.tags
    assert not [n for _, n, _ in document.attributes if n.startswith("on")]
    # And the rest of the page is intact.
    assert len(document.scripts) == 1
    assert html.startswith("<!doctype html>")


def test_every_component_failing_still_produces_a_page(monkeypatch: pytest.MonkeyPatch) -> None:
    for _order, _name, module in component_modules():

        def boom(_ctx: HtmlContext, _module: object = module) -> Fragment:
            raise ValueError("boom")

        monkeypatch.setattr(module, "render", boom)
    html = render_html_result(benign_result())
    assert html.startswith("<!doctype html>")
    assert "could not be rendered" in html
    assert len(Document(html).scripts) == 1


# --- 8. the contract every component must keep ----------------------------------------------------

#: Built once: every discovered component is exercised against the same hostile context.
COMPONENTS = component_modules()


def render_component(module: object, ctx: HtmlContext) -> Fragment | None:
    fragment: Fragment | None = module.render(ctx)  # type: ignore[attr-defined]
    return fragment


@pytest.fixture(scope="module")
def hostile_ctx() -> HtmlContext:
    result = hostile_result()
    return HtmlContext(result=result, source=HOSTILE, tool_version=HOSTILE)


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_declares_an_order(name: str) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    assert isinstance(getattr(module, "ORDER", None), int), f"{name} has no integer ORDER"


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_emits_no_script_and_no_handler_on_hostile_input(
    name: str, hostile_ctx: HtmlContext
) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    fragment = render_component(module, hostile_ctx)
    if fragment is None:
        return
    assert isinstance(fragment, Fragment)
    assert re.search(r"<\s*script", fragment.html, re.IGNORECASE) is None
    document = Document(f"<div>{fragment.html}</div>")
    handlers = [
        (tag, attr_name)
        for tag, attr_name, _ in document.attributes
        if re.fullmatch(r"on[a-z]+", attr_name, re.IGNORECASE)
    ]
    assert handlers == [], handlers
    malformed = [
        (tag, attr_name)
        for tag, attr_name, _ in document.attributes
        if not _ATTR_NAME.match(attr_name)
    ]
    assert malformed == [], malformed
    assert bad_urls(document) == []


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_js_cannot_close_the_script_element(name: str, hostile_ctx: HtmlContext) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    fragment = render_component(module, hostile_ctx)
    if fragment is None or not fragment.js:
        return
    assert re.search(r"</\s*script", fragment.js, re.IGNORECASE) is None
    assert "<!--" not in fragment.js
    assert "]]>" not in fragment.js


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_css_cannot_close_the_style_element_or_fetch(
    name: str, hostile_ctx: HtmlContext
) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    fragment = render_component(module, hostile_ctx)
    if fragment is None or not fragment.css:
        return
    css = fragment.css
    assert re.search(r"</\s*style", css, re.IGNORECASE) is None
    assert "@import" not in css.lower()
    assert "expression(" not in css.lower()
    assert "@font-face" not in css.lower()
    for target in _CSS_URL.findall(css):
        assert squash(target).startswith("data:"), f"{name} CSS fetches {target!r}"


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_leaks_no_invisible_character(name: str, hostile_ctx: HtmlContext) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    fragment = render_component(module, hostile_ctx)
    if fragment is None:
        return
    blob = fragment.html + fragment.css + fragment.js
    present = sorted({char for char in INVISIBLE if char in blob})
    assert present == [], [hex(ord(char)) for char in present]


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_is_deterministic(name: str, hostile_ctx: HtmlContext) -> None:
    module = next(m for _o, n, m in COMPONENTS if n == name)
    first = render_component(module, hostile_ctx)
    second = render_component(module, HtmlContext(result=hostile_result(), source=HOSTILE))
    assert (first is None) == (second is None)
    if first is not None and second is not None:
        assert first == second


@pytest.mark.parametrize("name", [name for _order, name, _module in COMPONENTS])
def test_component_degrades_on_an_empty_result(name: str) -> None:
    """``None`` or a fragment, never an exception, for a report with nothing in it."""
    empty = Result(tool_version="0.0.0-test", report=ingest_string("", input_format="text"))
    fragment = render_component(next(m for _o, n, m in COMPONENTS if n == name), HtmlContext(empty))
    assert fragment is None or isinstance(fragment, Fragment)
