# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The HackerOne corpus fetcher (ADR 0011), with a stubbed transport: no socket is opened."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nikasha.bench.h1corpus import (
    MIN_DELAY_S,
    CorpusError,
    fetch_corpus,
    load_cached,
    purge,
    report_id_from_url,
    report_markdown,
)
from nikasha.bench.manifests import load_manifests
from nikasha.bench.runner import collect_cases
from nikasha.errors import NikashaError

ROOT = Path(__file__).resolve().parents[3]


def _payload(rid: str, *, disclosed: bool = True, body: str = "Overflow in lib/x.c") -> bytes:
    return json.dumps(
        {
            "id": int(rid),
            "title": "A  title\nhere",
            "disclosed_at": "2024-01-01T00:00:00Z" if disclosed else None,
            "public": disclosed,
            "vulnerability_information": body,
            "reporter": {"username": "someone"},
        }
    ).encode()


def _never(url: str) -> bytes:
    raise AssertionError("no request expected")


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_refuses_without_online(tmp_path: Path) -> None:
    def boom(url: str) -> bytes:
        raise AssertionError("no request may be made offline")

    with pytest.raises(NikashaError, match="--online"):
        fetch_corpus(["1"], tmp_path, online=False, transport=boom)
    assert not any(tmp_path.iterdir())


def test_refuses_a_delay_below_the_minimum(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="minimum"):
        fetch_corpus(["1"], tmp_path, online=True, delay=MIN_DELAY_S / 2, transport=_never)


def test_rate_limited_sequential_and_resumable(tmp_path: Path) -> None:
    clock = _Clock()
    urls: list[str] = []

    def transport(url: str) -> bytes:
        urls.append(url)
        return _payload(url.rsplit("/", 1)[1].removesuffix(".json"))

    summary = fetch_corpus(
        ["30", "2", "100"],
        tmp_path,
        online=True,
        transport=transport,
        sleep=clock.sleep,
        clock=clock.time,
    )
    assert summary.fetched == ["2", "30", "100"]
    assert urls == [f"https://hackerone.com/reports/{i}.json" for i in ("2", "30", "100")]
    assert clock.sleeps == [MIN_DELAY_S, MIN_DELAY_S]
    again = fetch_corpus(["2", "30"], tmp_path, online=True, transport=transport)
    assert again.cached == ["2", "30"]
    assert len(urls) == 3


def test_only_title_and_body_are_cached(tmp_path: Path) -> None:
    fetch_corpus(["7"], tmp_path, online=True, transport=lambda u: _payload("7"))
    text = load_cached(tmp_path, "7")
    assert text == "# A title here\n\nOverflow in lib/x.c\n"
    assert "someone" not in text


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (_payload("5", disclosed=False), "publicly disclosed"),
        (_payload("6"), "publicly disclosed"),  # id mismatch
        (_payload("5", body="   "), "publicly disclosed"),
        (b"<html>", "not JSON"),
    ],
)
def test_drops_what_is_not_a_public_report(tmp_path: Path, raw: bytes, reason: str) -> None:
    summary = fetch_corpus(["5"], tmp_path, online=True, transport=lambda u: raw)
    assert reason in summary.dropped["5"]
    assert load_cached(tmp_path, "5") is None


def test_a_failed_request_is_recorded_not_fatal(tmp_path: Path) -> None:
    def transport(url: str) -> bytes:
        if "/1.json" in url:
            raise NikashaError("HTTP 404")
        return _payload("2")

    summary = fetch_corpus(["1", "2"], tmp_path, online=True, transport=transport)
    assert summary.dropped == {"1": "fetch failed: NikashaError"}
    assert summary.fetched == ["2"]


@pytest.mark.parametrize("bad", ["0", "-1", "1/../x", "12a", ""])
def test_bad_ids_are_refused(tmp_path: Path, bad: str) -> None:
    with pytest.raises(CorpusError):
        fetch_corpus([bad], tmp_path, online=True, transport=_never)


def test_url_parsing() -> None:
    assert report_id_from_url("https://hackerone.com/reports/547630") == "547630"
    assert report_id_from_url("https://hackerone.com/reports/547630.json") is None
    assert report_id_from_url("https://evil.example/reports/1") is None


def test_report_markdown_rejects_non_mappings() -> None:
    assert report_markdown([], "1") is None


def test_purge_removes_cached_reports(tmp_path: Path) -> None:
    fetch_corpus(["8"], tmp_path, online=True, transport=lambda u: _payload("8"))
    (tmp_path / "keep.txt").write_text("x", encoding="utf-8")
    assert purge(tmp_path) == 1
    assert load_cached(tmp_path, "8") is None
    assert (tmp_path / "keep.txt").exists()


def test_collect_cases_reads_the_cache(tmp_path: Path) -> None:
    manifests = load_manifests(ROOT / "bench" / "manifests")
    _, skipped_offline = collect_cases(manifests, ROOT)
    target = next(i for i in skipped_offline if i.startswith("h1-"))
    rid = target.removeprefix("h1-")
    fetch_corpus([rid], tmp_path, online=True, transport=lambda u: _payload(rid))
    cases, skipped = collect_cases(manifests, ROOT, h1_cache=tmp_path)
    assert target not in skipped
    assert len(skipped) == len(skipped_offline) - 1
    assert any(c.id == target for c in cases)
