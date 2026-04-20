from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sources


def test_merge_entries_prefers_valid_published_when_current_invalid() -> None:
    merged = sources.merge_entries(
        [
            {
                "cve_id": "CVE-2026-0001",
                "severity": "HIGH",
                "summary": "first",
                "published": "not-a-date",
                "source": "A",
                "references": [],
                "affected": "Unknown",
                "cvss_score": None,
                "kev": False,
            },
            {
                "cve_id": "CVE-2026-0001",
                "severity": "MEDIUM",
                "summary": "second",
                "published": "2026-01-10T00:00:00+00:00",
                "source": "B",
                "references": [],
                "affected": "Unknown",
                "cvss_score": None,
                "kev": False,
            },
        ]
    )

    assert merged[0]["published"] == "2026-01-10T00:00:00+00:00"


def test_fetch_all_continues_when_one_source_raises(monkeypatch) -> None:
    config = SimpleNamespace(
        enable_nvd=True,
        enable_cisa_kev=True,
        enable_github_advisories=False,
    )

    def broken_fetcher(_config, _storage):
        raise RuntimeError("boom")

    def cisa_fetcher(_config, _storage):
        return [
            {
                "cve_id": "CVE-2026-9999",
                "severity": "CRITICAL",
                "summary": "from cisa",
                "published": "2026-03-01T00:00:00+00:00",
                "source": "CISA-KEV",
                "references": ["https://example.com"],
                "affected": "vendor/product",
                "cvss_score": None,
                "kev": True,
            }
        ]

    monkeypatch.setattr(sources, "fetch_nvd", broken_fetcher)
    monkeypatch.setattr(sources, "fetch_cisa_kev", cisa_fetcher)

    merged = sources.fetch_all(config, storage=SimpleNamespace())

    assert len(merged) == 1
    assert merged[0]["cve_id"] == "CVE-2026-9999"
