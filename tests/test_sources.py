from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sources import normalize_kev_item


def test_normalize_kev_item_maps_expected_fields() -> None:
    raw = {
        "cveID": "CVE-2026-1234",
        "vendorProject": "Acme",
        "product": "Widget",
        "dateAdded": "2026-04-01",
        "shortDescription": "Actively exploited vulnerability.",
        "knownRansomwareCampaignUse": "Known",
    }

    normalized = normalize_kev_item(raw)

    assert normalized["cve_id"] == "CVE-2026-1234"
    assert normalized["vendor"] == "Acme"
    assert normalized["product"] == "Widget"
    assert normalized["date_added"] == "2026-04-01"
    assert normalized["summary"] == "Actively exploited vulnerability."
    assert normalized["known_ransomware"] == "Known"


def test_normalize_kev_item_fills_defaults() -> None:
    normalized = normalize_kev_item({"cveID": "CVE-2026-0001"})

    assert normalized["vendor"] == "Unknown"
    assert normalized["product"] == "Unknown"
    assert normalized["summary"] == "No description"
