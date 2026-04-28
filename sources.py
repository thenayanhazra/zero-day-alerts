"""Source fetchers for the simplified project."""
from __future__ import annotations

from typing import Any

import requests

from config import Config


def normalize_kev_item(item: dict[str, Any]) -> dict[str, str]:
    """Map a raw KEV item to a compact, stable shape."""
    return {
        "cve_id": item.get("cveID", ""),
        "vendor": item.get("vendorProject", "Unknown"),
        "product": item.get("product", "Unknown"),
        "date_added": item.get("dateAdded", ""),
        "summary": item.get("shortDescription", "No description"),
        "known_ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
    }


def fetch_kev(config: Config) -> list[dict[str, str]]:
    """Fetch and normalize CISA KEV records."""
    response = requests.get(config.kev_url, timeout=config.timeout_seconds)
    response.raise_for_status()
    payload = response.json()
    records = payload.get("vulnerabilities", [])
    return [normalize_kev_item(item) for item in records if item.get("cveID")]
