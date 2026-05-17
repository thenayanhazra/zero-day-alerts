from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

import requests


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str
    required_action: str


def fetch_catalog(url: str, timeout_seconds: int) -> dict[str, Any]:
    response = requests.get(url, timeout=timeout_seconds)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        raise ValueError(f"KEV catalog returned invalid JSON: {exc}") from exc


def parse_records(catalog: dict[str, Any]) -> list[KevRecord]:
    records: list[KevRecord] = []
    for item in catalog.get("vulnerabilities", []):
        try:
            records.append(KevRecord(
                cve_id=item.get("cveID", ""),
                vendor_project=item.get("vendorProject", ""),
                product=item.get("product", ""),
                vulnerability_name=item.get("vulnerabilityName", ""),
                date_added=date.fromisoformat(item["dateAdded"]),
                short_description=item.get("shortDescription", ""),
                required_action=item.get("requiredAction", ""),
            ))
        except (KeyError, ValueError):
            pass
    return records


def recent_records(records: list[KevRecord], days: int, today: date | None = None) -> list[KevRecord]:
    cutoff = (today or date.today()) - timedelta(days=days)
    return [record for record in records if record.date_added >= cutoff]
