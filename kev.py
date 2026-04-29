from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
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
    return response.json()


def parse_records(catalog: dict[str, Any]) -> list[KevRecord]:
    records: list[KevRecord] = []
    for item in catalog.get("vulnerabilities", []):
        records.append(
            KevRecord(
                cve_id=item.get("cveID", ""),
                vendor_project=item.get("vendorProject", ""),
                product=item.get("product", ""),
                vulnerability_name=item.get("vulnerabilityName", ""),
                date_added=datetime.strptime(item["dateAdded"], "%Y-%m-%d").date(),
                short_description=item.get("shortDescription", ""),
                required_action=item.get("requiredAction", ""),
            )
        )
    return records


def recent_records(records: list[KevRecord], days: int) -> list[KevRecord]:
    cutoff = date.today() - timedelta(days=days)
    return [record for record in records if record.date_added >= cutoff]
