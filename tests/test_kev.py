from datetime import date

from kev import parse_records, recent_records


def test_parse_records_maps_expected_fields() -> None:
    catalog = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Example",
                "product": "Gateway",
                "vulnerabilityName": "Sample vuln",
                "dateAdded": "2026-04-20",
                "shortDescription": "desc",
                "requiredAction": "Patch now",
            }
        ]
    }
    records = parse_records(catalog)

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-0001"
    assert records[0].date_added == date(2026, 4, 20)


def test_recent_records_filters_by_cutoff() -> None:
    catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-OLD", "dateAdded": "2024-01-01"},
            {"cveID": "CVE-NEW", "dateAdded": "2099-01-01"},
        ]
    }
    records = parse_records(catalog)
    filtered = recent_records(records, days=30)
    cves = {record.cve_id for record in filtered}
    assert "CVE-NEW" in cves
