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


def _make_vuln(cve_id: str, date_added: str) -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Name",
        "dateAdded": date_added,
        "shortDescription": "desc",
        "requiredAction": "action",
    }


def test_parse_records_skips_record_with_missing_date() -> None:
    catalog = {"vulnerabilities": [{"cveID": "CVE-2026-0002", "vendorProject": "X", "product": "Y",
                                    "vulnerabilityName": "N", "shortDescription": "d", "requiredAction": "a"}]}
    assert parse_records(catalog) == []


def test_parse_records_skips_record_with_bad_date_format() -> None:
    catalog = {"vulnerabilities": [{"cveID": "CVE-2026-0003", "vendorProject": "X", "product": "Y",
                                    "vulnerabilityName": "N", "dateAdded": "not-a-date",
                                    "shortDescription": "d", "requiredAction": "a"}]}
    assert parse_records(catalog) == []


def test_recent_records_filters_by_cutoff() -> None:
    today = date(2026, 4, 30)
    catalog = {
        "vulnerabilities": [
            _make_vuln("CVE-OLD", "2026-01-01"),   # 119 days before today — outside 30-day window
            _make_vuln("CVE-NEW", "2026-04-25"),   # 5 days before today — inside 30-day window
        ]
    }
    records = parse_records(catalog)
    filtered = recent_records(records, days=30, today=today)
    cves = {record.cve_id for record in filtered}
    assert "CVE-NEW" in cves
    assert "CVE-OLD" not in cves
