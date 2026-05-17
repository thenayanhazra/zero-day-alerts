from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import requests

from main import run


def _catalog(*entries: dict) -> dict:
    return {"vulnerabilities": list(entries)}


def _vuln(cve_id: str, date_added: str) -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Name",
        "dateAdded": date_added,
        "shortDescription": "desc",
        "requiredAction": "action",
    }


# Use far-future dates so tests pass regardless of when they run.
_RECENT = _vuln("CVE-2099-0001", "2099-01-01")
_OLD = _vuln("CVE-2020-0001", "2020-01-01")


def test_network_error_returns_exit_1(capsys) -> None:
    with patch("main.fetch_catalog", side_effect=requests.exceptions.ConnectionError("unreachable")):
        assert run([]) == 1
    assert "error:" in capsys.readouterr().err


def test_text_output_contains_cve_id(capsys) -> None:
    with patch("main.fetch_catalog", return_value=_catalog(_RECENT)):
        assert run(["--days", "36500"]) == 0
    assert "CVE-2099-0001" in capsys.readouterr().out


def test_json_output_is_parseable(capsys) -> None:
    with patch("main.fetch_catalog", return_value=_catalog(_RECENT)):
        assert run(["--days", "36500", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["cve_id"] == "CVE-2099-0001"


def test_no_entries_message(capsys) -> None:
    with patch("main.fetch_catalog", return_value=_catalog(_OLD)):
        assert run(["--days", "1"]) == 0
    assert "No KEV entries matched" in capsys.readouterr().out


def test_limit_caps_results(capsys) -> None:
    entries = [_vuln(f"CVE-2099-{i:04d}", "2099-01-01") for i in range(5)]
    with patch("main.fetch_catalog", return_value=_catalog(*entries)):
        assert run(["--days", "36500", "--limit", "2", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2


def test_invalid_json_returns_exit_1(capsys) -> None:
    with patch("main.fetch_catalog", side_effect=ValueError("invalid JSON")):
        assert run([]) == 1
    assert "error:" in capsys.readouterr().err


def test_http_error_returns_exit_1(capsys) -> None:
    with patch("main.fetch_catalog", side_effect=requests.exceptions.HTTPError("403")):
        assert run([]) == 1
    assert "error:" in capsys.readouterr().err


def test_nonpositive_days_rejected() -> None:
    with pytest.raises(SystemExit) as exc_info:
        run(["--days", "0"])
    assert exc_info.value.code != 0


def test_nonpositive_limit_rejected() -> None:
    with pytest.raises(SystemExit) as exc_info:
        run(["--limit", "-1"])
    assert exc_info.value.code != 0
