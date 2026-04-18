"""Fetchers for vulnerability feeds."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

from config import Config, SEVERITY_RANK, higher_severity
from storage import Storage

logger = logging.getLogger("zeroday.sources")
TIMEOUT = 30
UTC = timezone.utc

_EXPLOIT_PHRASES = [
    "exploited in the wild",
    "actively exploited",
    "active exploitation",
    "zero-day",
    "zero day",
    "0-day",
    "0day",
    "known to be exploited",
    "exploitation has been",
    "exploitation was observed",
    "exploit exists",
    "being exploited",
    "has been exploited",
    "under active attack",
]

_GH_GRAPHQL = "https://api.github.com/graphql"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    fixed = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(fixed).astimezone(UTC)
    except ValueError:
        return None


def _iso_utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _pick_summary(old: str, new: str, new_is_kev: bool) -> str:
    if new_is_kev and new:
        return new[:500]
    if len(new or "") > len(old or ""):
        return (new or "")[:500]
    return (old or new or "")[:500]


def _dedupe_refs(refs: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for ref in refs:
        if ref and ref not in seen:
            seen.add(ref)
            output.append(ref)
    return output[:8]


def _has_exploitation_signal(cve: dict[str, Any]) -> bool:
    if cve.get("cisaExploitAdd"):
        return True
    desc_text = " ".join(d.get("value", "") for d in cve.get("descriptions", [])).lower()
    if any(phrase in desc_text for phrase in _EXPLOIT_PHRASES):
        return True
    for ref in cve.get("references", []):
        if "Exploit" in ref.get("tags", []):
            return True
    return False


def _nvd_severity(metrics: dict[str, Any]) -> tuple[str, float | None]:
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        label = (data.get("baseSeverity") or "").upper()
        if not label and isinstance(score, (int, float)):
            if score >= 9.0:
                label = "CRITICAL"
            elif score >= 7.0:
                label = "HIGH"
            elif score >= 4.0:
                label = "MEDIUM"
            else:
                label = "LOW"
        return label or "MEDIUM", score
    return "MEDIUM", None


def _nvd_affected(configurations: list[dict[str, Any]]) -> str:
    products: set[str] = set()
    for group in configurations:
        for node in group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    if vendor != "*" and product != "*":
                        products.add(f"{vendor}/{product}")
    return ", ".join(sorted(products)[:5]) if products else "Unknown"


def fetch_nvd(config: Config, storage: Storage) -> list[dict[str, Any]]:
    now = _iso_utc_now()
    start = storage.get_source_cursor("nvd", config.nvd_lookback_hours, config.cursor_overlap_minutes)
    headers = {"apiKey": config.nvd_api_key} if config.nvd_api_key else {}
    all_items: list[dict[str, Any]] = []

    for date_type in ("pub", "lastMod"):
        params = {
            f"{date_type}StartDate": start,
            f"{date_type}EndDate": now,
            "resultsPerPage": 200,
            "startIndex": 0,
        }
        while True:
            try:
                resp = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                    headers=headers,
                    timeout=TIMEOUT,
                )
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.error("NVD fetch (%s) failed: %s", date_type, exc)
                break
            body = resp.json()
            vulns = body.get("vulnerabilities", [])
            all_items.extend(vulns)
            total = body.get("totalResults", len(vulns))
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total or not vulns:
                break

    seen_ids: set[str] = set()
    results: list[dict[str, Any]] = []
    for item in all_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id or cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        if config.zero_day_only and not _has_exploitation_signal(cve):
            continue
        descriptions = cve.get("descriptions", [])
        summary = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        severity, cvss_score = _nvd_severity(cve.get("metrics", {}))
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
        results.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "summary": summary[:500],
                "published": cve.get("published", now),
                "source": "NVD",
                "references": refs[:8],
                "affected": _nvd_affected(cve.get("configurations", [])),
                "cvss_score": cvss_score,
                "kev": bool(cve.get("cisaExploitAdd")),
            }
        )

    storage.set_source_cursor("nvd", now)
    logger.info("NVD returned %d entries", len(results))
    return results


def fetch_cisa_kev(_: Config, storage: Storage) -> list[dict[str, Any]]:
    try:
        resp = requests.get(_KEV_URL, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("CISA KEV fetch failed: %s", exc)
        return []

    body = resp.json()
    results: list[dict[str, Any]] = []
    for vuln in body.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue
        results.append(
            {
                "cve_id": cve_id,
                "severity": "CRITICAL",
                "summary": (
                    f"{vuln.get('vendorProject', '')} — {vuln.get('product', '')}: "
                    f"{vuln.get('shortDescription', 'No description')}"
                )[:500],
                "published": vuln.get("dateAdded", ""),
                "source": "CISA-KEV",
                "references": [],
                "affected": f"{vuln.get('vendorProject', '')}/{vuln.get('product', '')}".strip("/"),
                "cvss_score": None,
                "kev": True,
            }
        )
    storage.set_source_cursor("cisa-kev")
    logger.info("CISA KEV returned %d entries", len(results))
    return results


_GH_QUERY = """
query($first: Int!, $after: String, $since: DateTime!) {
  securityAdvisories(
    first: $first,
    after: $after,
    publishedSince: $since,
    orderBy: {field: PUBLISHED_AT, direction: DESC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      severity
      publishedAt
      references { url }
      identifiers { type value }
      vulnerabilities(first: 10) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""


def fetch_github_advisories(config: Config, storage: Storage) -> list[dict[str, Any]]:
    if not config.github_token:
        logger.warning("GITHUB_TOKEN not set; skipping GitHub advisories")
        return []

    since = storage.get_source_cursor(
        "github-advisories",
        config.github_lookback_hours,
        config.cursor_overlap_minutes,
    )
    now = _iso_utc_now()
    headers = {
        "Authorization": f"bearer {config.github_token}",
        "Content-Type": "application/json",
    }

    results: list[dict[str, Any]] = []
    after: str | None = None
    severity_map = {"LOW": "LOW", "MODERATE": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}

    while True:
        payload = {"query": _GH_QUERY, "variables": {"since": since, "first": 100, "after": after}}
        try:
            resp = requests.post(_GH_GRAPHQL, json=payload, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.error("GitHub advisories fetch failed: %s", exc)
            return results
        body = resp.json()
        if body.get("errors"):
            logger.error("GitHub GraphQL errors: %s", body["errors"])
            return results

        advisories = body.get("data", {}).get("securityAdvisories", {})
        for adv in advisories.get("nodes", []):
            cve_id = None
            for ident in adv.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value")
                    break
            if not cve_id:
                cve_id = adv.get("ghsaId", "UNKNOWN")

            vulns = adv.get("vulnerabilities", {}).get("nodes", [])
            affected = ", ".join(
                f"{v.get('package', {}).get('ecosystem', '')}/{v.get('package', {}).get('name', '')}"
                for v in vulns
                if v.get("package")
            )
            results.append(
                {
                    "cve_id": cve_id,
                    "severity": severity_map.get((adv.get("severity") or "MODERATE").upper(), "MEDIUM"),
                    "summary": (adv.get("summary") or "")[:500],
                    "published": adv.get("publishedAt", now),
                    "source": "GitHub-Advisory",
                    "references": [r.get("url", "") for r in adv.get("references", []) if r.get("url")][:8],
                    "affected": affected or "Unknown",
                    "cvss_score": None,
                    "kev": False,
                }
            )

        page_info = advisories.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break

    storage.set_source_cursor("github-advisories", now)
    logger.info("GitHub advisories returned %d entries", len(results))
    return results


def merge_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for entry in entries:
        cid = entry["cve_id"]
        if cid not in merged:
            merged[cid] = {
                **entry,
                "references": list(entry.get("references", [])),
                "source": entry.get("source", ""),
            }
            continue
        current = merged[cid]
        current["kev"] = bool(current.get("kev")) or bool(entry.get("kev"))
        current["severity"] = higher_severity(current.get("severity", "MEDIUM"), entry.get("severity", "MEDIUM"))
        current_cvss = current.get("cvss_score")
        new_cvss = entry.get("cvss_score")
        if current_cvss is None or (new_cvss is not None and new_cvss > current_cvss):
            current["cvss_score"] = new_cvss
        current["summary"] = _pick_summary(current.get("summary", ""), entry.get("summary", ""), bool(entry.get("kev")))
        current["references"] = _dedupe_refs(current.get("references", []) + entry.get("references", []))
        current_sources = set(filter(None, map(str.strip, current.get("source", "").split(","))))
        current_sources.add(entry.get("source", ""))
        current["source"] = ", ".join(sorted(filter(None, current_sources)))
        if current.get("affected") == "Unknown" and entry.get("affected") not in {None, "", "Unknown"}:
            current["affected"] = entry["affected"]
        current_published = _parse_iso(current.get("published"))
        entry_published = _parse_iso(entry.get("published"))
        if current_published and entry_published and entry_published < current_published:
            current["published"] = entry["published"]
    return list(merged.values())


def fetch_all(config: Config, storage: Storage) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if config.enable_nvd:
        entries.extend(fetch_nvd(config, storage))
    if config.enable_cisa_kev:
        entries.extend(fetch_cisa_kev(config, storage))
    if config.enable_github_advisories:
        entries.extend(fetch_github_advisories(config, storage))
    return merge_entries(entries)
