"""
Fetchers for vulnerability feeds.

Each source returns a list of VulnEntry dicts:
    {
        "cve_id": str,
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        "summary": str,
        "published": str (ISO date),
        "source": str,
        "references": list[str],
        "affected": str,          # short description of affected products
        "cvss_score": float | None,
        "kev": bool,              # in CISA Known Exploited Vulnerabilities catalog
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import requests

from config import Config

logger = logging.getLogger("zeroday.sources")

TIMEOUT = 30  # seconds

# Phrases in NVD descriptions that indicate active exploitation or zero-day status.
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


def _has_exploitation_signal(cve: dict) -> bool:
    """Check whether an NVD CVE entry shows signs of active exploitation."""

    # 1. CISA has flagged it (cisaExploitAdd date present)
    if cve.get("cisaExploitAdd"):
        return True

    # 2. Description contains exploitation language
    descriptions = cve.get("descriptions", [])
    desc_text = " ".join(d.get("value", "") for d in descriptions).lower()
    for phrase in _EXPLOIT_PHRASES:
        if phrase in desc_text:
            return True

    # 3. References tagged as "Exploit" by NVD analysts
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            return True

    return False


# ---------------------------------------------------------------------------
# NVD (National Vulnerability Database) — api.nvd.nist.gov/rest/json/cves/2.0
# ---------------------------------------------------------------------------

def _nvd_severity(metrics: dict) -> tuple[str, float | None]:
    """Extract highest severity + score from NVD metrics block."""
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore", 0)
            label = data.get("baseSeverity", "").upper()
            if not label:
                if score >= 9.0:
                    label = "CRITICAL"
                elif score >= 7.0:
                    label = "HIGH"
                elif score >= 4.0:
                    label = "MEDIUM"
                else:
                    label = "LOW"
            return label, score
    return "MEDIUM", None


def _nvd_affected(configurations: list) -> str:
    """Pull a short 'affected product' string from NVD config nodes."""
    products = set()
    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    if vendor != "*" and product != "*":
                        products.add(f"{vendor}/{product}")
    if products:
        return ", ".join(sorted(products)[:5])
    return "Unknown"


def fetch_nvd(config: Config) -> list[dict]:
    """Fetch recently published/modified CVEs from NVD."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=config.nvd_lookback_hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key

    # Query both newly published AND recently modified CVEs.
    # Modified catches cases where exploitation info is added after publication.
    all_items = []
    for date_type in ("pub", "lastMod"):
        params = {
            f"{date_type}StartDate": start,
            f"{date_type}EndDate": end,
            "resultsPerPage": 200,
        }
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, headers=headers, timeout=TIMEOUT,
            )
            resp.raise_for_status()
            all_items.extend(resp.json().get("vulnerabilities", []))
        except requests.RequestException as exc:
            logger.error("NVD fetch (%s) failed: %s", date_type, exc)

    # De-dup by CVE ID within this batch
    seen_ids = set()
    results = []

    for item in all_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)

        # Zero-day filter: skip CVEs without exploitation signals when enabled
        if config.zero_day_only and not _has_exploitation_signal(cve):
            continue

        descriptions = cve.get("descriptions", [])
        summary = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        severity, cvss_score = _nvd_severity(cve.get("metrics", {}))
        affected = _nvd_affected(cve.get("configurations", []))

        refs = [
            r.get("url", "")
            for r in cve.get("references", [])
            if r.get("url")
        ][:5]

        published = cve.get("published", now.isoformat())

        results.append({
            "cve_id": cve_id,
            "severity": severity,
            "summary": summary[:500],
            "published": published,
            "source": "NVD",
            "references": refs,
            "affected": affected,
            "cvss_score": cvss_score,
            "kev": bool(cve.get("cisaExploitAdd")),
        })

    logger.info("NVD returned %d CVEs (zero_day_only=%s)", len(results), config.zero_day_only)
    return results


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------

# We cache the full catalog and diff against storage.
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev(config: Config) -> list[dict]:
    """Fetch the CISA KEV catalog and return entries."""
    try:
        resp = requests.get(_KEV_URL, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("CISA KEV fetch failed: %s", exc)
        return []

    data = resp.json()
    results = []

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        results.append({
            "cve_id": cve_id,
            "severity": "CRITICAL",  # if it's in KEV, it's actively exploited
            "summary": (
                f"{vuln.get('vendorProject', '')} — {vuln.get('product', '')}: "
                f"{vuln.get('shortDescription', 'No description')}"
            ),
            "published": vuln.get("dateAdded", ""),
            "source": "CISA-KEV",
            "references": [],
            "affected": f"{vuln.get('vendorProject', '')}/{vuln.get('product', '')}",
            "cvss_score": None,
            "kev": True,
        })

    logger.info("CISA KEV catalog has %d entries", len(results))
    return results


# ---------------------------------------------------------------------------
# GitHub Security Advisories (via GraphQL API)
# ---------------------------------------------------------------------------

_GH_GRAPHQL = "https://api.github.com/graphql"

_GH_QUERY = """
query($since: DateTime!) {
  securityAdvisories(
    first: 50,
    publishedSince: $since,
    orderBy: {field: PUBLISHED_AT, direction: DESC}
  ) {
    nodes {
      ghsaId
      summary
      severity
      publishedAt
      references { url }
      identifiers { type value }
      vulnerabilities(first: 5) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""


def fetch_github_advisories(config: Config) -> list[dict]:
    """Fetch recent GitHub Security Advisories."""
    if not config.github_token:
        logger.warning("GITHUB_TOKEN not set — skipping GitHub Advisories")
        return []

    since = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

    headers = {
        "Authorization": f"bearer {config.github_token}",
        "Content-Type": "application/json",
    }
    payload = {"query": _GH_QUERY, "variables": {"since": since}}

    try:
        resp = requests.post(_GH_GRAPHQL, json=payload, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("GitHub Advisories fetch failed: %s", exc)
        return []

    body = resp.json()
    if "errors" in body:
        logger.error("GitHub GraphQL errors: %s", body["errors"])
        return []

    results = []
    advisories = body.get("data", {}).get("securityAdvisories", {}).get("nodes", [])

    for adv in advisories:
        cve_id = None
        for ident in adv.get("identifiers", []):
            if ident.get("type") == "CVE":
                cve_id = ident["value"]
                break
        if not cve_id:
            cve_id = adv.get("ghsaId", "UNKNOWN")

        sev = adv.get("severity", "MODERATE").upper()
        severity_map = {"MODERATE": "MEDIUM", "LOW": "LOW", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
        severity = severity_map.get(sev, "MEDIUM")

        vulns = adv.get("vulnerabilities", {}).get("nodes", [])
        affected_parts = []
        for v in vulns:
            pkg = v.get("package", {})
            if pkg:
                affected_parts.append(f"{pkg.get('ecosystem', '')}/{pkg.get('name', '')}")
        affected = ", ".join(affected_parts[:5]) or "Unknown"

        refs = [r["url"] for r in adv.get("references", []) if r.get("url")][:5]

        results.append({
            "cve_id": cve_id,
            "severity": severity,
            "summary": adv.get("summary", "")[:500],
            "published": adv.get("publishedAt", ""),
            "source": "GitHub-Advisory",
            "references": refs,
            "affected": affected,
            "cvss_score": None,
            "kev": False,
        })

    logger.info("GitHub Advisories returned %d entries", len(results))
    return results


# ---------------------------------------------------------------------------
# Unified fetch
# ---------------------------------------------------------------------------

def fetch_all(config: Config) -> list[dict]:
    """Run all enabled sources and return combined results."""
    entries: list[dict] = []

    if config.enable_nvd:
        entries.extend(fetch_nvd(config))
    if config.enable_cisa_kev:
        entries.extend(fetch_cisa_kev(config))
    if config.enable_github_advisories:
        entries.extend(fetch_github_advisories(config))

    # De-duplicate by CVE ID, preferring KEV entries
    seen: dict[str, dict] = {}
    for e in entries:
        cid = e["cve_id"]
        if cid not in seen or e["kev"]:
            seen[cid] = e
        elif not seen[cid]["kev"]:
            # Merge: keep higher severity
            from config import SEVERITY_RANK
            if SEVERITY_RANK.get(e["severity"], 0) > SEVERITY_RANK.get(seen[cid]["severity"], 0):
                seen[cid]["severity"] = e["severity"]
                seen[cid]["cvss_score"] = e["cvss_score"] or seen[cid]["cvss_score"]

    return list(seen.values())
