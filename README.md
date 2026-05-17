# Zero-Day Alerts

A lightweight CLI that pulls CISA's [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, filters by recency, and prints actionable output.

## Requirements

- Python 3.11+

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py [--days N] [--limit N] [--json]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `30` | Only show entries added in the last N days |
| `--limit` | `25` | Maximum number of entries to print |
| `--json` | off | Print machine-readable JSON instead of text |

**Examples**

```bash
# Last 30 days, top 25 (defaults)
python main.py

# Last 7 days, top 10
python main.py --days 7 --limit 10

# Full JSON output for the last 14 days
python main.py --days 14 --json
```

**Sample output**

```
YYYY-MM-DD | CVE-YYYY-0001 | Acme Router
  Acme Router Remote Code Execution Vulnerability
  Action: Apply mitigations per vendor instructions or discontinue use.
YYYY-MM-DD | CVE-YYYY-0002 | Example VPN
  Example VPN Authentication Bypass Vulnerability
  Action: Apply updates per vendor instructions.
```

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | Success (including "no entries matched") |
| `1` | Failed to fetch or parse the KEV catalog |

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

## Configuration

Override defaults via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KEV_URL` | CISA KEV feed URL | Source JSON feed |
| `TIMEOUT_SECONDS` | `20` | HTTP request timeout in seconds (must be a positive integer) |

A `.env.example` is included for reference.
