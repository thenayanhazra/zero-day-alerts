# Zero-Day Alerts (Basic)

A minimal command-line tool that fetches the CISA Known Exploited Vulnerabilities (KEV) feed and prints recent CVEs.

## What this rebuild includes

- One data source: CISA KEV JSON feed
- One command: fetch + print
- Optional JSON output
- Optional `--limit`
- No database, no daemon loop, no notifications

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Usage

```bash
python main.py --limit 10
python main.py --json
```

## Files

- `main.py` - CLI entrypoint
- `config.py` - simple runtime settings
- `sources.py` - KEV fetch + normalization
- `tests/test_sources.py` - basic unit tests
