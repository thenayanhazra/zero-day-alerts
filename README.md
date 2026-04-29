# Zero-Day Alerts

Rebuilt from scratch as a small, testable CLI that retrieves CISA's KEV catalog, filters by recency, and prints actionable output.

## Features

- Pulls latest KEV JSON feed from CISA
- Normalizes records to a simple internal model
- Filters by `--days` window
- Supports table output or JSON output

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py
python main.py --days 14 --limit 20
python main.py --json
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
```
