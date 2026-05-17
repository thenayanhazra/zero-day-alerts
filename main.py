from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Sequence

import requests

from config import SETTINGS
from kev import fetch_catalog, parse_records, recent_records


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value!r}")
    if n <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {n}")
    return n


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zero-Day Alerts CLI")
    parser.add_argument("--days", type=_positive_int, default=30, help="Only show entries added in the last N days.")
    parser.add_argument("--limit", type=_positive_int, default=25, help="Maximum number of entries to print.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        catalog = fetch_catalog(SETTINGS.kev_url, SETTINGS.timeout_seconds)
    except (requests.exceptions.RequestException, ValueError) as exc:
        print(f"error: failed to fetch KEV catalog: {exc}", file=sys.stderr)
        return 1
    records = parse_records(catalog)
    filtered = sorted(recent_records(records, args.days), key=lambda record: record.date_added, reverse=True)
    limited = filtered[: args.limit]

    if args.json:
        print(json.dumps([asdict(record) for record in limited], default=str, indent=2))
        return 0

    for record in limited:
        print(f"{record.date_added} | {record.cve_id} | {record.vendor_project} {record.product}")
        print(f"  {record.vulnerability_name}")
        print(f"  Action: {record.required_action}")
    if not limited:
        print("No KEV entries matched your filter.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
