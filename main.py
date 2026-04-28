#!/usr/bin/env python3
"""Minimal Zero-Day Alerts CLI."""
from __future__ import annotations

import argparse
import json
import sys

from config import Config
from sources import fetch_kev


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch and print CISA KEV vulnerabilities")
    parser.add_argument("--limit", type=int, default=20, help="Number of results to print (default: 20)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    return parser


def run() -> int:
    args = build_parser().parse_args()
    config = Config()

    try:
        items = fetch_kev(config)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: failed to fetch KEV feed: {exc}", file=sys.stderr)
        return 1

    if args.limit < 1:
        print("Error: --limit must be at least 1", file=sys.stderr)
        return 1

    limited = items[: args.limit]

    if args.json:
        print(json.dumps(limited, indent=2))
        return 0

    print(f"Fetched {len(items)} KEV records. Showing {len(limited)}:")
    for item in limited:
        print(f"- {item['cve_id']} | {item['vendor']}/{item['product']} | added {item['date_added']}")
        print(f"  {item['summary']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
