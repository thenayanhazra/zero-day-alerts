#!/usr/bin/env python3
"""
zero-day-alerts — Monitor vulnerability feeds and send email alerts for new CVEs.

Usage:
    python main.py              Run once (check feeds, alert, exit)
    python main.py --seed       Ingest current state without alerting (run first!)
    python main.py --daemon     Run continuously on a polling interval
    python main.py --stats      Print tracker stats and exit
    python main.py --test-email Send a test alert email and exit
"""

import argparse
import logging
import signal
import sys
import time

from config import Config, passes_severity_filter
from notifier import send_alert
from sources import fetch_all
from storage import Storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zeroday")

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Received signal %s — shutting down after current cycle", signum)
    _shutdown = True


def run_once(config: Config, storage: Storage) -> int:
    """Fetch feeds, detect unseen entries, alert. Returns count of new alerts."""
    logger.info("Fetching vulnerability feeds...")
    entries = fetch_all(config)
    logger.info("Fetched %d total entries across all sources", len(entries))

    new_entries = []
    for entry in entries:
        if storage.is_seen(entry["cve_id"]):
            continue
        if not passes_severity_filter(entry["severity"], config.min_severity):
            # Still mark as seen so we don't re-check every cycle
            storage.mark_seen(
                entry["cve_id"], entry["severity"], entry["source"],
                entry["summary"], entry["published"],
            )
            continue
        new_entries.append(entry)

    if not new_entries:
        logger.info("No new vulnerabilities above %s threshold", config.min_severity)
        return 0

    logger.info("🚨 %d new vulnerabilities detected!", len(new_entries))

    # Send alert
    success = send_alert(config, new_entries)

    # Mark as seen + log
    for entry in new_entries:
        storage.mark_seen(
            entry["cve_id"], entry["severity"], entry["source"],
            entry["summary"], entry["published"],
        )
        if success:
            storage.log_alert(entry["cve_id"], config.email_to)

    return len(new_entries)


def daemon_loop(config: Config, storage: Storage):
    """Run continuously with a polling interval."""
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "Starting daemon — polling every %ds, min severity: %s",
        config.poll_interval_seconds, config.min_severity,
    )

    while not _shutdown:
        try:
            run_once(config, storage)
        except Exception:
            logger.exception("Error during poll cycle")

        for _ in range(config.poll_interval_seconds):
            if _shutdown:
                break
            time.sleep(1)

    logger.info("Daemon stopped")


def send_test_email(config: Config):
    """Send a test alert to verify SMTP configuration."""
    test_entry = {
        "cve_id": "CVE-0000-00000",
        "severity": "CRITICAL",
        "summary": "This is a test alert from zero-day-alerts to verify your email configuration is working.",
        "published": "2025-01-01T00:00:00",
        "source": "TEST",
        "references": ["https://github.com/your-username/zero-day-alerts"],
        "affected": "test/verification",
        "cvss_score": 10.0,
        "kev": True,
    }
    success = send_alert(config, [test_entry])
    if success:
        print("✅ Test email sent successfully")
    else:
        print("❌ Test email failed — check logs and SMTP settings")


def seed_database(config: Config, storage: Storage):
    """Ingest all current entries into the database WITHOUT sending alerts.
    Run this once before starting the daemon so existing CVEs don't
    trigger a flood of emails on first real run."""
    logger.info("Seeding database — ingesting current state without alerting...")
    entries = fetch_all(config)

    count = 0
    for entry in entries:
        if not storage.is_seen(entry["cve_id"]):
            storage.mark_seen(
                entry["cve_id"], entry["severity"], entry["source"],
                entry["summary"], entry["published"],
            )
            count += 1

    logger.info("Seeded %d entries (%d were already tracked)", count, len(entries) - count)
    print(f"✅ Seeded {count} entries into {config.db_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Zero-day vulnerability alert system",
    )
    parser.add_argument("--daemon", action="store_true", help="Run as a continuous daemon")
    parser.add_argument("--seed", action="store_true", help="Ingest current state without alerting (run once before first real use)")
    parser.add_argument("--stats", action="store_true", help="Print tracker stats")
    parser.add_argument("--test-email", action="store_true", help="Send a test alert email")
    args = parser.parse_args()

    config = Config()
    storage = Storage(config)

    try:
        if args.stats:
            import json
            print(json.dumps(storage.stats(), indent=2))
        elif args.test_email:
            send_test_email(config)
        elif args.seed:
            seed_database(config, storage)
        elif args.daemon:
            daemon_loop(config, storage)
        else:
            count = run_once(config, storage)
            sys.exit(0 if count == 0 else 0)
    finally:
        storage.close()


if __name__ == "__main__":
    main()
