#!/usr/bin/env python3
"""zero-day-alerts entrypoint."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time

from config import Config, passes_severity_filter
from notifier import notify
from sources import fetch_all
from storage import Storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zeroday")
_shutdown = False


def _handle_signal(signum, frame) -> None:  # noqa: ANN001,ARG001
    global _shutdown
    logger.info("Received signal %s; shutting down after current cycle", signum)
    _shutdown = True


def run_once(config: Config, storage: Storage) -> int:
    logger.info("Fetching vulnerability feeds")
    entries = fetch_all(config, storage)
    logger.info("Fetched %d total entries across all sources", len(entries))

    candidates: list[dict] = []
    for entry in entries:
        if not passes_severity_filter(entry.get("severity", "MEDIUM"), config.min_severity):
            if not storage.has_record(entry["cve_id"]):
                storage.upsert_alert({**entry, "summary": entry.get("summary", "")[:500]})
                storage.mark_alert_sent([entry["cve_id"]], recipients=[])
            continue
        storage.upsert_alert(entry)
        candidates.append(entry)

    if not candidates:
        logger.info("No new candidates above %s threshold", config.min_severity)
        return 0

    pending_ids = set(storage.get_pending_alert_ids())
    pending_entries = [entry for entry in candidates if entry["cve_id"] in pending_ids]
    if not pending_entries:
        logger.info("No pending alerts to send")
        return 0

    logger.info("%d pending vulnerabilities detected", len(pending_entries))
    success = notify(config, pending_entries)
    cve_ids = [entry["cve_id"] for entry in pending_entries]
    if success:
        all_recipients = config.email_to + config.sms_to + config.whatsapp_to
        storage.mark_alert_sent(cve_ids, all_recipients)
        return len(pending_entries)

    storage.mark_alert_failed(cve_ids, "notify returned False")
    return 0


def daemon_loop(config: Config, storage: Storage) -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    logger.info(
        "Starting daemon; polling every %ds, min severity: %s",
        config.poll_interval_seconds,
        config.min_severity,
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


def send_test_notify(config: Config) -> None:
    test_entry = {
        "cve_id": "CVE-0000-0000",
        "severity": "CRITICAL",
        "summary": "This is a test alert to verify notification channel configuration.",
        "published": "2026-01-01T00:00:00+00:00",
        "source": "TEST",
        "references": ["https://example.com/test-alert"],
        "affected": "test/verification",
        "cvss_score": 10.0,
        "kev": True,
    }
    success = notify(config, [test_entry])
    print("Test notification sent successfully" if success else "Test notification failed — check logs and channel settings")


def seed_database(config: Config, storage: Storage) -> None:
    logger.info("Seeding database without sending alerts")
    entries = fetch_all(config, storage)
    count = 0
    for entry in entries:
        if not storage.has_record(entry["cve_id"]):
            storage.seed_record(entry)
            count += 1
    logger.info("Seeded %d entries", count)
    print(f"Seeded {count} entries into {config.db_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-day vulnerability alert system")
    parser.add_argument("--daemon", action="store_true", help="Run as a continuous daemon")
    parser.add_argument("--seed", action="store_true", help="Ingest current state without alerting")
    parser.add_argument("--stats", action="store_true", help="Print tracker stats")
    parser.add_argument("--test-notify", action="store_true", help="Send a test alert on all configured channels")
    args = parser.parse_args()

    config = Config()
    storage = Storage(config)
    try:
        if args.stats:
            print(json.dumps(storage.stats(), indent=2))
        elif args.test_notify:
            send_test_notify(config)
        elif args.seed:
            seed_database(config, storage)
        elif args.daemon:
            daemon_loop(config, storage)
        else:
            run_once(config, storage)
            sys.exit(0)
    finally:
        storage.close()


if __name__ == "__main__":
    main()
