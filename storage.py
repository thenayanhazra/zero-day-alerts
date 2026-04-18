"""SQLite-backed storage for alert state and source cursors."""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence

from config import Config


UTC = timezone.utc


class Storage:
    def __init__(self, config: Config):
        db_path = Path(config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                cve_id TEXT PRIMARY KEY,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                source TEXT,
                severity TEXT,
                summary TEXT,
                summary_hash TEXT,
                published_at TEXT,
                affected TEXT,
                references_json TEXT,
                cvss_score REAL,
                kev INTEGER NOT NULL DEFAULT 0,
                alert_status TEXT NOT NULL DEFAULT 'pending',
                last_alert_attempt_at TEXT,
                last_alert_sent_at TEXT,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS alert_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                recipients TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS source_state (
                source TEXT PRIMARY KEY,
                last_cursor TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _summary_hash(summary: str) -> str:
        return hashlib.sha256((summary or "").encode("utf-8")).hexdigest()

    def has_record(self, cve_id: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM alerts WHERE cve_id = ?", (cve_id,)).fetchone()
        return row is not None

    def upsert_alert(self, entry: dict) -> None:
        now = self._now()
        summary = entry.get("summary", "")
        summary_hash = self._summary_hash(summary)
        existing = self.conn.execute(
            "SELECT alert_status, summary_hash FROM alerts WHERE cve_id = ?",
            (entry["cve_id"],),
        ).fetchone()

        next_status = "pending"
        if existing is not None:
            prior_status = existing["alert_status"]
            prior_hash = existing["summary_hash"]
            if prior_status == "sent" and prior_hash == summary_hash:
                next_status = "sent"
            elif prior_status == "failed":
                next_status = "failed"

        self.conn.execute(
            """
            INSERT INTO alerts (
                cve_id, first_seen_at, last_seen_at, source, severity, summary,
                summary_hash, published_at, affected, references_json, cvss_score,
                kev, alert_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                source = excluded.source,
                severity = excluded.severity,
                summary = excluded.summary,
                summary_hash = excluded.summary_hash,
                published_at = excluded.published_at,
                affected = excluded.affected,
                references_json = excluded.references_json,
                cvss_score = excluded.cvss_score,
                kev = excluded.kev,
                alert_status = CASE
                    WHEN alerts.alert_status = 'sent' AND alerts.summary_hash = excluded.summary_hash THEN 'sent'
                    WHEN alerts.alert_status = 'sent' AND alerts.summary_hash <> excluded.summary_hash THEN 'pending'
                    ELSE alerts.alert_status
                END
            """,
            (
                entry["cve_id"],
                now,
                now,
                entry.get("source", ""),
                entry.get("severity", "MEDIUM"),
                summary,
                summary_hash,
                entry.get("published", ""),
                entry.get("affected", "Unknown"),
                "\n".join(entry.get("references", [])),
                entry.get("cvss_score"),
                1 if entry.get("kev") else 0,
                next_status,
            ),
        )
        self.conn.commit()

    def seed_record(self, entry: dict) -> None:
        self.upsert_alert(entry)
        self.mark_alert_sent([entry["cve_id"]], recipients=[])

    def get_pending_alert_ids(self) -> list[str]:
        rows = self.conn.execute(
            """
            SELECT cve_id
            FROM alerts
            WHERE alert_status IN ('pending', 'failed')
            ORDER BY kev DESC, cvss_score DESC, last_seen_at ASC
            """
        ).fetchall()
        return [row["cve_id"] for row in rows]

    def mark_alert_sent(self, cve_ids: Sequence[str], recipients: Sequence[str]) -> None:
        if not cve_ids:
            return
        now = self._now()
        self.conn.executemany(
            """
            UPDATE alerts
            SET alert_status = 'sent',
                last_alert_sent_at = ?,
                last_alert_attempt_at = ?,
                last_error = NULL
            WHERE cve_id = ?
            """,
            [(now, now, cve_id) for cve_id in cve_ids],
        )
        if recipients:
            self.conn.executemany(
                "INSERT INTO alert_log (cve_id, sent_at, recipients) VALUES (?, ?, ?)",
                [(cve_id, now, ",".join(recipients)) for cve_id in cve_ids],
            )
        self.conn.commit()

    def mark_alert_failed(self, cve_ids: Sequence[str], error: Exception | str) -> None:
        if not cve_ids:
            return
        now = self._now()
        self.conn.executemany(
            """
            UPDATE alerts
            SET alert_status = 'failed',
                last_alert_attempt_at = ?,
                last_error = ?
            WHERE cve_id = ?
            """,
            [(now, str(error), cve_id) for cve_id in cve_ids],
        )
        self.conn.commit()

    def get_source_cursor(self, source: str, fallback_hours: int, overlap_minutes: int = 10) -> str:
        row = self.conn.execute(
            "SELECT last_cursor FROM source_state WHERE source = ?",
            (source,),
        ).fetchone()
        if row and row["last_cursor"]:
            cursor = datetime.fromisoformat(row["last_cursor"])
            return (cursor - timedelta(minutes=overlap_minutes)).astimezone(UTC).isoformat()
        return (datetime.now(UTC) - timedelta(hours=fallback_hours)).isoformat()

    def set_source_cursor(self, source: str, cursor: str | None = None) -> None:
        now = self._now()
        actual_cursor = cursor or now
        self.conn.execute(
            """
            INSERT INTO source_state (source, last_cursor, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_cursor = excluded.last_cursor,
                updated_at = excluded.updated_at
            """,
            (source, actual_cursor, now),
        )
        self.conn.commit()

    def stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        pending = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='pending'").fetchone()[0]
        failed = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='failed'").fetchone()[0]
        sent = self.conn.execute("SELECT COUNT(*) FROM alert_log").fetchone()[0]
        latest = self.conn.execute(
            "SELECT cve_id, last_seen_at, alert_status FROM alerts ORDER BY last_seen_at DESC LIMIT 1"
        ).fetchone()
        return {
            "total_tracked": total,
            "pending": pending,
            "failed": failed,
            "total_alerts_sent": sent,
            "latest_cve": dict(latest) if latest else None,
        }

    def close(self) -> None:
        self.conn.close()
