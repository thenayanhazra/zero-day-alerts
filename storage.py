"""
SQLite-backed storage to track which CVEs have already been seen and alerted on.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import Config


class Storage:
    def __init__(self, config: Config):
        db_path = Path(config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS seen_cves (
                cve_id       TEXT PRIMARY KEY,
                severity     TEXT,
                source       TEXT,
                summary      TEXT,
                published_at TEXT,
                seen_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alert_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id       TEXT NOT NULL,
                sent_at      TEXT NOT NULL,
                recipients   TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def is_seen(self, cve_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM seen_cves WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return row is not None

    def mark_seen(self, cve_id: str, severity: str, source: str,
                  summary: str, published_at: str):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """INSERT OR IGNORE INTO seen_cves
               (cve_id, severity, source, summary, published_at, seen_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (cve_id, severity, source, summary, published_at, now),
        )
        self.conn.commit()

    def log_alert(self, cve_id: str, recipients: list[str]):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO alert_log (cve_id, sent_at, recipients) VALUES (?, ?, ?)",
            (cve_id, now, ",".join(recipients)),
        )
        self.conn.commit()

    def stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM seen_cves").fetchone()[0]
        alerts = self.conn.execute("SELECT COUNT(*) FROM alert_log").fetchone()[0]
        latest = self.conn.execute(
            "SELECT cve_id, seen_at FROM seen_cves ORDER BY seen_at DESC LIMIT 1"
        ).fetchone()
        return {
            "total_tracked": total,
            "total_alerts_sent": alerts,
            "latest_cve": dict(latest) if latest else None,
        }

    def close(self):
        self.conn.close()
