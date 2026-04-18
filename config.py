"""Configuration for zero-day-alerts."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _get_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default).lower()).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Config:
    poll_interval_seconds: int = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))
    db_path: str = os.getenv("DB_PATH", str(Path(__file__).parent / "data" / "alerts.db"))

    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls: bool = _get_bool("SMTP_USE_TLS", True)
    smtp_use_ssl: bool = _get_bool("SMTP_USE_SSL", False)
    smtp_timeout: int = int(os.getenv("SMTP_TIMEOUT", "20"))
    email_from: str = os.getenv("EMAIL_FROM", "")
    email_to: list[str] = field(default_factory=list)

    min_severity: str = os.getenv("MIN_SEVERITY", "HIGH").strip().upper()

    enable_nvd: bool = _get_bool("ENABLE_NVD", True)
    enable_cisa_kev: bool = _get_bool("ENABLE_CISA_KEV", True)
    enable_github_advisories: bool = _get_bool("ENABLE_GITHUB_ADVISORIES", True)

    zero_day_only: bool = _get_bool("ZERO_DAY_ONLY", True)
    nvd_lookback_hours: int = int(os.getenv("NVD_LOOKBACK_HOURS", "24"))
    github_lookback_hours: int = int(os.getenv("GITHUB_LOOKBACK_HOURS", "24"))
    cursor_overlap_minutes: int = int(os.getenv("CURSOR_OVERLAP_MINUTES", "10"))

    nvd_api_key: str = os.getenv("NVD_API_KEY", "")
    github_token: str = os.getenv("GITHUB_TOKEN", "")

    def __post_init__(self) -> None:
        raw = os.getenv("EMAIL_TO", "")
        self.email_to = [addr.strip() for addr in raw.split(",") if addr.strip()]
        if self.min_severity not in SEVERITY_RANK:
            self.min_severity = "HIGH"


def passes_severity_filter(severity: str, min_severity: str) -> bool:
    return SEVERITY_RANK.get((severity or "").upper(), -1) >= SEVERITY_RANK.get(min_severity.upper(), 2)


def higher_severity(left: str, right: str) -> str:
    left_u = (left or "MEDIUM").upper()
    right_u = (right or "MEDIUM").upper()
    return left_u if SEVERITY_RANK.get(left_u, 1) >= SEVERITY_RANK.get(right_u, 1) else right_u
