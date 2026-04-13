"""
Configuration loaded from environment variables or .env file.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # Polling
    poll_interval_seconds: int = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))

    # Database
    db_path: str = os.getenv("DB_PATH", str(Path(__file__).parent / "data" / "seen.db"))

    # Email (SMTP)
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    email_from: str = os.getenv("EMAIL_FROM", "")
    email_to: list[str] = field(default_factory=list)

    # Severity filter — only alert on these and above
    # Options: CRITICAL, HIGH, MEDIUM, LOW
    min_severity: str = os.getenv("MIN_SEVERITY", "HIGH")

    # Source toggles
    enable_nvd: bool = os.getenv("ENABLE_NVD", "true").lower() == "true"
    enable_cisa_kev: bool = os.getenv("ENABLE_CISA_KEV", "true").lower() == "true"
    enable_github_advisories: bool = os.getenv("ENABLE_GITHUB_ADVISORIES", "true").lower() == "true"

    # NVD API key (optional, raises rate limit from 5/30s to 50/30s)
    nvd_api_key: str = os.getenv("NVD_API_KEY", "")

    # GitHub token (optional, raises rate limit)
    github_token: str = os.getenv("GITHUB_TOKEN", "")

    def __post_init__(self):
        raw = os.getenv("EMAIL_TO", "")
        self.email_to = [addr.strip() for addr in raw.split(",") if addr.strip()]

        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if self.min_severity not in severity_order:
            self.min_severity = "HIGH"


SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def passes_severity_filter(severity: str, min_severity: str) -> bool:
    return SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK.get(min_severity, 2)
