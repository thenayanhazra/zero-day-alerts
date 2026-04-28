"""Basic runtime config for the simplified CLI."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kev_url: str = os.getenv(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    timeout_seconds: int = int(os.getenv("HTTP_TIMEOUT_SECONDS", "20"))
