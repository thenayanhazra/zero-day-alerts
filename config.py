from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    kev_url: str = os.environ.get(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    timeout_seconds: int = int(os.environ.get("TIMEOUT_SECONDS", "20"))


SETTINGS = Settings()
