from __future__ import annotations

import os
from dataclasses import dataclass, field


def _parse_timeout() -> int:
    raw = os.environ.get("TIMEOUT_SECONDS", "20")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"TIMEOUT_SECONDS must be an integer, got {raw!r}")
    if value <= 0:
        raise ValueError(f"TIMEOUT_SECONDS must be a positive integer, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    kev_url: str = os.environ.get(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    timeout_seconds: int = field(default_factory=_parse_timeout)


SETTINGS = Settings()
