from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    timeout_seconds: int = 20


SETTINGS = Settings()
