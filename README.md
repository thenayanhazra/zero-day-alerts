# Zero-Day Alerts

A lightweight Python service that watches public vulnerability feeds and delivers actionable alerts when high-risk CVEs appear.

One process. SQLite state. No bloatware.

## What it does

- Polls multiple sources on a schedule:
  - NVD
  - CISA Known Exploited Vulnerabilities (KEV)
  - GitHub Security Advisories
- Merges duplicate CVEs across sources into a single finding
- Filters by severity and optional zero-day-only mode
- Persists state in SQLite to avoid duplicate notifications
- Delivers alerts via email (SMTP), SMS, and/or WhatsApp (Twilio)

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env        # fill in your settings
python main.py --seed       # optional: backfill current state without alerting
python main.py              # single poll + alert run
python main.py --daemon     # continuous polling loop
python main.py --stats      # print local DB counters
python main.py --test-notify
```

## Configuration

Copy `.env.example` to `.env` and fill in the values you need.

### Email (SMTP)

| Variable | Description |
|---|---|
| `EMAIL_TO` | Comma-separated recipient addresses |
| `EMAIL_FROM` | Sender address |
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | Port (default: 587) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASSWORD` | SMTP password |
| `SMTP_USE_TLS` | STARTTLS (default: true) |
| `SMTP_USE_SSL` | SSL/SMTPS (default: false) |

### SMS / WhatsApp (Twilio)

| Variable | Description |
|---|---|
| `TWILIO_ACCOUNT_SID` | Twilio Account SID |
| `TWILIO_AUTH_TOKEN` | Twilio Auth Token |
| `TWILIO_FROM` | Your Twilio phone number (e.g. `+15551234567`) |
| `SMS_TO` | Comma-separated phone numbers for SMS |
| `WHATSAPP_TO` | Comma-separated phone numbers for WhatsApp |

For WhatsApp, use a Twilio-approved WhatsApp sender or the sandbox number.

### Alert policy

| Variable | Default | Description |
|---|---|---|
| `MIN_SEVERITY` | `HIGH` | Minimum severity to alert on (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `ZERO_DAY_ONLY` | `true` | Only alert on CVEs with active-exploitation signals |
| `POLL_INTERVAL_SECONDS` | `300` | Seconds between daemon polls |
| `NVD_LOOKBACK_HOURS` | `24` | How far back to query NVD on first run |
| `GITHUB_LOOKBACK_HOURS` | `24` | How far back to query GitHub on first run |

## Project layout

- `main.py` — CLI entrypoint and polling loop
- `config.py` — environment-based configuration
- `sources.py` — feed fetchers and merge logic
- `storage.py` — SQLite schema and state transitions
- `notifier.py` — email, SMS, and WhatsApp delivery
- `tests/` — regression tests for core source behavior
