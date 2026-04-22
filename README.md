# Zero-Day Alerts

Zero-Day Alerts is a lightweight Python service that watches public vulnerability feeds, normalizes new findings, and sends actionable email notifications when high-risk CVEs appear.

The project is intentionally small: one process, SQLite state, and SMTP delivery. It is designed for teams that want early warning without operating a full SIEM stack.

## What it does today

- Polls multiple sources on a schedule:
  - NVD
  - CISA Known Exploited Vulnerabilities (KEV)
  - GitHub Security Advisories
- Merges duplicate CVEs across sources into a single finding
- Filters alerts by severity and optional zero-day mode
- Persists state in SQLite to avoid duplicate notifications
- Sends HTML email alerts through SMTP
- Supports one-off and daemon modes from a single CLI

## Reliability and correctness improvements in this revision

- Alert state is retryable with `pending`, `sent`, and `failed`
- Findings are marked `sent` only after successful SMTP delivery
- GitHub advisory polling uses a persistent cursor (not a fixed time window)
- GitHub GraphQL pagination is implemented
- Duplicate CVEs across sources are merged instead of partially overwritten
- HTML email content is escaped before rendering

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py --seed      # optional initial backfill
python main.py             # single poll + alert run
python main.py --daemon    # continuous polling loop
python main.py --stats     # print local DB counters
python main.py --test-email
```

## Configuration

Use `.env.example` as your template. Most deployments only need to adjust:

- Email / SMTP: `EMAIL_TO`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`
- Alert policy: `MIN_SEVERITY`, `ZERO_DAY_ONLY`
- Polling windows / overlap: `NVD_LOOKBACK_HOURS`, `GITHUB_LOOKBACK_HOURS`, `CURSOR_OVERLAP_MINUTES`

## How it works (high level)

1. Fetch vulnerability records from each source.
2. Normalize and merge CVE data into a consistent internal shape.
3. Compare against local SQLite state.
4. Queue unsent high-risk findings as `pending`.
5. Deliver email notifications and transition status to `sent` (or `failed` for retry).

## Project layout

- `main.py` — CLI entrypoint and polling/alert loop
- `config.py` — environment-based configuration
- `sources.py` — source fetchers and merge logic
- `storage.py` — SQLite schema and state transitions
- `notifier.py` — SMTP client and email rendering
- `tests/` — regression tests for core source behavior


None of these require changing the core architecture; they extend observability and control while preserving the project’s lightweight design.
