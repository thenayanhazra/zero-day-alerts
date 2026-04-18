# Zero-Day Alerts

A small Python daemon that monitors public vulnerability feeds and sends email alerts for newly observed high-risk CVEs.

## What changed in this prepared revision

- Alert state is now retryable: `pending`, `sent`, `failed`
- Findings are marked sent only after successful SMTP delivery
- GitHub advisory polling uses a persistent cursor instead of a fixed 2-hour window
- GitHub GraphQL pagination is implemented
- Duplicate CVEs across sources are merged instead of partially overwritten
- HTML email content is escaped before rendering

## Sources

- NVD
- CISA KEV
- GitHub Security Advisories

## Usage

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py --seed
python main.py
python main.py --daemon
python main.py --stats
python main.py --test-email
```

## Configuration

Use `.env.example` as the template. The most important variables are:

- `EMAIL_TO`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `MIN_SEVERITY`
- `ZERO_DAY_ONLY`
- `NVD_LOOKBACK_HOURS`
- `GITHUB_LOOKBACK_HOURS`
- `CURSOR_OVERLAP_MINUTES`

## Files

- `main.py` — CLI entrypoint and alert loop
- `config.py` — environment-based configuration
- `sources.py` — source fetchers and merge logic
- `storage.py` — SQLite state, alert status, source cursors
- `notifier.py` — SMTP and email rendering
- `tests/` — minimal regression coverage
