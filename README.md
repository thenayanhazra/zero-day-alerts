# zero-day-alerts

A lightweight Python daemon that monitors public vulnerability feeds for new CVEs and sends email alerts the moment they appear.

## What it monitors

| Source | What it catches | Update frequency |
|---|---|---|
| **NVD** (NIST) | All newly published CVEs with CVSS scoring | Minutes after publication |
| **CISA KEV** | Vulnerabilities confirmed to be actively exploited in the wild | As CISA adds entries |
| **GitHub Security Advisories** | Vulnerabilities in open-source packages (npm, PyPI, Go, etc.) | Near real-time |

Entries from CISA KEV are always treated as CRITICAL since they represent confirmed active exploitation.

## How it works

1. Polls all enabled sources on a configurable interval (default: 5 minutes)
2. De-duplicates across sources — if the same CVE appears in NVD and KEV, the KEV data takes priority
3. Filters by your configured minimum severity (default: HIGH and above)
4. Sends a formatted HTML email for any CVE it hasn't seen before
5. Tracks everything in a local SQLite database so it never alerts twice on the same CVE

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/zero-day-alerts.git
cd zero-day-alerts
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your SMTP credentials and preferences
```

### API keys (optional but recommended)

**NVD API key** — Without one you're limited to 5 requests per 30 seconds. Request a free key at https://nvd.nist.gov/developers/request-an-api-key

**GitHub token** — Required for the GitHub Advisories source. Create a personal access token at https://github.com/settings/tokens — no scopes are needed, just a basic token.

### Gmail SMTP

If using Gmail, you'll need an App Password (not your regular password):

1. Enable 2FA on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Create an app password for "Mail"
4. Use that 16-character password as `SMTP_PASSWORD`

## Usage

```bash
# Single check — fetch feeds, alert on new CVEs, exit
python main.py

# Daemon mode — run continuously
python main.py --daemon

# Verify SMTP is working
python main.py --test-email

# Check how many CVEs have been tracked
python main.py --stats
```

### Docker

```bash
docker compose up -d
```

Or without Compose:

```bash
docker build -t zero-day-alerts .
docker run -d \
  --name zero-day-alerts \
  --env-file .env \
  -v ./data:/app/data \
  zero-day-alerts
```

### Cron (alternative to daemon mode)

If you prefer cron over the built-in daemon:

```cron
*/5 * * * * cd /path/to/zero-day-alerts && python main.py >> /var/log/zero-day-alerts.log 2>&1
```

## Configuration

All configuration is via environment variables (or `.env` file):

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | `300` | How often to check feeds (daemon mode) |
| `DB_PATH` | `./data/seen.db` | SQLite database location |
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_USE_TLS` | `true` | Use STARTTLS |
| `EMAIL_FROM` | — | Sender address |
| `EMAIL_TO` | — | Comma-separated recipient addresses |
| `MIN_SEVERITY` | `HIGH` | Minimum severity to alert on: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `ENABLE_NVD` | `true` | Enable NVD source |
| `ENABLE_CISA_KEV` | `true` | Enable CISA KEV source |
| `ENABLE_GITHUB_ADVISORIES` | `true` | Enable GitHub Advisories source |
| `NVD_API_KEY` | — | NVD API key (raises rate limit) |
| `GITHUB_TOKEN` | — | GitHub personal access token |

## Email format

Alerts are sent as multipart emails with both HTML and plain-text versions. The HTML version includes color-coded severity badges and a `KEV` tag for entries in the CISA Known Exploited Vulnerabilities catalog.

## Project structure

```
zero-day-alerts/
├── main.py           # Entry point, CLI, scheduler
├── sources.py        # Feed fetchers (NVD, CISA KEV, GitHub)
├── storage.py        # SQLite tracking layer
├── notifier.py       # Email formatting and SMTP delivery
├── config.py         # Environment-based configuration
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── LICENSE
```

## License

MIT
