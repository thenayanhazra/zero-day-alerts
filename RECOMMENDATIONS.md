# Zero-Day-Alerts: Improvement Recommendations

This project is already lean and practical. The highest-impact next steps are mostly around reliability, observability, and safer operations.

## Priority 1 (Do next)

1. **Add source-level retry/backoff + jitter**
   - Wrap external API calls (NVD, CISA, GitHub, Twilio) with bounded retries and exponential backoff.
   - Benefit: fewer false negatives during short outages or rate-limit spikes.

2. **Introduce structured logging**
   - Emit JSON logs with keys like `source`, `cve_id`, `severity`, `delivery_channel`, and `run_id`.
   - Benefit: easier debugging and alert correlation in production log tooling.

3. **Expand test coverage for storage and notifier paths**
   - Add tests for `Storage.upsert_alert`, `mark_alert_sent/failed`, and channel dispatch behavior in `notify`.
   - Benefit: protects dedupe/alert-state logic from regressions.

## Priority 2 (Strongly recommended)

4. **Add idempotency and retry policy for notification delivery**
   - Distinguish transient vs permanent failures for email/Twilio sends.
   - Add capped retry attempts and a backoff schedule before moving alerts to `failed`.

5. **Harden configuration validation at startup**
   - Validate incompatible/missing settings (e.g., `SMTP_USE_SSL=true` with invalid port, Twilio partial credentials).
   - Fail fast with actionable errors.

6. **Add metrics endpoint or periodic metrics summary**
   - Track counts like fetch duration, source failures, alerts sent, and pending queue size.
   - Helps detect degraded feeds and notification issues early.

## Priority 3 (Nice to have)

7. **Move DB writes in hot paths into small transactions/batches**
   - Particularly when processing large NVD windows.

8. **Add feed-specific freshness checks**
   - Emit warnings when a source has not produced updates in an expected time window.

9. **Introduce CI checks**
   - Add a workflow for `pytest`, formatting, and linting on pull requests.

## Contributor Mapping

- Added `.mailmap` so historical commits authored as `Claude <noreply@anthropic.com>` are attributed to `Nayan <nayanmanihazra@gmail.com>` in contributor reports.
