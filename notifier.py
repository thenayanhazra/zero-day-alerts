"""Notification delivery: email (SMTP), SMS and WhatsApp (Twilio)."""
from __future__ import annotations

import html
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

from config import Config

logger = logging.getLogger("zeroday.notifier")

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}


# ---------------------------------------------------------------------------
# Plain / HTML builders (shared by email and stdout fallback)
# ---------------------------------------------------------------------------

def _build_html(entries: list[dict]) -> str:
    rows = []
    for entry in entries:
        color = SEVERITY_COLORS.get(entry.get("severity", ""), "#6b7280")
        kev_badge = " <strong>KEV</strong>" if entry.get("kev") else ""
        refs_html = "".join(
            f'<li><a href="{html.escape(ref, quote=True)}">{html.escape(ref)}</a></li>'
            for ref in entry.get("references", [])[:3]
        )
        rows.append(
            f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin:12px 0;">
              <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
                <div>
                  <div style="font-size:18px;font-weight:700;">{html.escape(entry.get('cve_id', 'UNKNOWN'))}{kev_badge}</div>
                  <div style="margin-top:6px;color:#374151;">Affected: {html.escape(entry.get('affected', 'Unknown'))}</div>
                  <div style="margin-top:8px;color:#111827;">{html.escape(entry.get('summary', ''))}</div>
                </div>
                <div style="white-space:nowrap;background:{color};color:white;padding:6px 10px;border-radius:999px;font-weight:700;">
                  {html.escape(entry.get('severity', 'UNKNOWN'))}
                  {f" ({entry['cvss_score']})" if entry.get('cvss_score') is not None else ''}
                </div>
              </div>
              <div style="margin-top:10px;color:#6b7280;">Source: {html.escape(entry.get('source', ''))} | Published: {html.escape(str(entry.get('published', ''))[:10])}</div>
              <ul>{refs_html}</ul>
            </div>
            """
        )

    return f"""
    <html>
      <body style="font-family:Arial,sans-serif;max-width:900px;margin:auto;padding:16px;">
        <h2>Zero-Day Alert — {len(entries)} New Vulnerabilit{'y' if len(entries) == 1 else 'ies'}</h2>
        {''.join(rows)}
      </body>
    </html>
    """


def _build_plain(entries: list[dict]) -> str:
    lines = [f"ZERO-DAY ALERT — {len(entries)} New Vulnerabilities", "=" * 60, ""]
    for entry in entries:
        kev = " [KEV]" if entry.get("kev") else ""
        lines.append(f"{entry.get('cve_id', 'UNKNOWN')} {entry.get('severity', 'UNKNOWN')}{kev}")
        if entry.get("cvss_score") is not None:
            lines.append(f"  CVSS: {entry['cvss_score']}")
        lines.append(f"  Affected: {entry.get('affected', 'Unknown')}")
        lines.append(f"  Summary: {entry.get('summary', '')}")
        for ref in entry.get("references", [])[:3]:
            lines.append(f"  Ref: {ref}")
        lines.append(f"  Source: {entry.get('source', '')} | Published: {str(entry.get('published', ''))[:10]}")
        lines.append("")
    return "\n".join(lines)


def _build_sms(entries: list[dict]) -> str:
    """Compact text for SMS/WhatsApp (no hard size limit but kept tight)."""
    lines = [f"ZERO-DAY ALERT: {len(entries)} CVE{'s' if len(entries) != 1 else ''}"]
    for entry in entries[:5]:
        kev = " [KEV]" if entry.get("kev") else ""
        score = f" CVSS:{entry['cvss_score']}" if entry.get("cvss_score") is not None else ""
        lines.append(f"{entry.get('cve_id', '?')} {entry.get('severity', '?')}{score}{kev}")
        summary = entry.get("summary", "")
        if summary:
            lines.append(summary[:140])
    if len(entries) > 5:
        lines.append(f"...and {len(entries) - 5} more")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def _send_email(config: Config, entries: list[dict]) -> bool:
    crit_count = sum(1 for e in entries if e.get("severity") == "CRITICAL")
    subject = (
        f"{crit_count} CRITICAL — Zero-Day Alert ({len(entries)} total)"
        if crit_count
        else f"Zero-Day Alert — {len(entries)} New Vulnerabilities"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.email_from or config.smtp_user
    msg["To"] = ", ".join(config.email_to)
    msg.attach(MIMEText(_build_plain(entries), "plain", "utf-8"))
    msg.attach(MIMEText(_build_html(entries), "html", "utf-8"))

    try:
        if config.smtp_use_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=config.smtp_timeout)
        else:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.smtp_timeout)
        with server:
            server.ehlo()
            if config.smtp_use_tls and not config.smtp_use_ssl:
                server.starttls()
                server.ehlo()
            if config.smtp_user and config.smtp_password:
                server.login(config.smtp_user, config.smtp_password)
            server.sendmail(config.email_from or config.smtp_user, config.email_to, msg.as_string())
        logger.info("Email sent to %s", config.email_to)
        return True
    except Exception as exc:
        logger.error("Email delivery failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Twilio (SMS + WhatsApp)
# ---------------------------------------------------------------------------

def _twilio_send(config: Config, to: str, from_: str, body: str) -> bool:
    url = f"https://api.twilio.com/2010-04-01/Accounts/{config.twilio_account_sid}/Messages.json"
    try:
        resp = requests.post(
            url,
            data={"To": to, "From": from_, "Body": body},
            auth=(config.twilio_account_sid, config.twilio_auth_token),
            timeout=20,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.error("Twilio message to %s failed: %s", to, exc)
        return False


def _send_sms(config: Config, entries: list[dict]) -> bool:
    body = _build_sms(entries)
    results = [_twilio_send(config, to, config.twilio_from, body) for to in config.sms_to]
    if results:
        logger.info("SMS sent to %d recipient(s)", sum(results))
    return all(results)


def _send_whatsapp(config: Config, entries: list[dict]) -> bool:
    body = _build_sms(entries)
    from_ = f"whatsapp:{config.twilio_from}"
    results = [_twilio_send(config, f"whatsapp:{to}", from_, body) for to in config.whatsapp_to]
    if results:
        logger.info("WhatsApp sent to %d recipient(s)", sum(results))
    return all(results)


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def notify(config: Config, entries: list[dict]) -> bool:
    """Send alerts on all configured channels. Returns True only if all succeed."""
    if not entries:
        return True

    results: list[bool] = []

    if config.smtp_host and config.email_to:
        results.append(_send_email(config, entries))

    _twilio_ready = config.twilio_account_sid and config.twilio_auth_token and config.twilio_from
    if _twilio_ready and config.sms_to:
        results.append(_send_sms(config, entries))
    if _twilio_ready and config.whatsapp_to:
        results.append(_send_whatsapp(config, entries))

    if not results:
        logger.warning("No notification channels configured; printing to stdout")
        print(_build_plain(entries))
        return False

    return all(results)
