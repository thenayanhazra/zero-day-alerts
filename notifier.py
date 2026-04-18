"""Email notification delivery."""
from __future__ import annotations

import html
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import Config

logger = logging.getLogger("zeroday.notifier")

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}


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


def send_alert(config: Config, entries: list[dict]) -> bool:
    if not entries:
        return True
    if not config.smtp_host or not config.email_to:
        logger.warning("SMTP not configured; printing alert to stdout")
        print(_build_plain(entries))
        return False

    crit_count = sum(1 for entry in entries if entry.get("severity") == "CRITICAL")
    if crit_count:
        subject = f"{crit_count} CRITICAL — Zero-Day Alert ({len(entries)} total)"
    else:
        subject = f"Zero-Day Alert — {len(entries)} New Vulnerabilities"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.email_from or config.smtp_user
    msg["To"] = ", ".join(config.email_to)
    msg.attach(MIMEText(_build_plain(entries), "plain", "utf-8"))
    msg.attach(MIMEText(_build_html(entries), "html", "utf-8"))

    try:
        server: smtplib.SMTP
        if config.smtp_use_ssl:
            server = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=config.smtp_timeout)
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
        logger.info("Alert email sent to %s", config.email_to)
        return True
    except Exception as exc:
        logger.error("Failed to send email: %s", exc)
        return False
