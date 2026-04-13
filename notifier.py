"""
Email alert sender via SMTP.
"""

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
    rows = ""
    for e in entries:
        color = SEVERITY_COLORS.get(e["severity"], "#6b7280")
        kev_badge = ' <span style="background:#dc2626;color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;">KEV</span>' if e.get("kev") else ""
        refs_html = ""
        for ref in e.get("references", [])[:3]:
            refs_html += f'<a href="{ref}" style="color:#2563eb;font-size:12px;word-break:break-all;">{ref}</a><br>'

        rows += f"""
        <tr style="border-bottom:1px solid #e5e7eb;">
            <td style="padding:12px 8px;vertical-align:top;">
                <strong>{e["cve_id"]}</strong>{kev_badge}
            </td>
            <td style="padding:12px 8px;vertical-align:top;">
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">
                    {e["severity"]}{f" ({e['cvss_score']})" if e.get("cvss_score") else ""}
                </span>
            </td>
            <td style="padding:12px 8px;vertical-align:top;font-size:13px;">
                <strong>Affected:</strong> {e.get("affected", "Unknown")}<br>
                {e.get("summary", "")}<br>
                {refs_html}
            </td>
            <td style="padding:12px 8px;vertical-align:top;font-size:12px;color:#6b7280;">
                {e.get("source", "")}<br>
                {e.get("published", "")[:10]}
            </td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1f2937;margin:0;padding:0;">
        <div style="max-width:800px;margin:0 auto;padding:20px;">
            <div style="background:#0f172a;color:#fff;padding:16px 24px;border-radius:8px 8px 0 0;">
                <h2 style="margin:0;font-size:18px;">⚡ Zero-Day Alert — {len(entries)} New Vulnerabilit{"y" if len(entries) == 1 else "ies"}</h2>
            </div>
            <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;">
                <thead>
                    <tr style="background:#f9fafb;border-bottom:2px solid #e5e7eb;">
                        <th style="padding:10px 8px;text-align:left;font-size:12px;text-transform:uppercase;color:#6b7280;">CVE</th>
                        <th style="padding:10px 8px;text-align:left;font-size:12px;text-transform:uppercase;color:#6b7280;">Severity</th>
                        <th style="padding:10px 8px;text-align:left;font-size:12px;text-transform:uppercase;color:#6b7280;">Details</th>
                        <th style="padding:10px 8px;text-align:left;font-size:12px;text-transform:uppercase;color:#6b7280;">Source</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            <div style="padding:12px;font-size:11px;color:#9ca3af;text-align:center;">
                Sent by zero-day-alerts · 
                <a href="https://nvd.nist.gov/" style="color:#9ca3af;">NVD</a> · 
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" style="color:#9ca3af;">CISA KEV</a>
            </div>
        </div>
    </body>
    </html>
    """


def _build_plain(entries: list[dict]) -> str:
    lines = [f"ZERO-DAY ALERT — {len(entries)} New Vulnerabilities", "=" * 50, ""]
    for e in entries:
        kev = " [ACTIVELY EXPLOITED]" if e.get("kev") else ""
        lines.append(f"{e['cve_id']}  {e['severity']}{kev}")
        if e.get("cvss_score"):
            lines.append(f"  CVSS: {e['cvss_score']}")
        lines.append(f"  Affected: {e.get('affected', 'Unknown')}")
        lines.append(f"  {e.get('summary', '')}")
        for ref in e.get("references", [])[:3]:
            lines.append(f"  → {ref}")
        lines.append(f"  Source: {e.get('source', '')} | Published: {e.get('published', '')[:10]}")
        lines.append("")
    return "\n".join(lines)


def send_alert(config: Config, entries: list[dict]) -> bool:
    """Send an email alert for new vulnerability entries. Returns True on success."""
    if not entries:
        return True

    if not config.smtp_host or not config.email_to:
        logger.warning("SMTP not configured — printing alert to stdout")
        print(_build_plain(entries))
        return False

    msg = MIMEMultipart("alternative")

    crit_count = sum(1 for e in entries if e["severity"] == "CRITICAL")
    if crit_count:
        subject = f"🔴 {crit_count} CRITICAL — Zero-Day Alert ({len(entries)} total)"
    else:
        subject = f"⚠️ Zero-Day Alert — {len(entries)} New Vulnerabilities"

    msg["Subject"] = subject
    msg["From"] = config.email_from or config.smtp_user
    msg["To"] = ", ".join(config.email_to)

    msg.attach(MIMEText(_build_plain(entries), "plain"))
    msg.attach(MIMEText(_build_html(entries), "html"))

    try:
        if config.smtp_use_tls:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port)
            server.ehlo()
            server.starttls()
        else:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port)

        if config.smtp_user and config.smtp_password:
            server.login(config.smtp_user, config.smtp_password)

        server.sendmail(
            config.email_from or config.smtp_user,
            config.email_to,
            msg.as_string(),
        )
        server.quit()
        logger.info("Alert email sent to %s", config.email_to)
        return True

    except Exception as exc:
        logger.error("Failed to send email: %s", exc)
        return False
