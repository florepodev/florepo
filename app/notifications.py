"""E-mail alerts for new findings detected by (periodic) re-scans.

Flow: the worker snapshots a version's findings before scanning, `evaluate()` queues a Notification when the
new scan reports findings at/above the configured threshold, and `flush_pending()` batches all queued
notifications into a single e-mail per cycle.
"""
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from flask import current_app, render_template

from . import settings
from .extensions import db
from .models import SEVERITY_RANK, Notification, Vulnerability, utcnow

DEFAULTS = {
    "enabled": False,
    "recipients": [],
    "threshold": "HIGH",
    "only_new": True,          # only alert on findings that were not present in the previous scan
    "include_uploads": False,  # also alert on the first scan of newly uploaded / cached versions
    "repos": [],               # empty = all repositories
}
MAX_ATTEMPTS = 3
FLUSH_DELAY = timedelta(minutes=15)  # send at the latest after this, even while a re-scan batch is running


def get_config():
    return {**DEFAULTS, **(settings.get("alerts") or {})}


def smtp_configured():
    return bool(current_app.config["SMTP_HOST"])


def finding_keys(version_id):
    return {(v.vuln_id, v.pkg_name or "") for v in Vulnerability.query.filter_by(version_id=version_id)}


def evaluate(version, previous_keys, was_rescan):
    """Queue an alert for `version` if its fresh scan matches the alert rule. Caller commits."""
    cfg = get_config()
    if not cfg["enabled"] or not cfg["recipients"]:
        return None
    if not was_rescan and not cfg["include_uploads"]:
        return None
    repo = version.package.repository
    if cfg["repos"] and repo.name not in cfg["repos"]:
        return None
    threshold = SEVERITY_RANK.get(cfg["threshold"], SEVERITY_RANK["HIGH"])
    hits = [v for v in Vulnerability.query.filter_by(version_id=version.id)
            if SEVERITY_RANK.get(v.severity, 0) >= threshold]
    if cfg["only_new"]:
        hits = [v for v in hits if (v.vuln_id, v.pkg_name or "") not in previous_keys]
    if not hits:
        return None
    hits.sort(key=lambda v: (-SEVERITY_RANK.get(v.severity, 0), v.vuln_id))
    n = Notification(
        version_id=version.id, repo_name=repo.name, package_name=version.package.display_name,
        version_name=version.version, trigger="rescan" if was_rescan else "upload",
        max_severity=hits[0].severity,
        findings=[{"id": v.vuln_id, "severity": v.severity, "component": v.pkg_name,
                   "installed": v.installed_version, "fixed": v.fixed_version or None,
                   "title": (v.title or "")[:200]} for v in hits[:50]],
    )
    db.session.add(n)
    return n


def evaluate_malware(version, previous_status):
    """Queue an alert when ClamAV newly reports a version as infected (independent of the CVE threshold)."""
    cfg = get_config()
    if not cfg["enabled"] or not cfg["recipients"] or version.malware_status != "infected":
        return None
    if previous_status == "infected":
        return None
    repo = version.package.repository
    if cfg["repos"] and repo.name not in cfg["repos"]:
        return None
    found = ((version.meta or {}).get("malware") or {}).get("found") or []
    n = Notification(
        version_id=version.id, repo_name=repo.name, package_name=version.package.display_name,
        version_name=version.version, trigger="malware", max_severity="CRITICAL",
        findings=[{"id": f["signature"], "severity": "CRITICAL", "component": f["file"], "installed": "",
                   "fixed": None, "title": "Malware detected by ClamAV"} for f in found[:50]],
    )
    db.session.add(n)
    return n


def send_mail(recipients, subject, text, html=None):
    cfg = current_app.config
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    security = cfg["SMTP_SECURITY"].lower()
    if security == "ssl":
        smtp = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=cfg["SMTP_TIMEOUT"],
                                context=ssl.create_default_context())
    else:
        smtp = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=cfg["SMTP_TIMEOUT"])
    with smtp:
        if security == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if cfg["SMTP_USERNAME"]:
            smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
        smtp.send_message(msg)


def _base_url():
    return current_app.config["BASE_URL"] or "http://localhost:8080"


def render_alert(notifications):
    worst = max((n.max_severity for n in notifications), key=lambda s: SEVERITY_RANK.get(s, 0))
    total = sum(len(n.findings or []) for n in notifications)
    infected = [n for n in notifications if n.trigger == "malware"]
    if infected:
        subject = (f"[Florepo] MALWARE detected in {len(infected)} artifact{'s' if len(infected) != 1 else ''}"
                   + (f" (+ {len(notifications) - len(infected)} with new vulnerabilities)"
                      if len(infected) != len(notifications) else ""))
    else:
        subject = (f"[Florepo] {total} new {worst.lower()}+ finding{'s' if total != 1 else ''} "
                   f"in {len(notifications)} artifact{'s' if len(notifications) != 1 else ''}")
    ctx = {"notifications": notifications, "base_url": _base_url(), "total": total, "worst": worst,
           "threshold": get_config()["threshold"]}
    return subject, render_template("email/alert.txt", **ctx), render_template("email/alert.html", **ctx)


def flush_pending(force=False):
    """Send all queued alerts as one e-mail. Returns the number of notifications sent."""
    pending = (Notification.query.filter(Notification.sent_at.is_(None), Notification.attempts < MAX_ATTEMPTS)
               .order_by(Notification.created_at).all())
    if not pending:
        return 0
    if not force and pending[0].created_at > utcnow() - FLUSH_DELAY and _scans_running():
        return 0  # wait until the current scan batch is finished (one mail instead of many)
    cfg = get_config()
    recipients = cfg["recipients"]
    if not smtp_configured() or not recipients:
        for n in pending:
            n.attempts = MAX_ATTEMPTS
            n.error = "SMTP not configured" if not smtp_configured() else "no recipients configured"
        db.session.commit()
        return 0
    subject, text, html = render_alert(pending)
    try:
        send_mail(recipients, subject, text, html)
    except Exception as exc:  # network / auth errors -> retry next cycle
        for n in pending:
            n.attempts += 1
            n.error = str(exc)[:1000]
        db.session.commit()
        current_app.logger.error("sending alert e-mail failed: %s", exc)
        return 0
    now = utcnow()
    for n in pending:
        n.sent_at, n.error, n.recipients = now, None, ", ".join(recipients)
        n.attempts += 1
    db.session.commit()
    current_app.logger.info("alert e-mail sent to %s (%d artifacts)", recipients, len(pending))
    return len(pending)


def _scans_running():
    from .models import Version
    return Version.query.filter(Version.scan_status.in_(["pending", "running"])).first() is not None
