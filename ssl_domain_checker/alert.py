import os
import logging
import smtplib
import json
import ssl as ssl_mod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
logger = logging.getLogger(__name__)

import email_templates
import webhook
import models

_SMTP_ENV_KEYS = frozenset(['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASS', 'RECIPIENT_MAIL'])


def _smtp_from_env():
    host = os.environ.get('SMTP_HOST', '').strip()
    if not host:
        return None
    return {
        'smtp_server': host,
        'smtp_port': int(os.environ.get('SMTP_PORT', '587')),
        'smtp_email': os.environ.get('SMTP_USER', ''),
        'smtp_password': os.environ.get('SMTP_PASS', ''),
        'alert_emails': os.environ.get('RECIPIENT_MAIL', ''),
        'smtp_secure': os.environ.get('SMTP_SECURE', 'true').lower() in ('1', 'true', 'yes'),
    }


def _resolve_smtp_config(settings):
    env_cfg = _smtp_from_env()
    if env_cfg is not None:
        return env_cfg
    return settings


def send_alerts(domain_name, status, ssl_days_left, domain_days_left, settings, domain_data=None):
    errors = []
    smtp_cfg = _resolve_smtp_config(settings)
    if smtp_cfg.get("smtp_enabled", True) and smtp_cfg.get("smtp_email") and smtp_cfg.get("smtp_password"):
        try:
            _send_smtp(domain_name, status, ssl_days_left, domain_days_left, smtp_cfg, settings, domain_data)
        except Exception as e:
            errors.append(f"SMTP: {e}")
    webhook_errors = webhook.send_webhook_alerts(
        domain_name, status, ssl_days_left, domain_days_left, settings, domain_data
    )
    errors.extend(webhook_errors)
    return errors


def _get_custom_templates(settings):
    raw = settings.get("email_templates", "{}")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        for tpl in ("ssl_alert", "domain_alert", "webapp_alert", "check_complete"):
            if tpl in data:
                entry = data[tpl]
                if not isinstance(entry, dict) or not any(k in entry for k in ("subject", "body_html", "body_text")):
                    return {}
        return data
    except Exception:
        return {}


def _build_alert_variables(domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    d = domain_data or {}
    return {
        "domain": domain_name,
        "status": status,
        "days_left": ssl_days_left if ssl_days_left is not None else (domain_days_left if domain_days_left is not None else "N/A"),
        "ssl_days_left": ssl_days_left if ssl_days_left is not None else "N/A",
        "domain_days_left": domain_days_left if domain_days_left is not None else "N/A",
        "ssl_expiry": d.get("ssl_expiry", "N/A"),
        "domain_expiry": d.get("domain_expiry", "N/A"),
        "issuer": d.get("ssl_issuer", "N/A"),
        "registrar": d.get("manual_registrar", d.get("domain_registrar", "N/A")),
        "url": d.get("url", "N/A"),
        "status_code": str(d.get("status_code", "N/A")),
        "date": models.to_local_time(models.timezone_now_str()),
    }


def _send_smtp(domain_name, status, ssl_days_left, domain_days_left, smtp_cfg, settings, domain_data=None):
    custom = _get_custom_templates(settings)
    variables = _build_alert_variables(domain_name, status, ssl_days_left, domain_days_left, domain_data)

    if ssl_days_left is None and domain_days_left is None:
        tpl_name = "webapp_alert"
    else:
        is_ssl = ssl_days_left is not None and (domain_days_left is None or ssl_days_left < domain_days_left)
        tpl_name = "ssl_alert" if is_ssl else "domain_alert"

    if tpl_name in custom:
        subject = email_templates.render_template(custom[tpl_name].get("subject", ""), variables)
        body_html = email_templates.render_template(custom[tpl_name].get("body_html", ""), variables)
        body_text = email_templates.render_template(custom[tpl_name].get("body_text", ""), variables)
    else:
        subject, body_html, body_text = email_templates.render_email(tpl_name, variables)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_cfg["smtp_email"]

    recipients = [r.strip() for r in smtp_cfg.get("alert_emails", "").split(",") if r.strip()]
    if not recipients:
        recipients = [smtp_cfg["smtp_email"]]
    msg["To"] = ", ".join(recipients)

    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    _send_email(smtp_cfg, msg)


def _send_email(smtp_cfg, msg):
    port = int(smtp_cfg["smtp_port"])
    secure = smtp_cfg.get("smtp_secure", True)
    if port == 465:
        with smtplib.SMTP_SSL(smtp_cfg["smtp_server"], port, timeout=10) as server:
            server.login(smtp_cfg["smtp_email"], smtp_cfg["smtp_password"])
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_cfg["smtp_server"], port, timeout=10) as server:
            if secure:
                server.starttls(context=ssl_mod.create_default_context())
            server.login(smtp_cfg["smtp_email"], smtp_cfg["smtp_password"])
            server.send_message(msg)


def send_check_complete_summary(smtp_cfg, settings,
                                ssl_total, ssl_healthy, ssl_warning, ssl_expired,
                                domain_total, domain_healthy, domain_warning, domain_expired):
    if not smtp_cfg.get("smtp_email"):
        return

    custom = _get_custom_templates(settings)
    variables = {
        "ssl_total": ssl_total,
        "ssl_healthy": ssl_healthy,
        "ssl_warning": ssl_warning,
        "ssl_expired": ssl_expired,
        "domain_total": domain_total,
        "domain_healthy": domain_healthy,
        "domain_warning": domain_warning,
        "domain_expired": domain_expired,
        "date": models.to_local_time(models.timezone_now_str()),
    }

    if "check_complete" in custom:
        subject = email_templates.render_template(custom["check_complete"].get("subject", ""), variables)
        body_html = email_templates.render_template(custom["check_complete"].get("body_html", ""), variables)
        body_text = email_templates.render_template(custom["check_complete"].get("body_text", ""), variables)
    else:
        subject, body_html, body_text = email_templates.render_email("check_complete", variables)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_cfg["smtp_email"]
        recipients = [r.strip() for r in smtp_cfg.get("alert_emails", "").split(",") if r.strip()]
        if not recipients:
            recipients = [smtp_cfg["smtp_email"]]
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        _send_email(smtp_cfg, msg)
    except Exception as e:
        logger.warning("Failed to send check summary email: %s", e)


def test_smtp(smtp_cfg, settings):
    _send_smtp("test.example.com", "test", 30, 30, smtp_cfg, settings)
