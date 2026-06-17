import os
import json
import re

DEFAULT_TEMPLATES = {
    "webapp_alert": {
        "subject": "[Vigil] Web App Status Changed — {domain}",
        "body_html": """<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#fff">
<h2 style="color:#3b82f6">Web App Status Alert</h2>
<p><strong>{domain}</strong> status changed to <strong>{status}</strong>.</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0">
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600;width:40%">Name</td><td style="padding:8px;border:1px solid #e2e8f0">{domain}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Status</td><td style="padding:8px;border:1px solid #e2e8f0">{status}</td></tr>
</table>
<p style="color:#64748b;font-size:12px">Sent by Vigil Monitoring</p>
</div>""",
        "body_text": "Web App Status Alert — {domain}\n\nName: {domain}\nStatus: {status}\n\nSent by Vigil Monitoring",
    },
    "ssl_alert": {
        "subject": "[Vigil] SSL Certificate Expiring Soon — {domain}",
        "body_html": """<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#fff">
<h2 style="color:#ef4444">SSL Certificate Alert</h2>
<p>The SSL certificate for <strong>{domain}</strong> is expiring soon.</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0">
<tr><td colspan="2" style="padding:8px;border:1px solid #e2e8f0;font-weight:700;font-size:14px">SSL Certificate</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600;width:40%">Status</td><td style="padding:8px;border:1px solid #e2e8f0">{status}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expiry</td><td style="padding:8px;border:1px solid #e2e8f0">{ssl_expiry}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Days Left</td><td style="padding:8px;border:1px solid #e2e8f0">{ssl_days_left}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Issuer</td><td style="padding:8px;border:1px solid #e2e8f0">{issuer}</td></tr>
<tr><td colspan="2" style="padding:12px 8px 4px;border:none;font-weight:700;font-size:14px">Domain Registration</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expiry</td><td style="padding:8px;border:1px solid #e2e8f0">{domain_expiry}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Days Left</td><td style="padding:8px;border:1px solid #e2e8f0">{domain_days_left}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Registrar</td><td style="padding:8px;border:1px solid #e2e8f0">{registrar}</td></tr>
</table>
<p style="color:#64748b;font-size:12px">Sent by Vigil Monitoring</p>
</div>""",
        "body_text": "SSL Certificate Alert — {domain}\n\nSSL Certificate\nStatus: {status}\nExpiry: {ssl_expiry}\nDays Left: {ssl_days_left}\nIssuer: {issuer}\n\nDomain Registration\nExpiry: {domain_expiry}\nDays Left: {domain_days_left}\nRegistrar: {registrar}\n\nSent by Vigil Monitoring",
    },
    "domain_alert": {
        "subject": "[Vigil] Domain Expiring Soon — {domain}",
        "body_html": """<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#fff">
<h2 style="color:#f97316">Domain Expiry Alert</h2>
<p>The domain <strong>{domain}</strong> is expiring soon.</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0">
<tr><td colspan="2" style="padding:8px;border:1px solid #e2e8f0;font-weight:700;font-size:14px">Domain Registration</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600;width:40%">Status</td><td style="padding:8px;border:1px solid #e2e8f0">{status}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expiry</td><td style="padding:8px;border:1px solid #e2e8f0">{domain_expiry}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Days Left</td><td style="padding:8px;border:1px solid #e2e8f0">{domain_days_left}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Registrar</td><td style="padding:8px;border:1px solid #e2e8f0">{registrar}</td></tr>
<tr><td colspan="2" style="padding:12px 8px 4px;border:none;font-weight:700;font-size:14px">SSL Certificate</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Status</td><td style="padding:8px;border:1px solid #e2e8f0">{status}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expiry</td><td style="padding:8px;border:1px solid #e2e8f0">{ssl_expiry}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Days Left</td><td style="padding:8px;border:1px solid #e2e8f0">{ssl_days_left}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Issuer</td><td style="padding:8px;border:1px solid #e2e8f0">{issuer}</td></tr>
</table>
<p style="color:#64748b;font-size:12px">Sent by Vigil Monitoring</p>
</div>""",
        "body_text": "Domain Expiry Alert — {domain}\n\nDomain Registration\nStatus: {status}\nExpiry: {domain_expiry}\nDays Left: {domain_days_left}\nRegistrar: {registrar}\n\nSSL Certificate\nStatus: {status}\nExpiry: {ssl_expiry}\nDays Left: {ssl_days_left}\nIssuer: {issuer}\n\nSent by Vigil Monitoring",
    },
    "check_complete": {
        "subject": "[Vigil] Scheduled Check Complete — {date}",
        "body_html": """<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#fff">
<h2 style="color:#3b82f6">Check Complete</h2>
<p>Scheduled check completed at {date}.</p>
<h3 style="color:#64748b;margin:20px 0 8px">SSL Certificate Health</h3>
<table style="border-collapse:collapse;width:100%;margin:8px 0 16px">
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Total</td><td style="padding:8px;border:1px solid #e2e8f0">{ssl_total}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Healthy</td><td style="padding:8px;border:1px solid #e2e8f0;color:#22c55e">{ssl_healthy}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Warning</td><td style="padding:8px;border:1px solid #e2e8f0;color:#eab308">{ssl_warning}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expired</td><td style="padding:8px;border:1px solid #e2e8f0;color:#ef4444">{ssl_expired}</td></tr>
</table>
<h3 style="color:#64748b;margin:16px 0 8px">Domain Registration Health</h3>
<table style="border-collapse:collapse;width:100%;margin:8px 0 16px">
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Total</td><td style="padding:8px;border:1px solid #e2e8f0">{domain_total}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Healthy</td><td style="padding:8px;border:1px solid #e2e8f0;color:#22c55e">{domain_healthy}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Warning</td><td style="padding:8px;border:1px solid #e2e8f0;color:#eab308">{domain_warning}</td></tr>
<tr><td style="padding:8px;border:1px solid #e2e8f0;font-weight:600">Expired</td><td style="padding:8px;border:1px solid #e2e8f0;color:#ef4444">{domain_expired}</td></tr>
</table>
<p style="color:#64748b;font-size:12px">Sent by Vigil Monitoring</p>
</div>""",
        "body_text": "Check Complete\n\nScheduled check completed at {date}.\n\nSSL Certificate Health\nTotal: {ssl_total}\nHealthy: {ssl_healthy}\nWarning: {ssl_warning}\nExpired: {ssl_expired}\n\nDomain Registration Health\nTotal: {domain_total}\nHealthy: {domain_healthy}\nWarning: {domain_warning}\nExpired: {domain_expired}\n\nSent by Vigil Monitoring",
    },
}


def get_default_templates():
    return DEFAULT_TEMPLATES


def render_template(template, variables):
    """Render a template string with variables (safe substitution only)."""
    def _replace(m):
        return str(variables.get(m.group(1), m.group(0)))
    return re.sub(r'\{(\w+)\}', _replace, template)


def render_email(template_name, variables, custom_templates=None):
    """Render an email template, falling back to defaults."""
    tpl = dict(DEFAULT_TEMPLATES.get(template_name, {}))
    if custom_templates and template_name in custom_templates:
        tpl.update({k: v for k, v in custom_templates[template_name].items() if v})
    subject = render_template(tpl.get("subject", ""), variables)
    body_html = render_template(tpl.get("body_html", ""), variables)
    body_text = render_template(tpl.get("body_text", ""), variables)
    return subject, body_html, body_text
