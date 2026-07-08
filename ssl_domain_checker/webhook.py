import ipaddress
import logging
from urllib.parse import urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)

_PRIVATE_NETLOCS = frozenset({'localhost', '127.0.0.1', '::1', '0.0.0.0'})
_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('fc00::/7'),
]


def validate_webhook_url(url):
    """Validate that a webhook URL is safe (HTTPS, not a private/internal host)."""
    parsed = urlparse(url)
    if parsed.scheme != 'https' or not parsed.netloc:
        return False
    host = parsed.hostname or ''
    if host in _PRIVATE_NETLOCS:
        return False
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in net for net in _PRIVATE_NETS):
            return False
    except ValueError:
        pass
    return True

_STATUS_COLORS = {
    "expired": "#ef4444",
    "critical": "#f97316",
    "warning": "#eab308",
    "caution": "#f59e0b",
    "watch": "#fb923c",
    "error": "#ef4444",
    "healthy": "#22c55e",
}


def send_webhook_alerts(domain_name, status, ssl_days_left, domain_days_left, settings, domain_data=None):
    errors = []
    slack_url = settings.get('slack_webhook_url', '')
    if slack_url and settings.get('slack_enabled'):
        try:
            _send_slack(slack_url, domain_name, status, ssl_days_left, domain_days_left, domain_data)
        except Exception as e:
            errors.append(f"Slack: {e}")
    zulip_url = settings.get('zulip_webhook_url', '')
    if zulip_url and settings.get('zulip_enabled'):
        try:
            _send_zulip(zulip_url, domain_name, status, ssl_days_left, domain_days_left, domain_data)
        except Exception as e:
            errors.append(f"Zulip: {e}")
    return errors


def _send_slack(webhook_url, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    if not validate_webhook_url(webhook_url):
        raise ValueError("Blocked: unsafe webhook URL")
    color = _STATUS_COLORS.get(status, "#64748b")
    fields = [
        {"type": "mrkdwn", "text": f"*Domain:*\n{domain_name}"},
        {"type": "mrkdwn", "text": f"*Status:*\n{status}"},
    ]
    if ssl_days_left is not None:
        fields.append({"type": "mrkdwn", "text": f"*SSL Days Left:*\n{ssl_days_left}"})
    if domain_days_left is not None:
        fields.append({"type": "mrkdwn", "text": f"*Domain Days Left:*\n{domain_days_left}"})

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"\u26a0\ufe0f Vigil Alert: {domain_name}"}},
        {"type": "section", "fields": fields},
    ]
    resp = requests.post(webhook_url, json={"blocks": blocks}, timeout=10, verify=True)
    if resp.status_code not in (200, 204):
        raise Exception(f"HTTP {resp.status_code}")


def send_test_webhook(webhook_type, webhook_url):
    """Send a test message to a webhook."""
    if not validate_webhook_url(webhook_url):
        raise ValueError("Blocked: unsafe webhook URL")
    if webhook_type == 'slack':
        payload = {"blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ Vigil Test Notification"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "This is a test from Vigil SSL Checker.\nIf you see this, your Slack webhook is configured correctly."}},
        ]}
        resp = requests.post(webhook_url, json=payload, timeout=10, verify=True)
    elif webhook_type == 'zulip':
        parsed = urlparse(webhook_url)
        qs = parse_qs(parsed.query)
        email = (qs.get('email') or [''])[0]
        api_key = (qs.get('api_key') or [''])[0]
        stream = (qs.get('stream') or [''])[0]
        topic = (qs.get('topic') or ['Vigil Alerts'])[0]
        if not email:
            raise ValueError("Zulip email missing in webhook URL")
        if not api_key:
            raise ValueError("Zulip API key missing in webhook URL")
        if not stream:
            raise ValueError("Zulip stream missing in webhook URL")
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        resp = requests.post(base_url, auth=(email, api_key), data={
            "type": "stream",
            "to": stream,
            "topic": topic,
            "content": "**✅ Vigil Test Notification**\n\nThis is a test from Vigil SSL Checker. If you see this, your Zulip webhook is configured correctly.",
        }, timeout=10, verify=True)
    else:
        raise ValueError(f"Unknown webhook type: {webhook_type}")
    if resp.status_code not in (200, 204):
        raise Exception(f"HTTP {resp.status_code}")


def _send_zulip(webhook_url, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    if not validate_webhook_url(webhook_url):
        raise ValueError("Blocked: unsafe webhook URL")
    parsed = urlparse(webhook_url)
    qs = parse_qs(parsed.query)
    email = (qs.get('email') or [''])[0]
    api_key = (qs.get('api_key') or [''])[0]
    stream = (qs.get('stream') or [''])[0]
    topic = (qs.get('topic') or ['Vigil Alerts'])[0]
    if not email:
        raise ValueError("Zulip email missing in webhook URL")
    if not api_key:
        raise ValueError("Zulip API key missing in webhook URL")
    if not stream:
        raise ValueError("Zulip stream missing in webhook URL")
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    ssl_line = f"SSL Days Left: {ssl_days_left}\n" if ssl_days_left is not None else ""
    domain_line = f"Domain Days Left: {domain_days_left}\n" if domain_days_left is not None else ""
    content = (
        f"**Vigil Alert: {domain_name}**\n"
        f"Status: {status}\n"
        f"{ssl_line}{domain_line}"
    )
    resp = requests.post(base_url, auth=(email, api_key), data={
        "type": "stream",
        "to": stream,
        "topic": topic,
        "content": content,
    }, timeout=10, verify=True)
    if resp.status_code != 200:
        raise Exception(f"HTTP {resp.status_code}")
