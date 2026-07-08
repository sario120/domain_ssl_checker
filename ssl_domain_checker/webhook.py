import ipaddress
import json
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
    discord_url = settings.get('discord_webhook_url', '')
    if discord_url and settings.get('discord_enabled'):
        try:
            _send_discord(discord_url, domain_name, status, ssl_days_left, domain_days_left, domain_data)
        except Exception as e:
            errors.append(f"Discord: {e}")
    telegram_token = settings.get('telegram_bot_token', '')
    telegram_chat = settings.get('telegram_chat_id', '')
    if telegram_token and telegram_chat and settings.get('telegram_enabled'):
        try:
            _send_telegram(telegram_token, telegram_chat, domain_name, status, ssl_days_left, domain_days_left, domain_data)
        except Exception as e:
            errors.append(f"Telegram: {e}")
    teams_url = settings.get('teams_webhook_url', '')
    if teams_url and settings.get('teams_enabled'):
        try:
            _send_teams(teams_url, domain_name, status, ssl_days_left, domain_days_left, domain_data)
        except Exception as e:
            errors.append(f"Teams: {e}")
    generic_raw = settings.get('generic_webhooks', '[]')
    if generic_raw:
        try:
            generic_list = json.loads(generic_raw) if isinstance(generic_raw, str) else generic_raw
            for gw in generic_list:
                if not gw.get('enabled') or not gw.get('url'):
                    continue
                try:
                    _send_generic(gw, domain_name, status, ssl_days_left, domain_days_left, domain_data)
                except Exception as e:
                    errors.append(f"Generic({gw.get('name', '?')}): {e}")
        except (json.JSONDecodeError, TypeError):
            errors.append("Generic webhooks: invalid JSON configuration")
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


def send_test_webhook(webhook_type, webhook_url, settings=None):
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
    elif webhook_type == 'discord':
        payload = {"embeds": [{
            "title": "✅ Vigil Test Notification",
            "description": "This is a test from Vigil SSL Checker. If you see this, your Discord webhook is configured correctly.",
            "color": 5763719,
        }]}
        resp = requests.post(webhook_url, json=payload, timeout=10, verify=True)
    elif webhook_type == 'telegram':
        token = webhook_url
        chat_id = settings.get('telegram_chat_id', '') if settings else ''
        if not chat_id:
            raise ValueError("Telegram chat ID not configured")
        text = "✅ *Vigil Test Notification*\n\nThis is a test from Vigil SSL Checker. If you see this, your Telegram bot is configured correctly."
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10, verify=True
        )
    elif webhook_type == 'teams':
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "Vigil Test Notification",
            "title": "✅ Vigil Test Notification",
            "text": "This is a test from Vigil SSL Checker. If you see this, your Teams webhook is configured correctly.",
        }
        resp = requests.post(webhook_url, json=payload, timeout=10, verify=True)
    elif webhook_type == 'generic':
        payload = webhook_url
        method = 'POST'
        headers = {}
        resp = requests.request(method, webhook_url, headers=headers, data=payload, timeout=10, verify=True)
    else:
        raise ValueError(f"Unknown webhook type: {webhook_type}")
    if resp.status_code not in (200, 204):
        raise Exception(f"HTTP {resp.status_code}")


def _send_discord(webhook_url, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    if not validate_webhook_url(webhook_url):
        raise ValueError("Blocked: unsafe webhook URL")
    color = _STATUS_COLORS.get(status, 0x64748b)
    desc = f"**Status:** {status}\n"
    if ssl_days_left is not None:
        desc += f"**SSL Days Left:** {ssl_days_left}\n"
    if domain_days_left is not None:
        desc += f"**Domain Days Left:** {domain_days_left}\n"
    payload = {"embeds": [{
        "title": f"Vigil Alert: {domain_name}",
        "description": desc,
        "color": int(color.lstrip('#'), 16) if isinstance(color, str) else color,
    }]}
    resp = requests.post(webhook_url, json=payload, timeout=10, verify=True)
    if resp.status_code not in (200, 204):
        raise Exception(f"HTTP {resp.status_code}")


def _send_telegram(bot_token, chat_id, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    ssl_line = f"SSL Days Left: {ssl_days_left}\n" if ssl_days_left is not None else ""
    domain_line = f"Domain Days Left: {domain_days_left}\n" if domain_days_left is not None else ""
    text = (
        f"\u26a0\ufe0f *Vigil Alert: {domain_name}*\n"
        f"Status: {status}\n"
        f"{ssl_line}{domain_line}"
    )
    resp = requests.post(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
        timeout=10, verify=True
    )
    if not resp.json().get('ok'):
        raise Exception(resp.json().get('description', 'Telegram API error'))


def _send_teams(webhook_url, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    if not validate_webhook_url(webhook_url):
        raise ValueError("Blocked: unsafe webhook URL")
    text = f"**Status:** {status}\n\n"
    if ssl_days_left is not None:
        text += f"**SSL Days Left:** {ssl_days_left}\n"
    if domain_days_left is not None:
        text += f"**Domain Days Left:** {domain_days_left}\n"
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Vigil Alert: {domain_name}",
        "title": f"\u26a0\ufe0f Vigil Alert: {domain_name}",
        "text": text,
        "themeColor": 0xef4444,
    }
    resp = requests.post(webhook_url, json=payload, timeout=10, verify=True)
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


def _send_generic(config, domain_name, status, ssl_days_left, domain_days_left, domain_data=None):
    url = config['url']
    if not validate_webhook_url(url):
        raise ValueError("Blocked: unsafe webhook URL")

    method = config.get('method', 'POST').upper()
    headers = config.get('headers', {})
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            headers = {}
    body_template = config.get('body_template', '')

    ssl_line = f'"ssl_days_left": {ssl_days_left}' if ssl_days_left is not None else ''
    domain_line = f'"domain_days_left": {domain_days_left}' if domain_days_left is not None else ''

    payload = body_template.format(
        domain_name=domain_name,
        status=status,
        ssl_days_left=ssl_days_left or '',
        domain_days_left=domain_days_left or '',
    )

    resp = requests.request(method, url, headers=headers, data=payload, timeout=10, verify=True)
    if resp.status_code >= 400:
        raise Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")
