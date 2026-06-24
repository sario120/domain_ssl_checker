import atexit
import collections
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import whois as whois_lib
from models import parse_hostname
from status_utils import Status, domain_status_from_days, ssl_status_from_days

WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', '15'))
WHOIS_CACHE_TTL = int(os.environ.get('WHOIS_CACHE_TTL', '300'))
WHOIS_CACHE_ERROR_TTL = 30  # errors retried after 30s
WHOIS_RECV_TIMEOUT = int(os.environ.get('WHOIS_RECV_TIMEOUT', '5'))
WHOIS_MIN_BUFFER = max(2, WHOIS_TIMEOUT // 4)  # min seconds remaining before aborting a query phase
WHOIS_ERR_TIMEOUT = "WHOIS_TIMEOUT"
IANA_WHOIS = "whois.iana.org"

_whois_cache = collections.OrderedDict()
_whois_cache_lock = threading.Lock()
_whois_executor = ThreadPoolExecutor(max_workers=4)
atexit.register(lambda: _whois_executor.shutdown(wait=False))

_PRIVATE_IPS = (
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
)


def _resolve_hostname(hostname):
    """Resolve hostname to a list of IP address strings."""
    try:
        addrs = socket.getaddrinfo(hostname, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = set()
        result = []
        for family, _, _, _, sockaddr in addrs:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result
    except socket.gaierror:
        return []


def _is_private_ip(ip_str):
    """Check if a single IP address string is private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in _PRIVATE_IPS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def _is_private_host(hostname, resolved=None):
    """Check if hostname resolves to a private IP. Pass pre-resolved addresses to prevent DNS rebinding."""
    addrs = resolved if resolved is not None else _resolve_hostname(hostname)
    for ip_str in addrs:
        if _is_private_ip(ip_str):
            return True
    return False


def _cached_whois(hostname):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).timestamp()
    with _whois_cache_lock:
        if hostname in _whois_cache:
            entry = _whois_cache[hostname]
            if now - entry['ts'] < WHOIS_CACHE_TTL:
                _whois_cache.move_to_end(hostname)
                return entry['result']
            del _whois_cache[hostname]
    future = _whois_executor.submit(_do_whois, hostname)
    try:
        result = future.result(timeout=WHOIS_TIMEOUT)
    except TimeoutError:
        result = {"domain_expiry": None, "domain_days_left": None,
                  "domain_status": None, "domain_error": "WHOIS lookup timed out",
                  "domain_error_code": WHOIS_ERR_TIMEOUT}
    # Only cache successful results; errors cached for shorter duration
    with _whois_cache_lock:
        if result.get("domain_expiry"):
            _whois_cache[hostname] = {'result': result, 'ts': now}
        else:
            _whois_cache[hostname] = {'result': result, 'ts': now - WHOIS_CACHE_ERROR_TTL}
        while len(_whois_cache) > 1000:
            _whois_cache.popitem(last=False)
    return result

# Known WHOIS servers per TLD to skip IANA lookup
KNOWN_WHOIS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "me": "whois.nic.me",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "in": "whois.registry.in",
    "asia": "whois.nic.asia",
    "mobi": "whois.afilias.net",
    "name": "whois.nic.name",
    "us": "whois.nic.us",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "store": "whois.nic.store",
    "club": "whois.nic.club",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "page": "whois.nic.google",
    "cloud": "whois.nic.cloud",
    "ai": "whois.nic.ai",
    "cc": "ccwhois.verisign-grs.com",
    "tv": "whois.nic.tv",
    "ws": "whois.website.ws",
    "pro": "whois.registrypro.pro",
    "pe": "kero.yachay.pe",
    # Pakistan
    "pk": "whois.pknic.net.pk",
    "com.pk": "whois.pknic.net.pk",
    "net.pk": "whois.pknic.net.pk",
    "org.pk": "whois.pknic.net.pk",
    "edu.pk": "whois.pknic.net.pk",
    "gov.pk": "whois.pknic.net.pk",
    "web.pk": "whois.pknic.net.pk",
}


def check_domain(url, domain_type="full"):
    result = {"url": url, "type": domain_type}
    ssl_data = _check_ssl(url)
    result.update(ssl_data)

    if domain_type == "full":
        domain_data = _check_whois(url)
        result.update(domain_data)
    else:
        result.update({
            "domain_expiry": None, "domain_days_left": None,
            "domain_status": None
        })

    result["status"] = _determine_status(result, domain_type)
    return result


def _parse_hostname(url):
    return parse_hostname(url)


def _check_ssl(url):
    hostname = _parse_hostname(url)
    result = {"ssl_expiry": None, "ssl_days_left": None, "ssl_status": "pending",
              "ssl_issuer": None, "ssl_subject": None, "ssl_sans": None,
              "ssl_valid_from": None, "ssl_valid_until": None,
              "ssl_tls_version": None, "ssl_cipher": None,
              "ssl_fingerprint": None, "ssl_serial": None}
    try:
        # Resolve once to prevent DNS rebinding between private-IP check and connection
        resolved = _resolve_hostname(hostname)
        if not resolved:
            raise ValueError("Could not resolve hostname")
        if _is_private_host(hostname, resolved=resolved):
            result["ssl_status"] = "error"
            result["ssl_error"] = "Connection to private IP blocked"
            return result
        ctx = ssl.create_default_context()
        # Connect via resolved IP to prevent DNS rebinding, use SNI for certificate validation
        sock = None
        for ip in resolved:
            try:
                sock = socket.create_connection((ip, 443), timeout=10)
                break
            except (OSError, socket.timeout):
                continue
        if sock is None:
            raise ValueError("Could not connect to any resolved address")
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            result["ssl_tls_version"] = ssock.version()
            cipher = ssock.cipher()
            if cipher:
                result["ssl_cipher"] = cipher[0]
            cert = ssock.getpeercert()
            cert_binary = ssock.getpeercert(binary_form=True)
            if cert_binary:
                result["ssl_fingerprint"] = hashlib.sha256(cert_binary).hexdigest()
                result["ssl_pem"] = ssl.DER_cert_to_PEM_cert(cert_binary)
        if not cert:
            return result
        result["ssl_serial"] = cert.get("serialNumber")
        expires = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_left = (expires - now).days
        result["ssl_expiry"] = expires.isoformat()
        result["ssl_days_left"] = days_left
        result["ssl_status"] = ssl_status_from_days(days_left)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        result["ssl_issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))
        result["ssl_subject"] = subject.get("commonName", "")
        sans = []
        for ext in cert.get("subjectAltName", []):
            if ext[0] == "DNS": sans.append(ext[1])
        result["ssl_sans"] = json.dumps(sans)
        valid_from = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        result["ssl_valid_from"] = valid_from.isoformat()
        result["ssl_valid_until"] = expires.isoformat()
    except Exception as e:
        result["ssl_status"] = "error"
        result["ssl_error"] = str(e)
    return result


def _raw_whois_query(server, hostname, deadline=0):
    if _is_private_host(server):
        return ""
    try:
        with socket.create_connection((server, 43), timeout=max(5, WHOIS_RECV_TIMEOUT)) as s:
            s.settimeout(WHOIS_RECV_TIMEOUT)
            s.sendall(f"{hostname}\r\n".encode())
            data = b""
            for _ in range(256):
                if deadline and time.monotonic() > deadline:
                    break
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _get_whois_server_from_iana(tld):
    text = _raw_whois_query(IANA_WHOIS, tld)
    for line in text.splitlines():
        if line.lower().startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return None


def _parse_whois_response(text):
    result = {"domain_expiry": None, "domain_days_left": None,
              "domain_status": None, "domain_registrar": None}

    expiry_patterns = [
        r"(?:Registry Expiry Date|Expiry Date|Expiration Date|Expire Date|Expir\w+ Date)[\s:]+(.+)",
        r"(?:expiry[ :]+)(.+)",
        r"(?:expire[ :]+)(.+)",
        r"(?:paid-till[ :]+)(.+)",
        r"(?:Expiration Time)[\s:]+(.+)",
        r"(?:Expires on)[\s:]+(.+)",
        r"(?:Record expires on)[\s:]+(.+)",
        r"(?:Domain expires)[\s:]+(.+)",
    ]

    expiry_str = None
    for pat in expiry_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val and len(val) > 4:
                expiry_str = val
                break

    if expiry_str:
        # Normalize: strip trailing Z (UTC marker) and timezone offsets like +05:00, +0000
        expiry_str = re.sub(r'[+-]\d{2}:?\d{2}$', '', expiry_str.strip().rstrip('Z'))
        expiry = None
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y", "%Y.%m.%d", "%d.%m.%Y",
                     "%B %d, %Y", "%d %B %Y", "%b %d, %Y", "%Y-%m-%dT%H:%M:%S",
                     "%Y-%m-%d %H:%M:%S"):
            try:
                expiry = datetime.datetime.strptime(expiry_str, fmt)
                break
            except ValueError:
                continue
        if expiry:
            if expiry.year < 100:
                expiry = expiry.replace(year=expiry.year + 2000)
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days_left = (expiry - now).days
            result["domain_expiry"] = expiry.isoformat()
            result["domain_days_left"] = days_left
            result["domain_status"] = domain_status_from_days(days_left)

    registar_patterns = [
        r"(?:^|[\n\r])[ \t]*(?:Registrar|Sponsoring Registrar):[ \t]*(.+)",
        r"(?:^|[\n\r])[ \t]*(?:Registrar|Sponsoring Registrar):[ \t]*\n[ \t]*Name:[ \t]*(.+)",
        r"(?:^|[\n\r])[ \t]*registrar:[ \t]*(.+)",
    ]
    for pat in registar_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1).strip().rstrip('.')
            if val and len(val) > 2:
                result["domain_registrar"] = val
                break

    return result


def _do_whois(hostname):
    default = {"domain_expiry": None, "domain_days_left": None,
               "domain_status": None, "domain_registrar": None}
    deadline = time.monotonic() + WHOIS_TIMEOUT
    parts = hostname.split(".")
    if len(parts) < 2:
        return {**default, "domain_error": "Invalid domain"}

    # Try whois library first (handles server selection, query, parsing)
    remaining = deadline - time.monotonic()
    if remaining > WHOIS_MIN_BUFFER:
        try:
            w = whois_lib.whois(hostname, timeout=max(WHOIS_MIN_BUFFER, int(remaining)))
            raw_expiry = w.get("expiration_date")
            if raw_expiry:
                expiry = raw_expiry[0] if isinstance(raw_expiry, list) else raw_expiry
                if isinstance(expiry, datetime.datetime):
                    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    expiry_naive = expiry.replace(tzinfo=None) if expiry.tzinfo else expiry
                    days_left = (expiry_naive - now).days
                    registrar = w.get("registrar")
                    if isinstance(registrar, list):
                        registrar = registrar[0]
                    return {
                        "domain_expiry": expiry_naive.isoformat(),
                        "domain_days_left": days_left,
                        "domain_status": domain_status_from_days(days_left),
                        "domain_registrar": registrar or "",
                    }
        except Exception:
            pass

    # Fallback: raw socket WHOIS query
    compound = ".".join(parts[-2:])
    base = parts[-1]
    whois_server = KNOWN_WHOIS.get(compound) or KNOWN_WHOIS.get(base)
    if not whois_server:
        remaining = deadline - time.monotonic()
        if remaining < WHOIS_MIN_BUFFER:
            return {**default, "domain_error": "WHOIS lookup timed out", "domain_error_code": WHOIS_ERR_TIMEOUT}
        whois_server = _get_whois_server_from_iana(base)
    if not whois_server:
        return {**default, "domain_error": f"Unknown WHOIS server for .{compound}"}

    text = _raw_whois_query(whois_server, hostname, deadline)
    if not text:
        return {**default, "domain_error": "No response from WHOIS server"}

    result = _parse_whois_response(text)

    return result


def _check_whois(url):
    hostname = _parse_hostname(url)
    default = {"domain_expiry": None, "domain_days_left": None,
               "domain_status": None, "domain_registrar": None}
    try:
        result = _cached_whois(hostname)
        if result.get("domain_error_code") == WHOIS_ERR_TIMEOUT:
            # Retry once — the pool thread may have been slow, not the server
            with _whois_cache_lock:
                _whois_cache.pop(hostname, None)
            result = _cached_whois(hostname)
        return result
    except Exception as e:
        return {**default, "domain_error": str(e)}


def _determine_status(result, domain_type):
    if domain_type == "full":
        domain_stat = result.get("domain_status") or (domain_status_from_days(result.get("domain_days_left")) if result.get("domain_days_left") is not None else None)
        ssl_stat = result.get("ssl_status")
        candidates = [s for s in [domain_stat, ssl_stat] if s in Status.SEVERITY]
        if candidates:
            return min(candidates, key=lambda s: Status.SEVERITY.index(s))
        return Status.PENDING
    else:
        ssl = result.get("ssl_status")
        if ssl in Status.SEVERITY:
            return ssl
        return Status.PENDING



