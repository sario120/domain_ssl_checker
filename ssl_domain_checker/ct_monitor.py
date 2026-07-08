import json
import logging
import time
import urllib.request

logger = logging.getLogger(__name__)

CRTSH_API = "https://crt.sh/?q={}&output=json&excluded=expired&deduplicate=Y"


def fetch_certificates(domain):
    url = CRTSH_API.format(urllib.request.quote(domain))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Vigil-CTMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return data
    except Exception as e:
        logger.warning("CT fetch failed for %s: %s", domain, e)
        return None


def check_ct_logs(domain, known_ids_str):
    known_ids = set()
    if known_ids_str:
        try:
            known_ids = set(json.loads(known_ids_str))
        except (json.JSONDecodeError, TypeError):
            known_ids = set()

    certs = fetch_certificates(domain)
    if not certs:
        return {"new_certs": [], "current_ids": list(known_ids), "error": "Failed to fetch CT data"}

    current_ids = set()
    new_certs = []
    for c in certs:
        cid = c.get("id")
        if cid is None:
            continue
        current_ids.add(cid)
        if cid not in known_ids:
            new_certs.append({
                "id": cid,
                "issued": c.get("entry_timestamp", ""),
                "issuer_name": c.get("issuer_name", ""),
                "name_value": c.get("name_value", ""),
                "not_before": c.get("not_before", ""),
                "not_after": c.get("not_after", ""),
                "serial_number": c.get("serial_number", ""),
            })

    return {
        "new_certs": new_certs,
        "current_ids": list(current_ids),
        "count": len(new_certs),
        "error": None,
    }
