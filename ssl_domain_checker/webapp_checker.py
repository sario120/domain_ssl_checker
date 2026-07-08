import json
import logging
import time
import urllib.request
import urllib.error

from checker import _parse_hostname, _is_private_host

logger = logging.getLogger(__name__)

SLOW_THRESHOLD_MS = 2000


def check_webapp(wa):
    url = wa['url']
    method = wa.get('method', 'GET')
    timeout = wa.get('timeout', 10)
    expected_status = wa.get('expected_status', 200)
    expected_body = wa.get('expected_body')
    expected_body_negate = wa.get('expected_body_negate', False)
    headers_raw = wa.get('headers')
    body = wa.get('body')

    req_headers = {}
    if headers_raw:
        try:
            req_headers = json.loads(headers_raw) if isinstance(headers_raw, str) else headers_raw
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid headers JSON for %s", url)

    result = {
        'status': 'down',
        'status_code': None,
        'response_time_ms': None,
        'error': None,
        'uptime_count': wa.get('uptime_count', 0),
        'downtime_count': wa.get('downtime_count', 0),
        'total_checks': wa.get('total_checks', 0) + 1,
        'successful_checks': wa.get('successful_checks', 0),
    }

    data = None
    if body and method in ('POST', 'PUT', 'PATCH'):
        data = body.encode('utf-8')
        if 'Content-Type' not in req_headers:
            req_headers['Content-Type'] = 'application/json'

    hostname = _parse_hostname(url)
    if _is_private_host(hostname):
        result['error'] = 'Connection to private IP blocked'
        return result

    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.perf_counter() - t0) * 1000
            result['response_time_ms'] = round(elapsed, 1)
            result['status_code'] = resp.status

            if resp.status != expected_status:
                result['status'] = 'down'
                result['error'] = f"Expected status {expected_status}, got {resp.status}"
            elif expected_body:
                body_text = resp.read().decode('utf-8', errors='replace')
                found = expected_body in body_text
                if expected_body_negate:
                    if found:
                        result['status'] = 'down'
                        result['error'] = f"Body should NOT contain '{expected_body}'"
                    else:
                        result['status'] = 'up' if elapsed < SLOW_THRESHOLD_MS else 'slow'
                else:
                    if found:
                        result['status'] = 'up' if elapsed < SLOW_THRESHOLD_MS else 'slow'
                    else:
                        result['status'] = 'down'
                        result['error'] = f"Expected body containing '{expected_body}' not found"
            else:
                result['status'] = 'up' if elapsed < SLOW_THRESHOLD_MS else 'slow'
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        result['response_time_ms'] = round(elapsed, 1)
        result['status_code'] = e.code
        if e.code == expected_status:
            result['status'] = 'up' if elapsed < SLOW_THRESHOLD_MS else 'slow'
        else:
            result['error'] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result['error'] = f"Connection failed: {e.reason}"
    except OSError as e:
        result['error'] = f"Network error: {e}"
    except Exception as e:
        result['error'] = str(e)

    if result['status'] == 'up':
        result['uptime_count'] = result.get('uptime_count', 0) + 1
        result['downtime_count'] = 0
        result['successful_checks'] = result.get('successful_checks', 0) + 1
    else:
        result['downtime_count'] = result.get('downtime_count', 0) + 1
        result['uptime_count'] = 0

    return result
