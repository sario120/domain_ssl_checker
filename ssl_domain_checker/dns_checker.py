import logging
import socket
import time

logger = logging.getLogger(__name__)

RECORD_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'}

def check_dns_record(dns_check):
    hostname = dns_check['hostname']
    record_type = dns_check.get('record_type', 'A').upper()
    expected = dns_check.get('expected_value') or None

    result = {
        'status': 'down',
        'response_time_ms': None,
        'error': None,
        'values': [],
    }

    t0 = time.perf_counter()
    try:
        if record_type in ('A', 'AAAA'):
            family = socket.AF_INET6 if record_type == 'AAAA' else socket.AF_INET
            try:
                addrs = list(set(
                    addr[4][0] for addr in socket.getaddrinfo(hostname, None, family)
                ))
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = addrs
            except socket.gaierror as e:
                result['error'] = f"DNS resolution failed: {e}"
                result['status'] = 'down'
        elif record_type == 'CNAME':
            try:
                cname = socket.getaddrinfo(hostname, None, socket.AF_INET)
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = [cname[0][4][0]]
            except socket.gaierror as e:
                result['error'] = f"CNAME lookup failed: {e}"
        elif record_type == 'MX':
            try:
                import dns.resolver
                answers = dns.resolver.resolve(hostname, 'MX')
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = sorted(str(r.exchange) for r in answers)
            except ImportError:
                result['error'] = "MX lookups require dnspython: pip install dnspython"
            except Exception as e:
                result['error'] = f"MX lookup failed: {e}"
        elif record_type == 'NS':
            try:
                import dns.resolver
                answers = dns.resolver.resolve(hostname, 'NS')
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = sorted(str(r.target) for r in answers)
            except ImportError:
                result['error'] = "NS lookups require dnspython: pip install dnspython"
            except Exception as e:
                result['error'] = f"NS lookup failed: {e}"
        elif record_type == 'TXT':
            try:
                import dns.resolver
                answers = dns.resolver.resolve(hostname, 'TXT')
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = sorted(''.join(s.decode() if isinstance(s, bytes) else s for s in r.strings) for r in answers)
            except ImportError:
                result['error'] = "TXT lookups require dnspython: pip install dnspython"
            except Exception as e:
                result['error'] = f"TXT lookup failed: {e}"
        elif record_type == 'SOA':
            try:
                import dns.resolver
                answers = dns.resolver.resolve(hostname, 'SOA')
                elapsed = (time.perf_counter() - t0) * 1000
                result['response_time_ms'] = round(elapsed, 1)
                result['values'] = [str(answers[0].mname)]
            except ImportError:
                result['error'] = "SOA lookups require dnspython: pip install dnspython"
            except Exception as e:
                result['error'] = f"SOA lookup failed: {e}"
        else:
            result['error'] = f"Unsupported record type: {record_type}"
            result['status'] = 'down'

    except socket.gaierror as e:
        result['error'] = f"DNS error: {e}"
    except Exception as e:
        result['error'] = str(e)

    if result['error']:
        result['status'] = 'down'
    else:
        if expected:
            matches = [v for v in result['values'] if expected.lower() in v.lower()]
            if matches:
                result['status'] = 'up'
            else:
                result['error'] = f"Expected '{expected}' not found in: {', '.join(result['values'])}"
                result['status'] = 'down'
        else:
            result['status'] = 'up'

    return result
