import logging
import socket
import time

logger = logging.getLogger(__name__)


def check_port(port_check):
    hostname = port_check['hostname']
    port = int(port_check.get('port', 80))
    timeout = port_check.get('timeout', 10)

    result = {
        'status': 'down',
        'response_time_ms': None,
        'error': None,
    }

    t0 = time.perf_counter()
    try:
        family = socket.AF_INET6 if port_check.get('use_ipv6') else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((hostname, port))
            elapsed = (time.perf_counter() - t0) * 1000
            result['response_time_ms'] = round(elapsed, 1)
            result['status'] = 'up'
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result['error'] = f"Connection failed: {e}"
        finally:
            sock.close()
    except socket.gaierror as e:
        result['error'] = f"Host resolution failed: {e}"
    except Exception as e:
        result['error'] = str(e)

    return result
