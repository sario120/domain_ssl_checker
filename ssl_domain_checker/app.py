import atexit
import hashlib
import ipaddress
import hmac as hmac_mod
import json
import logging
import os
import secrets
import signal
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import ContextVar
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from flask import Flask, g, jsonify, request, session, redirect, send_from_directory, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

import db as db_mod
import models
import backup
import email_templates
import scheduler as sched_mod
from checker import check_domain
from alert import send_alerts, test_smtp, send_check_complete_summary, _resolve_smtp_config
from scheduler import start_scheduler, get_next_scheduled_check

# ─── Logging ──────────────────────────────────────────────────
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s')
_log_max = int(os.environ.get('LOG_MAX_BYTES', str(5 * 1024 * 1024)))
_log_count = int(os.environ.get('LOG_BACKUP_COUNT', '3'))
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s',
    handlers=[
        RotatingFileHandler(
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data_volume", "app.log"),
            maxBytes=_log_max, backupCount=_log_count
        ),
        logging.StreamHandler()
    ],
    force=True
)
logger = logging.getLogger(__name__)
logging.getLogger("whois").setLevel(logging.WARNING)

# ─── Request ID for traceability ──────────────────────────────
_request_id_var: ContextVar[str] = ContextVar('request_id', default='')

class _RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = _request_id_var.get() or '-'
        return True

for _handler in logging.getLogger().handlers:
    _handler.addFilter(_RequestIdFilter())


# ─── App factory ──────────────────────────────────────────────
app = Flask(__name__,
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'),
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if os.environ.get('FLASK_DEBUG', '0') == '1' or os.environ.get('PYTEST_VERSION'):
        logger.warning(
            "SECRET_KEY not set — generating random key for dev/test only. "
            "Sessions and encrypted DB fields will reset on restart."
        )
        secret_key = secrets.token_hex(32)
    else:
        raise RuntimeError("SECRET_KEY must be set in production")
app.secret_key = secret_key
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS', '1') == '1'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get(
    'SESSION_COOKIE_SAMESITE', 'Strict' if os.environ.get('HTTPS', '1') == '1' else 'Lax'
)
if os.environ.get('HTTPS', '1') == '1':
    app.config['SESSION_COOKIE_NAME'] = '__Host-session'
# Session timeout capped at 4h. login_required enforces activity-based timeout separately.
MAX_SESSION_HOURS = 4
_session_timeout_hours = min(int(os.environ.get('SESSION_LIFETIME_HOURS', '24')), MAX_SESSION_HOURS)
app.config['PERMANENT_SESSION_LIFETIME'] = _session_timeout_hours * 3600

models.init_db()
models.init_settings()

_check_workers = int(os.environ.get('CHECK_WORKERS', '20'))


# ─── Rate limiter ─────────────────────────────────────────────
def rate_limit(max_requests, window_seconds):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = f"{request.remote_addr}:{request.endpoint}"
            if not models.check_rate_limit(key, max_requests, window_seconds):
                return api_error("Rate limit exceeded", 429)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def _validate_password(password, sec):
    min_len = sec.get('min_password_length', 8)
    if len(password) < min_len:
        return f'Password must be at least {min_len} characters'
    if sec.get('require_uppercase') and not any(c.isupper() for c in password):
        return 'Password must contain an uppercase letter'
    if sec.get('require_lowercase') and not any(c.islower() for c in password):
        return 'Password must contain a lowercase letter'
    if sec.get('require_number') and not any(c.isdigit() for c in password):
        return 'Password must contain a number'
    if sec.get('require_special') and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>/?' for c in password):
        return 'Password must contain a special character'
    return None


def _parse_rate_limit(s):
    parts = s.split()
    count = int(parts[0])
    unit = parts[2] if len(parts) > 2 else 'minute'
    seconds = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400}.get(unit, 60)
    return count, seconds


# ─── Check concurrency guard ─────────────────────────────────
_check_lock = threading.Lock()
_shutdown_event = threading.Event()

def _acquire_check_run():
    """Try to start a check run. Returns True if acquired, False if already running or shutting down."""
    if _shutdown_event.is_set():
        return False
    if not _check_lock.acquire(blocking=False):
        return False
    last = models.get_last_check_run()
    if last and last.get('status') == 'running':
        started = models.parse_dt(last.get('started_at'))
        if started and (models.timezone_now() - started).total_seconds() < models.STALE_RUN_SECONDS:
            _check_lock.release()
            return False
    return True

def _release_check_run():
    _check_lock.release()


# ─── CSRF protection ─────────────────────────────────────────
# Token derived from user_id + session-bound random nonce + secret_key.
# Rotates on every new session (login/logout), limiting leak window.
def generate_csrf_token():
    uid = str(session.get('user_id', ''))
    if 'csrf_nonce' not in session:
        session['csrf_nonce'] = secrets.token_hex(16)
    raw = f"{uid}:{session['csrf_nonce']}".encode()
    return hmac_mod.new(app.secret_key.encode(), raw, 'sha256').hexdigest()


def csrf_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token or not hmac_mod.compare_digest(token, generate_csrf_token()):
            username = session.get('username', 'anonymous')
            models.add_log('warning', f'Invalid CSRF token from {username}', username=username, client_ip=request.remote_addr)
            return api_error('Invalid CSRF token', 403)
        # Rotate nonce after each mutation — limits token theft window
        session['csrf_nonce'] = secrets.token_hex(16)
        session.modified = True
        return f(*args, **kwargs)
    return wrapper


# ─── Security helpers ─────────────────────────────────────────
def api_error(msg, code=400):
    return jsonify({'error': msg}), code


_PRIVATE_NETLOCS = frozenset({'localhost', '127.0.0.1', '::1', '0.0.0.0'})
_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('fc00::/7'),
]


def _validate_webhook_url(url):
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


def json_body(*required):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True)
            if data is None:
                return api_error('Request body must be JSON')
            for field in required:
                if field not in data or (isinstance(data[field], str) and not data[field].strip()):
                    return api_error(f'Missing required field: {field}')
            return f(data, *args, **kwargs)
        return wrapper
    return decorator


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                auth = request.headers.get('Authorization', '').strip()
                if auth.startswith('Bearer '):
                    api_key = auth[7:]
                    if not models.verify_api_key(api_key):
                        return api_error('Invalid API key', 401)
                    # Rate limit per API key — use hash of full key to avoid prefix collisions
                    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
                    if not models.check_rate_limit(f"apikey:{key_hash}", 300, 60):
                        return api_error('API key rate limit exceeded', 429)
                    session['api_key_name'] = 'api'
                    return f(*args, **kwargs)
                return api_error('Authentication required', 401)
            return redirect('/')
        # Activity-based timeout — sec.session_timeout is in minutes, capped at app-level max in hours
        sec = models.get_security_settings()
        timeout = min(sec.get('session_timeout', 60), _session_timeout_hours * 60) * 60  # → seconds
        last = session.get('_last_activity', 0)
        if last and time.time() - last > timeout:
            session.clear()
            if request.is_json or request.path.startswith('/api/'):
                return api_error('Session expired', 401)
            return redirect('/')
        session['_last_activity'] = time.time()
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            return api_error('Admin access required', 403)
        return f(*args, **kwargs)
    return wrapper


def current_username():
    return session.get('username', 'system')


@app.route('/api/csrf-token', methods=['GET'])
@login_required
def csrf_token_route():
    return jsonify({'csrf_token': generate_csrf_token()})


# ─── Request ID ────────────────────────────────────────────────
@app.before_request
def set_request_id():
    _request_id_var.set(str(uuid.uuid4())[:8])


# ─── Security headers ─────────────────────────────────────────
@app.before_request
def handle_cors_preflight():
    if request.method == 'OPTIONS' and request.path.startswith('/api/'):
        return jsonify({}), 200


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    if os.environ.get('HTTPS', '1') == '1':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if 'csrf_nonce' in session:
        response.headers['X-CSRF-Token'] = generate_csrf_token()
    if request.path.startswith('/api/'):
        origin = request.headers.get('Origin', '')
        allowed = os.environ.get('CORS_ORIGIN', '')
        if allowed and origin == allowed:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-CSRF-Token'
            response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
    csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:;"
    response.headers['Content-Security-Policy'] = csp
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


# ─── DB connection lifecycle ──────────────────────────────────
@app.teardown_appcontext
def shutdown_db(error):
    models.close_db()


# ─── Error handler ────────────────────────────────────────────
@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({'error': 'Internal server error'}), 500


# ─── Health check ─────────────────────────────────────────────
@app.route('/api/health')
def health():
    try:
        conn = models.get_db()
        conn.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    backend = db_mod.get_backend_info()
    scheduler_next = get_next_scheduled_check()
    sched_running = False
    try:
        sched_running = sched_mod.scheduler.running
    except Exception:
        pass
    return jsonify({
        'status': 'ok' if db_ok else 'degraded',
        'database': {
            'type': backend['type'],
            'status': 'connected' if db_ok else 'error',
            **({'schema': backend['schema']} if backend['type'] == 'postgresql' else {}),
        },
        'scheduler': {
            'running': sched_running,
            'next_run': scheduler_next,
        },
    })


@app.route('/api/metrics')
def prometheus_metrics():
    try:
        status_counts = models.get_domain_status_counts()
        check_run = models.get_last_check_run()
    except Exception:
        return "text/plain", 500
    lines = ['# HELP vigil_domains_total Total domains by status',
             '# TYPE vigil_domains_total gauge']
    for status, count in sorted(status_counts.items()):
        lines.append(f'vigil_domains_total{{status="{status}"}} {count}')
    if check_run:
        lines.append(f'# HELP vigil_last_check_timestamp Last check completion timestamp')
        lines.append(f'# TYPE vigil_last_check_timestamp gauge')
        lines.append(f'vigil_last_check_timestamp {check_run.get("completed_at") or "0"}')
    return '\n'.join(lines) + '\n', 200, {'Content-Type': 'text/plain; charset=utf-8'}


# ─── Dashboard Summary ─────────────────────────────────────────
@app.route('/api/dashboard/summary', methods=['GET'])
@login_required
def dashboard_summary():
    return jsonify(models.get_dashboard_summary())


# ─── Auth ─────────────────────────────────────────────────────
_login_rate = os.environ.get('RATE_LIMIT_LOGIN', '10 per minute')
_login_rate_limit, _login_rate_window = _parse_rate_limit(_login_rate)

@app.route('/api/login', methods=['POST'])
@rate_limit(_login_rate_limit, _login_rate_window)
@json_body('username', 'password')
def login(data):
    username = data['username'].strip()

    # Check if user is locked out
    if models.is_user_locked(username):
        sec = models.get_security_settings()
        return api_error(f'Account locked. Try again in {sec.get("lockout_duration", 15)} minutes', 429)

    if len(data['password']) < 1:
        return api_error('Password is required', 400)

    user = models.get_user_by_username(username)
    if not user:
        check_password_hash("dummy", data['password'])
        models.add_log('warning', f'Failed login attempt for unknown user {username}', username=username, client_ip=request.remote_addr)
        return api_error('Invalid username or password', 401)
    if not check_password_hash(user['password'], data['password']):
        models.record_fail_time(username)
        models.record_login_attempt(username, False)
        models.add_log('warning', f'Failed login attempt for {username}', username=username, client_ip=request.remote_addr)
        sec = models.get_security_settings()
        fails = (user or {}).get('login_fails', 0) + 1
        if fails >= sec.get('max_login_attempts', 5):
            return api_error('Account locked. Try again later.', 429)
        return api_error('Invalid username or password', 401)

    if not user.get('is_active', 1):
        return api_error('Account is deactivated. Contact an administrator.', 403)

    # Success
    previous_login = user.get('last_login')
    models.record_login_attempt(username, True)
    session.clear()  # Flask signed-cookie sessions: clearing + re-setting values effectively rotates the session cookie
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user.get('role', 'admin')
    session.permanent = True
    sec = models.get_security_settings()
    app.permanent_session_lifetime = min(sec.get('session_timeout', 60), MAX_SESSION_HOURS * 60) * 60
    models.add_log('audit', f'Login: {username}', username=username, client_ip=request.remote_addr)
    return jsonify({
        'message': 'Login successful',
        'username': user['username'],
        'role': user.get('role', 'admin'),
        'last_login': previous_login,
    })


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    username = current_username()
    session.clear()
    models.add_log('audit', f'Logout: {username}', username=username, client_ip=request.remote_addr)
    return jsonify({'message': 'Logged out'})


@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' in session:
        return jsonify({'authenticated': True, 'username': session.get('username'), 'role': session.get('role', 'admin')})
    return jsonify({'authenticated': False}), 401


# ─── Domains CRUD ─────────────────────────────────────────────
@app.route('/api/domains', methods=['GET'])
@login_required
def list_domains():
    domain_type = request.args.get('type')
    if domain_type and domain_type not in ('full', 'ssl_only'):
        return api_error('Invalid type filter (use full or ssl_only)')
    page = request.args.get('page', type=int)
    limit = request.args.get('limit', type=int)
    domains = models.get_domains(type_filter=domain_type)
    if page and limit:
        start = (page - 1) * limit
        end = start + limit
        return jsonify({'domains': domains[start:end], 'total': len(domains)})
    return jsonify(domains)


@app.route('/api/domains/all', methods=['GET'])
@login_required
def list_all_domains():
    full = models.get_domains(type_filter='full')
    ssl = models.get_domains(type_filter='ssl_only')
    return jsonify({'full': full, 'ssl_only': ssl})


@app.route('/api/domains', methods=['POST'])
@admin_required
@csrf_required
@json_body('url')
def add_domain_route(data):
    url = data['url'].strip()
    domain_type = data.get('type', 'full')
    notes = data.get('notes', '')
    manual_expiry = data.get('manual_expiry_date') or None
    manual_registrar = data.get('manual_registrar') or None
    if domain_type not in ('full', 'ssl_only'):
        return api_error('domain_type must be "full" or "ssl_only"')
    if not models.is_valid_domain(url):
        return api_error('Invalid domain format')
    result = models.add_domain(url, domain_type, notes, manual_expiry, manual_registrar)
    if not result.get('ok'):
        return api_error(result.get('error', 'Failed to add domain'))
    models.add_log('info', f'Domain added: {url} ({domain_type})', username=current_username())
    return jsonify({'id': result['id'], 'message': 'Domain added'}), 201


@app.route('/api/domains/<int:domain_id>', methods=['PUT'])
@admin_required
@csrf_required
def update_domain_route(domain_id):
    domain = models.get_domain(domain_id)
    if not domain:
        return api_error('Domain not found', 404)
    data = request.get_json(silent=True) or {}
    new_url = data.get('url')
    if new_url and not models.is_valid_domain(new_url):
        return api_error('Invalid domain format')
    models.update_domain(domain_id,
                         url=data.get('url'),
                         domain_type=data.get('type'),
                         notes=data.get('notes'),
                         manual_expiry_date=data.get('manual_expiry_date'),
                         manual_registrar=data.get('manual_registrar'))
    models.add_log('info', f'Domain updated: {domain["url"]}', username=current_username())
    return jsonify({'message': 'Domain updated'})


@app.route('/api/domains/<int:domain_id>', methods=['DELETE'])
@admin_required
@csrf_required
def delete_domain_route(domain_id):
    domain = models.get_domain(domain_id)
    if not domain:
        return api_error('Domain not found', 404)
    models.delete_domain(domain_id)
    models.add_log('audit', f'Domain deleted: {domain["url"]}', username=current_username())
    return jsonify({'message': 'Domain deleted'})


# ─── Import / Export ──────────────────────────────────────────
@app.route('/api/domains/export', methods=['GET'])
@admin_required
def export_domains():
    domains = models.get_domains()
    fmt = request.args.get('format', 'json')

    if fmt == 'csv':
        import csv as csv_mod
        import io
        buf = io.StringIO()
        w = csv_mod.writer(buf)
        w.writerow(['url', 'type', 'notes', 'ssl_alert_threshold', 'domain_alert_threshold'])
        for d in domains:
            w.writerow([d['url'], d['type'], d.get('notes', ''),
                        d.get('ssl_alert_threshold', ''),
                        d.get('domain_alert_threshold', '')])
        return buf.getvalue(), 200, {'Content-Type': 'text/csv',
                                      'Content-Disposition': 'attachment; filename=domains.csv'}

    if fmt == 'txt':
        lines = '\n'.join(d['url'] for d in domains)
        return lines, 200, {'Content-Type': 'text/plain',
                             'Content-Disposition': 'attachment; filename=domains.txt'}

    data = []
    for d in domains:
        data.append({
            'url': d['url'],
            'type': d['type'],
            'notes': d.get('notes', ''),
            'ssl_alert_threshold': d.get('ssl_alert_threshold'),
            'domain_alert_threshold': d.get('domain_alert_threshold'),
        })
    return jsonify(data)


@app.route('/api/domains/import', methods=['POST'])
@admin_required
@csrf_required
def import_domains():
    import csv as csv_mod
    import io

    items = []
    default_txt_type = request.args.get('type', 'full')
    if default_txt_type not in ('full', 'ssl_only'):
        default_txt_type = 'full'

    # Detect format: JSON body, JSON file, CSV file, or TXT file
    if request.files:
        f = request.files.get('file')
        if f:
            raw = f.read().decode('utf-8', errors='replace')
            filename = f.filename or ''
            if filename.endswith('.csv'):
                reader = csv_mod.DictReader(io.StringIO(raw))
                for row in reader:
                    url = row.get('url', '').strip()
                    if url:
                        items.append({
                            'url': url,
                            'type': row.get('type', row.get('domain_type', 'full')),
                            'notes': row.get('notes', ''),
                        })
            elif filename.endswith('.txt'):
                for line in raw.strip().splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        items.append({'url': line, 'type': default_txt_type, 'notes': ''})
            else:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        items = parsed
                    elif isinstance(parsed, dict) and 'domains' in parsed:
                        items = parsed['domains']
                except json.JSONDecodeError:
                    return api_error('Unsupported file format. Use .json, .csv, or .txt')
    else:
        data = request.get_json(silent=True) or {}
        if isinstance(data, list):
            items = data
        elif 'domains' in data:
            items = data['domains']
        else:
            return api_error('Send JSON with "domains" array, or upload a .csv/.txt/.json file')

    results = {'added': 0, 'skipped': 0, 'errors': [], 'added_list': [], 'skipped_list': []}
    for item in items:
        url = item.get('url', '').strip() if isinstance(item, dict) else str(item).strip()
        if not url:
            continue
        if not models.is_valid_domain(url):
            results['errors'].append(f'{url}: invalid domain format')
            continue
        domain_type = item.get('type', item.get('domain_type', 'full')) if isinstance(item, dict) else 'full'
        if domain_type not in ('full', 'ssl_only'):
            domain_type = 'full'
        r = models.add_domain(url, domain_type, item.get('notes', '') if isinstance(item, dict) else '')
        if r.get('ok'):
            results['added'] += 1
            results['added_list'].append(url)
        elif 'already exists' in r.get('error', ''):
            results['skipped'] += 1
            results['skipped_list'].append({'url': url, 'reason': 'already exists'})
        else:
            results['errors'].append(f'{url}: {r.get("error")}')

    log_username = current_username()
    models.add_log('info', f'Import: {results["added"]} added, {results["skipped"]} skipped, {len(results["errors"])} errors', username=log_username)
    return jsonify(results)


# ─── Check operations ─────────────────────────────────────────
def run_check_for_domain(domain):
    url = domain['url']
    try:
        result = check_domain(url, domain['type'])
        return {
            'domain_id': domain['id'], 'url': url,
            'status': result['status'], 'success': True,
            **result
        }
    except Exception as e:
        logger.exception(f"Unexpected error checking {url}")
        return {
            'domain_id': domain['id'], 'url': url,
            'status': 'error', 'success': False, 'error': str(e),
            'ssl_status': 'error', 'domain_status': None,
            'ssl_days_left': None, 'domain_days_left': None,
            'ssl_expiry': None, 'domain_expiry': None,
            'ssl_issuer': None, 'ssl_subject': None, 'ssl_sans': None,
            'ssl_valid_from': None, 'ssl_valid_until': None,
            'domain_registrar': None,
        }


def _maybe_send_alert(domain, result, settings):
    ssl_days = result.get('ssl_days_left')
    domain_days = result.get('domain_days_left')
    v = domain.get('ssl_alert_threshold')
    threshold_ssl = v if v is not None else settings.get('ssl_alert_threshold', 30)
    v = domain.get('domain_alert_threshold')
    threshold_domain = v if v is not None else settings.get('domain_alert_threshold', 30)

    ssl_triggered = ssl_days is not None and ssl_days < threshold_ssl
    domain_triggered = domain_days is not None and domain_days < threshold_domain

    if result['status'] == 'expired' or result.get('ssl_status') == 'error':
        ssl_triggered = True

    if not ssl_triggered and not domain_triggered:
        return

    last = models.parse_dt(domain.get('last_alerted'))
    if last and (models.timezone_now() - last).total_seconds() < models.ALERT_COOLDOWN_SECONDS:
        return

    errors = send_alerts(domain['url'], result['status'], ssl_days, domain_days, settings, domain_data=dict(domain))

    if errors:
        for e in errors:
            models.add_log('alert_error', f'Alert failed for {domain["url"]}: {e}', domain_id=domain['id'])
    else:
        models.add_log('alert', f'Alert sent for {domain["url"]}: {result["status"]}', domain_id=domain['id'])
        models.update_last_alerted(domain['id'])


@app.route('/api/domains/<int:domain_id>/check', methods=['POST'])
@admin_required
@csrf_required
def manual_check(domain_id):
    domain = models.get_domain(domain_id)
    if not domain:
        return api_error('Domain not found', 404)
    result = run_check_for_domain(domain)
    models.save_domain_check(domain_id, result)
    models.save_check_result_history(domain_id, result)
    models.add_log('check', f'Manual check for {domain["url"]}: {result["status"]}', domain_id=domain_id)
    settings = models.get_settings()
    if result.get('status') in ('expired', 'expiring_soon', 'error'):
        _maybe_send_alert(domain, result, settings)
    return jsonify(result)


@app.route('/api/check-all', methods=['POST'])
@admin_required
@csrf_required
def check_all():
    if not _acquire_check_run():
        return api_error('A check is already running', 409)
    try:
        domains = models.get_domains()
        if not domains:
            return jsonify({'message': 'No domains to check', 'results': []})
        run_id = models.start_check_run('manual', len(domains))
        if run_id is None:
            return api_error('Another check started concurrently', 409)
        results = []
        with ThreadPoolExecutor(max_workers=_check_workers) as pool:
            futures = {pool.submit(run_check_for_domain, d): d for d in domains}
            for future in as_completed(futures):
                r = future.result()
                results.append(r)
        if not models.save_domain_checks_batch(results):
            logger.warning("Manual check: batch save returned failure — results may be incomplete")
        models.save_check_results_batch(results)
        log_entries = []
        for r in results:
            log_type = 'error' if r.get('success') is False else 'check'
            log_msg = f'[run:{run_id}] Check completed for {r["url"]}: {r["status"]}' if r.get('success') else f'[run:{run_id}] Check failed for {r["url"]}: {r.get("error")}'
            log_entries.append((log_type, log_msg, r.get('domain_id'), None, None))
        models.add_logs_batch(log_entries)
        models.update_check_run(run_id, len(results), 'completed')
        models.save_health_snapshot()
        settings = models.get_settings()
        domain_map = {d['id']: d for d in domains}
        for r in results:
            domain = domain_map.get(r.get('domain_id'))
            if domain and r.get('status') in ('expired', 'expiring_soon', 'error'):
                _maybe_send_alert(domain, r, settings)
        return jsonify({'message': f'Checked {len(results)} domains', 'results': results})
    finally:
        _release_check_run()


# ─── Scheduler Status ──────────────────────────────────────────
@app.route('/api/scheduler/status', methods=['GET'])
@login_required
def scheduler_status():
    return jsonify({'next_run': get_next_scheduled_check()})


# ─── Cert Details ──────────────────────────────────────────────
@app.route('/api/domains/<int:domain_id>/cert', methods=['GET'])
@login_required
def cert_details(domain_id):
    domain = models.get_domain(domain_id)
    if not domain:
        return api_error('Domain not found', 404)
    return jsonify({
        'url': domain['url'],
        'ssl_issuer': domain.get('ssl_issuer'),
        'ssl_subject': domain.get('ssl_subject'),
        'ssl_sans': domain.get('ssl_sans'),
        'ssl_valid_from': domain.get('ssl_valid_from'),
        'ssl_valid_until': domain.get('ssl_valid_until'),
        'ssl_expiry': domain.get('ssl_expiry'),
        'ssl_status': domain.get('ssl_status'),
        'status': domain.get('status'),
        'last_checked': domain.get('last_checked'),
    })


@app.route('/api/domains/<int:domain_id>/history', methods=['GET'])
@login_required
def domain_check_history(domain_id):
    days = request.args.get('days', 7, type=int)
    return jsonify(models.get_domain_check_history(domain_id, days))


# ─── Settings ──────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
@admin_required
def get_settings_route():
    settings = models.get_settings()
    if settings:
        has_pw = bool(settings.pop('smtp_password', ''))
        settings['has_password'] = has_pw
    return jsonify(settings or {})


@app.route('/api/settings/export', methods=['GET'])
@admin_required
def export_settings():
    settings = models.get_settings()
    security = models.get_security_settings()
    if settings:
        settings.pop('id', None)
        settings.pop('smtp_password', None)
    if security:
        security.pop('id', None)
    return jsonify({'settings': settings, 'security': security, 'exported_at': models.timezone_now().isoformat()})


@app.route('/api/settings/import', methods=['POST'])
@admin_required
@csrf_required
def import_settings():
    data = request.get_json(silent=True) or {}
    imported = data.get('settings')
    security = data.get('security')
    if not imported and not security:
        return api_error('No settings data provided')
    if imported:
        models.update_settings(imported)
    if security:
        models.update_security_settings(security)
    models.add_log('audit', 'Settings imported from export', username=current_username())
    return jsonify({'message': 'Settings imported'})


@app.route('/api/settings', methods=['PUT'])
@admin_required
@csrf_required
def update_settings_route():
    data = request.get_json(silent=True) or {}
    # Validate webhook URLs before saving
    for wh_key in ('slack_webhook_url', 'zulip_webhook_url'):
        url = data.get(wh_key)
        if url and not _validate_webhook_url(url):
            return api_error(f'Invalid {wh_key}: must be an HTTPS URL')
    models.update_settings(data)
    # Granular audit log
    changed = []
    label_map = {
        'smtp_enabled': 'SMTP alerts',
        'ssl_alert_threshold': 'SSL alert threshold',
        'domain_alert_threshold': 'Domain alert threshold',
        'slack_webhook_url': 'Slack webhook URL',
        'slack_enabled': 'Slack alerts',
        'zulip_webhook_url': 'Zulip webhook URL',
        'zulip_enabled': 'Zulip alerts',
    }
    for k, label in label_map.items():
        if k in data:
            v = data[k]
            if isinstance(v, bool):
                changed.append(f'{label} → {"on" if v else "off"}')
            else:
                changed.append(f'{label} updated')
    if changed:
        models.add_log('audit', 'Settings: ' + '; '.join(changed), username=current_username())
    else:
        models.add_log('audit', 'Settings saved', username=current_username())
    return jsonify({'message': 'Settings saved'})


# ─── Users ──────────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@admin_required
def list_users():
    users = models.get_users()
    return jsonify(users)


@app.route('/api/users', methods=['POST'])
@admin_required
@csrf_required
@json_body('username', 'password')
def add_user_route(data):
    username = data['username'].strip()
    password = data['password']
    role = data.get('role', 'viewer')
    err = _validate_password(password, models.get_security_settings())
    if err:
        return api_error(err)
    result = models.add_user(username, password, role)
    if not result.get('ok'):
        return api_error(result.get('error', 'Failed to create user'))
    models.add_log('audit', f'User created: {username}', username=current_username())
    return jsonify({'message': 'User created'}), 201


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
@csrf_required
def update_user_route(user_id):
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    role = data.get('role')
    is_active = data.get('is_active')
    if password:
        err = _validate_password(password, models.get_security_settings())
        if err:
            return api_error(err)
    if is_active is not None and int(user_id) == int(session.get('user_id')):
        return api_error('Cannot deactivate your own account', 403)
    result = models.update_user(user_id, password=password, role=role, is_active=is_active)
    models.add_log('audit', f'User updated: {user_id}', username=current_username())
    return jsonify({'message': 'User updated'})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
@csrf_required
def delete_user_route(user_id):
    result = models.delete_user(user_id, session.get('user_id'))
    if not result.get('ok'):
        return api_error(result.get('error', 'Failed to delete user'))
    models.add_log('audit', f'User deleted: {user_id}', username=current_username())
    return jsonify({'message': 'User deleted'})


# ─── Security Settings ─────────────────────────────────────────
@app.route('/api/security-settings', methods=['GET'])
@admin_required
def get_security_settings():
    settings = models.get_security_settings()
    return jsonify(settings or {})


@app.route('/api/security-settings', methods=['PUT'])
@admin_required
@csrf_required
def update_security_settings():
    data = request.get_json(silent=True) or {}
    models.update_security_settings(data)
    models.add_log('audit', 'Security settings updated', username=current_username())
    return jsonify({'message': 'Security settings saved'})


# ─── API Keys ──────────────────────────────────────────────────
@app.route('/api/api-keys', methods=['GET'])
@admin_required
def list_api_keys():
    keys = models.get_api_keys()
    for k in keys:
        k.pop('key_hash', None)
    return jsonify(keys)


@app.route('/api/api-keys', methods=['POST'])
@admin_required
@csrf_required
def create_api_key():
    data = request.get_json(silent=True) or {}
    name = data.get('name', 'Key-' + str(int(time.time())))
    result = models.create_api_key(name)
    models.add_log('audit', f'API key created: {name}', username=current_username())
    return jsonify({'key': result['key'], 'name': name, 'key_masked': result['key_masked']}), 201


@app.route('/api/api-keys/bulk-revoke', methods=['POST'])
@admin_required
@csrf_required
def bulk_revoke_api_keys():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not ids:
        return api_error('No API key IDs provided')
    for key_id in ids:
        models.revoke_api_key(key_id)
    models.add_log('audit', f'{len(ids)} API keys revoked', username=current_username())
    return jsonify({'message': f'{len(ids)} API keys revoked'})


@app.route('/api/api-keys/<int:key_id>', methods=['DELETE'])
@admin_required
@csrf_required
def revoke_api_key(key_id):
    models.revoke_api_key(key_id)
    models.add_log('audit', f'API key revoked: {key_id}', username=current_username())
    return jsonify({'message': 'API key revoked'})


# ─── Enhanced SMTP Test ────────────────────────────────────────
@app.route('/api/settings/test-smtp', methods=['POST'])
@admin_required
@csrf_required
def test_smtp_route():
    settings = models.get_settings()
    if not settings:
        return api_error('No settings found')
    smtp_cfg = _resolve_smtp_config(settings)
    if not smtp_cfg.get('smtp_email') or not smtp_cfg.get('smtp_password'):
        return api_error('SMTP credentials not configured. Set SMTP_USER and SMTP_PASS in .env or save in Settings.')

    steps = []

    # Step 1: DNS resolution
    try:
        socket.gethostbyname(smtp_cfg['smtp_server'])
        steps.append({'message': f'DNS resolved: {smtp_cfg["smtp_server"]}', 'ok': True})
    except Exception as e:
        steps.append({'message': f'DNS failed: {e}', 'ok': False})
        return jsonify({'steps': steps, 'message': 'DNS resolution failed'}), 500

    # Step 2: TCP connection (5s timeout)
    try:
        sock = socket.create_connection((smtp_cfg['smtp_server'], int(smtp_cfg['smtp_port'])), timeout=5)
        sock.close()
        steps.append({'message': f'TCP connected to port {smtp_cfg["smtp_port"]}', 'ok': True})
    except Exception as e:
        steps.append({'message': f'TCP failed: {e}', 'ok': False})
        return jsonify({'steps': steps, 'message': 'TCP connection failed'}), 500

    # Step 3: TLS + AUTH
    try:
        test_smtp(smtp_cfg, settings)
        steps.append({'message': 'TLS handshake + AUTH successful', 'ok': True})
        steps.append({'message': 'Test email sent!', 'ok': True})
        models.add_log('info', 'Test SMTP alert sent', username=current_username())
        return jsonify({'steps': steps, 'message': 'Test SMTP sent'})
    except Exception as e:
        steps.append({'message': f'SMTP AUTH/send failed: {e}', 'ok': False})
        return jsonify({'steps': steps, 'message': f'SMTP test failed: {e}'}), 500


@app.route('/api/settings/test-webhook', methods=['POST'])
@admin_required
@csrf_required
def test_webhook_route():
    data = request.get_json(silent=True) or {}
    webhook_type = data.get('type')
    webhook_url = data.get('url')
    if not webhook_type or not webhook_url:
        return api_error('type and url are required')
    if not _validate_webhook_url(webhook_url):
        return api_error('Webhook URL must be HTTPS')
    try:
        from webhook import send_test_webhook
        send_test_webhook(webhook_type, webhook_url)
        models.add_log('info', f'Test {webhook_type} alert sent', username=current_username())
        return jsonify({'message': f'Test {webhook_type} sent'})
    except Exception as e:
        return api_error(f'{webhook_type} test failed: {e}', 500)


# ─── Logs ──────────────────────────────────────────────────────
@app.route('/api/logs', methods=['GET'])
@admin_required
def get_logs():
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    log_type = request.args.get('type', 'all')
    query = request.args.get('q', '').strip()
    limit = min(limit, 500)
    logs = models.get_logs(limit=limit, offset=offset, log_type=log_type, query=query)
    total = models.get_logs_count(log_type=log_type, query=query)
    summary = models.get_logs_summary(log_type=log_type, query=query)
    return jsonify({'logs': logs, 'total': total, 'summary': summary})


@app.route('/api/logs', methods=['POST'])
@admin_required
@csrf_required
def create_log():
    data = request.get_json(silent=True) or {}
    log_type = data.get('type', 'info')
    message = data.get('message', '')
    if message:
        models.add_log(log_type, message, username=current_username())
    return jsonify({'message': 'Logged'})


# ─── Backups ───────────────────────────────────────────────────
@app.route('/api/backups', methods=['GET'])
@admin_required
def list_backups():
    backups = backup.list_backups()
    return jsonify(backups)


@app.route('/api/backups', methods=['POST'])
@admin_required
@csrf_required
def create_backup():
    path = backup.create_backup()
    if path:
        models.add_log('audit', f'Database backup created: {os.path.basename(path)}', username=current_username())
        return jsonify({'message': 'Backup created', 'path': path})
    return api_error('Backup failed', 500)


@app.route('/api/backups/restore', methods=['POST'])
@admin_required
@csrf_required
def restore_backup():
    data = request.get_json(silent=True) or {}
    filename = data.get('filename')
    if not filename:
        return api_error('filename is required')
    try:
        snapshot = backup.create_backup()
        if snapshot:
            logger.info(f"Pre-restore snapshot created: {os.path.basename(snapshot)}")
        backup.restore_backup(filename)
        models.add_log('audit', f'Database restored from {filename}', username=current_username())
        return jsonify({'message': 'Database restored'})
    except FileNotFoundError as e:
        return api_error(str(e))
    except Exception as e:
        return api_error(f'Restore failed: {e}', 500)


def _safe_backup_path(filename):
    """Resolve backup path safely — prevent path traversal."""
    resolved = os.path.realpath(os.path.join(backup.BACKUP_DIR, filename))
    real_base = os.path.realpath(backup.BACKUP_DIR)
    if not resolved.startswith(real_base):
        return None
    return resolved


@app.route('/api/backups/download/<filename>', methods=['GET'])
@admin_required
def download_backup(filename):
    backup_path = _safe_backup_path(filename)
    if not backup_path or not os.path.exists(backup_path):
        return api_error('Backup not found')
    return send_file(backup_path, as_attachment=True, download_name=filename)


@app.route('/api/backups/<filename>', methods=['DELETE'])
@admin_required
@csrf_required
def delete_backup(filename):
    backup_path = _safe_backup_path(filename)
    if not backup_path or not os.path.exists(backup_path):
        return api_error('Backup not found')
    meta_path = backup_path + ".meta"
    os.remove(backup_path)
    if os.path.exists(meta_path):
        os.remove(meta_path)
    return jsonify({'message': 'Backup deleted'})


# ─── Email Templates ───────────────────────────────────────────
@app.route('/api/email-templates', methods=['GET'])
@admin_required
def get_email_templates():
    defaults = email_templates.get_default_templates()
    settings = models.get_settings()
    custom_raw = settings.get('email_templates', '{}') if settings else '{}'
    try:
        custom = json.loads(custom_raw)
    except Exception:
        custom = {}
    merged = {}
    for name, tpl in defaults.items():
        merged[name] = dict(tpl)
        if name in custom:
            merged[name].update({k: v for k, v in custom[name].items() if v})
    return jsonify(merged)


@app.route('/api/email-templates/<template_name>', methods=['PUT'])
@admin_required
@csrf_required
def update_email_template(template_name):
    data = request.get_json(silent=True) or {}
    # Store custom overrides in settings table
    existing = models.get_settings()
    custom = existing.get('email_templates', '{}')
    try:
        templates = json.loads(custom)
    except Exception:
        templates = {}
    templates[template_name] = {
        'subject': data.get('subject', ''),
        'body_html': data.get('body_html', ''),
        'body_text': data.get('body_text', ''),
    }
    models.update_settings({'email_templates': json.dumps(templates)})
    return jsonify({'message': 'Template saved'})


@app.route('/api/email-templates/reset', methods=['PUT'])
@admin_required
@csrf_required
def reset_email_templates():
    models.update_settings({'email_templates': '{}'})
    return jsonify({'message': 'Templates reset to defaults'})


# ─── Frontend ──────────────────────────────────────────────────
@app.route('/')
def login_page():
    if 'user_id' in session:
        return redirect('/dashboard')
    return send_from_directory(app.template_folder, 'login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return send_from_directory(app.template_folder, 'index.html')


# ─── Background scheduler ──────────────────────────────────────
def check_all_background():
    if not _acquire_check_run():
        logger.info("Scheduled check skipped — another check is already running")
        return
    try:
        with app.app_context():
            logger.info("Scheduled check: checking all domains")
            domains = models.get_domains()
            run_id = models.start_check_run('scheduled', len(domains))
            if run_id is None:
                logger.warning("Scheduled check skipped — concurrent start detected")
                return
            results = []
            with ThreadPoolExecutor(max_workers=_check_workers) as pool:
                futures = {pool.submit(run_check_for_domain, d): d for d in domains}
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
            if not models.save_domain_checks_batch(results):
                logger.warning("Scheduled check: batch save returned failure — results may be incomplete")
            models.save_check_results_batch(results)
            log_entries = []
            for r in results:
                log_type = 'error' if r.get('success') is False else 'check'
                log_msg = f'[run:{run_id}] Check completed for {r["url"]}: {r["status"]}' if r.get('success') else f'[run:{run_id}] Check failed for {r["url"]}: {r.get("error")}'
                log_entries.append((log_type, log_msg, r.get('domain_id'), None, None))
            models.add_logs_batch(log_entries)
            models.update_check_run(run_id, len(results), 'completed')
            models.save_health_snapshot()

            # Send check complete summary email (once per day max)
            try:
                settings = models.get_settings()
                last_summary = models.parse_dt(settings.get('last_summary_sent'))
                if last_summary and (models.timezone_now() - last_summary).total_seconds() < models.SUMMARY_COOLDOWN_SECONDS:
                    logger.info("Summary already sent today, skipping")
                    return
                smtp_cfg = _resolve_smtp_config(settings)
                if smtp_cfg and smtp_cfg.get('smtp_email') and smtp_cfg.get('smtp_password'):
                    snapshot = models.get_health_snapshots(days=1)
                    ssl_total = sum(1 for r in results if r.get('ssl_status') is not None)
                    ssl_healthy = sum(1 for r in results if r.get('ssl_status') == 'healthy')
                    ssl_expired = sum(1 for r in results if r.get('ssl_status') == 'expired')
                    ssl_warning = ssl_total - ssl_healthy - ssl_expired
                    domain_total = sum(1 for r in results if r.get('domain_status') is not None)
                    domain_healthy = sum(1 for r in results if r.get('domain_status') == 'healthy')
                    domain_expired = sum(1 for r in results if r.get('domain_status') == 'expired')
                    domain_warning = domain_total - domain_healthy - domain_expired
                    send_check_complete_summary(smtp_cfg, settings,
                                                ssl_total, ssl_healthy, ssl_warning, ssl_expired,
                                                domain_total, domain_healthy, domain_warning, domain_expired)
                    models.update_last_summary_sent()
            except Exception as e:
                logger.warning("Failed to send check summary for run %s: %s", run_id, e)

            logger.info("Scheduled check completed for %d domains (run %s)", len(domains), run_id)
    except Exception as e:
        logger.error(f"Scheduled check failed: {e}")
    finally:
        _release_check_run()


# ─── Graceful shutdown ────────────────────────────────────────
def shutdown(wait=True):
    """Graceful shutdown. Set wait=True to block until in-flight checks complete (atexit),
    wait=False for signal handlers that must return immediately."""
    logger.info("Shutting down (wait=%s)...", wait)
    _shutdown_event.set()
    try:
        sched_mod.scheduler.shutdown(wait=wait)
    except Exception:
        pass
    try:
        from checker import _whois_executor
        _whois_executor.shutdown(wait=wait)
    except Exception:
        pass


def _handle_sigterm(signum, frame):
    logger.warning("Received signal %d, performing fast shutdown", signum)
    shutdown(wait=False)
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)

# Start scheduler on import so it works under gunicorn (not just `python app.py`)
if not os.environ.get("PYTEST_VERSION"):
    import sys as _sys
    _sys.stderr.write("[vigil] Initialising scheduler at module level...\n")
    _sys.stderr.flush()
    start_scheduler(check_all_background)
    backup.schedule_backup(sched_mod.scheduler)
    atexit.register(shutdown)


def main():
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug)


if __name__ == '__main__':
    main()
