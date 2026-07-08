"""Gunicorn config — starts APScheduler after worker boots."""
import os
import sys

_app_pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "ssl_domain_checker")
if _app_pkg not in sys.path:
    sys.path.insert(0, _app_pkg)

workers = 1
threads = 4
bind = "0.0.0.0:" + os.environ.get("PORT", "5000")
timeout = 120
accesslog = "-"
errorlog = "-"
worker_class = "gthread"
graceful_timeout = 30
max_requests = 10000
max_requests_jitter = 1000


def post_worker_init(worker):
    """Called once per worker after the app is fully loaded."""
    if os.environ.get("PYTEST_VERSION"):
        return
    worker.log.info("Starting scheduler (gunicorn worker %s)", worker.pid)
    from app import check_all_background, check_webapps_background, check_dns_background, check_port_background
    from scheduler import start_scheduler
    import backup
    import scheduler as sched_mod
    start_scheduler(check_all_background, check_webapps_background, check_dns_background, check_port_background)
    backup.schedule_backup(sched_mod.scheduler)
