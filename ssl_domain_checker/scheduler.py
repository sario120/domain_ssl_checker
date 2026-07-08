import fcntl
import logging
import os
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(
    daemon=True,
    job_defaults={
        'coalesce': True,
        'max_instances': 1,
        'misfire_grace_time': 300,
    }
)

_lock_fh = None


def _try_acquire_lock():
    global _lock_fh
    lock_path = os.environ.get('SCHEDULER_LOCK_FILE', '/tmp/vigil_scheduler.lock')
    try:
        _lock_fh = open(lock_path, 'w')
        fcntl.flock(_lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logger.info("Scheduler lock acquired (pid %d)", os.getpid())
        return True
    except (BlockingIOError, OSError):
        if _lock_fh:
            _lock_fh.close()
            _lock_fh = None
        return False


def start_scheduler(check_all_callback, check_webapps_callback=None, check_dns_callback=None):
    if scheduler.get_job('check_all_domains'):
        return
    if not _try_acquire_lock():
        logger.info("Scheduler already running in another worker — skipping")
        return

    interval_hours = int(os.environ.get('SCHEDULER_INTERVAL_HOURS', '24'))
    scheduler.add_job(
        check_all_callback,
        'interval',
        hours=interval_hours,
        id='check_all_domains',
        name='Check all domains',
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    if check_webapps_callback:
        scheduler.add_job(
            check_webapps_callback,
            'interval',
            minutes=1,
            id='check_webapps',
            name='Check webapps',
        )
    if check_dns_callback:
        scheduler.add_job(
            check_dns_callback,
            'interval',
            minutes=1,
            id='check_dns',
            name='Check DNS records',
        )
    retention_days = int(os.environ.get('DATA_RETENTION_DAYS', '90'))
    if not scheduler.get_job('cleanup_old_data'):
        from models import cleanup_old_data
        scheduler.add_job(
            cleanup_old_data,
            CronTrigger(hour=4, minute=0),
            args=[retention_days],
            id='cleanup_old_data',
            name='Cleanup old check history and logs',
        )
        logger.info("Data cleanup scheduled daily at 04:00 (retention: %d days)", retention_days)

    scheduler.start()
    logger.info("Scheduler started — checking all domains every %d hours", interval_hours)


def get_next_scheduled_check():
    job = scheduler.get_job('check_all_domains')
    webapp_job = scheduler.get_job('check_webapps')
    result = {}
    if job and job.next_run_time:
        result['next_run'] = job.next_run_time.isoformat()
        result['domain_interval_hours'] = int(os.environ.get('SCHEDULER_INTERVAL_HOURS', '24'))
    if webapp_job:
        result['webapp_interval_seconds'] = 60  # runs every 1 minute
    return result if result else None
