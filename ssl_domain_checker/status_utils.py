import datetime


class Status:
    EXPIRED = "expired"
    CRITICAL = "critical"
    WARNING = "warning"
    CAUTION = "caution"
    WATCH = "watch"
    HEALTHY = "healthy"
    PENDING = "pending"
    ERROR = "error"
    SEVERITY = [EXPIRED, CRITICAL, WARNING, CAUTION, WATCH, HEALTHY, PENDING]


def ssl_status_from_days(days):
    if days is None:
        return None
    if days < 0:
        return "expired"
    if days < 5:
        return "critical"
    if days < 15:
        return "warning"
    if days < 20:
        return "caution"
    if days < 30:
        return "watch"
    return "healthy"


def domain_status_from_days(days):
    if days is None:
        return None
    if days < 0:
        return "expired"
    if days < 30:
        return "critical"
    if days < 60:
        return "warning"
    if days < 90:
        return "caution"
    return "healthy"


def compute_manual_domain_status(manual_expiry_date):
    try:
        exp = datetime.datetime.strptime(manual_expiry_date, "%Y-%m-%d")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days = (exp - now).days
        status = domain_status_from_days(days)
        return days, status, manual_expiry_date
    except ValueError:
        return None, None, None
