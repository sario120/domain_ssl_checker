from status_utils import ssl_status_from_days, domain_status_from_days, compute_manual_domain_status


class TestSslStatusFromDays:
    def test_none(self):
        assert ssl_status_from_days(None) is None

    def test_expired(self):
        assert ssl_status_from_days(-1) == "expired"
        assert ssl_status_from_days(-30) == "expired"

    def test_critical(self):
        assert ssl_status_from_days(0) == "critical"
        assert ssl_status_from_days(4) == "critical"

    def test_warning(self):
        assert ssl_status_from_days(5) == "warning"
        assert ssl_status_from_days(14) == "warning"

    def test_caution(self):
        assert ssl_status_from_days(15) == "caution"
        assert ssl_status_from_days(19) == "caution"

    def test_watch(self):
        assert ssl_status_from_days(20) == "watch"
        assert ssl_status_from_days(29) == "watch"

    def test_healthy(self):
        assert ssl_status_from_days(30) == "healthy"
        assert ssl_status_from_days(365) == "healthy"


class TestDomainStatusFromDays:
    def test_none(self):
        assert domain_status_from_days(None) is None

    def test_expired(self):
        assert domain_status_from_days(-1) == "expired"

    def test_critical(self):
        assert domain_status_from_days(0) == "critical"
        assert domain_status_from_days(29) == "critical"

    def test_warning(self):
        assert domain_status_from_days(30) == "warning"
        assert domain_status_from_days(59) == "warning"

    def test_caution(self):
        assert domain_status_from_days(60) == "caution"
        assert domain_status_from_days(89) == "caution"

    def test_healthy(self):
        assert domain_status_from_days(90) == "healthy"
        assert domain_status_from_days(365) == "healthy"


class TestComputeManualDomainStatus:
    def test_invalid_date(self):
        days, status, expiry = compute_manual_domain_status("not-a-date")
        assert days is None
        assert status is None
        assert expiry is None

    def test_valid_date(self):
        days, status, expiry = compute_manual_domain_status("2099-12-31")
        assert days is not None
        assert status == "healthy"
        assert expiry == "2099-12-31"
