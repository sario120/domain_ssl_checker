from checker import _parse_hostname, _is_private_host, _determine_status


class TestParseHostname:
    def test_strips_protocol(self):
        assert _parse_hostname("https://example.com") == "example.com"
        assert _parse_hostname("http://example.com/path") == "example.com"

    def test_strips_port(self):
        assert _parse_hostname("example.com:443") == "example.com"

    def test_no_protocol(self):
        assert _parse_hostname("example.com") == "example.com"

    def test_strips_trailing_path(self):
        assert _parse_hostname("https://example.com/test?q=1") == "example.com"


class TestIsPrivateHost:
    def test_private_ip(self):
        assert _is_private_host("127.0.0.1") is True
        assert _is_private_host("10.0.0.1") is True
        assert _is_private_host("192.168.1.1") is True

    def test_public_hostname(self):
        assert _is_private_host("example.com") is False

    def test_invalid_hostname(self):
        assert _is_private_host("") is False


class TestDetermineStatus:
    def test_full_domain_pending(self):
        result = {"domain_days_left": None, "domain_status": None}
        assert _determine_status(result, "full") == "pending"

    def test_full_domain_uses_domain_status(self):
        result = {"domain_days_left": 10, "domain_status": "critical"}
        assert _determine_status(result, "full") == "critical"

    def test_full_domain_falls_back_to_days(self):
        result = {"domain_days_left": 10, "domain_status": None}
        assert _determine_status(result, "full") == "critical"

    def test_ssl_only_uses_ssl_status(self):
        result = {"ssl_status": "watch"}
        assert _determine_status(result, "ssl_only") == "watch"

    def test_ssl_only_pending(self):
        result = {"ssl_status": "pending"}
        assert _determine_status(result, "ssl_only") == "pending"
