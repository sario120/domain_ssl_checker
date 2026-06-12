import os
import tempfile
import shutil
import atexit
from models import is_valid_domain, add_domain, get_domain, delete_domain
from models import init_db, init_settings, get_settings, update_settings, get_security_settings, close_db


_test_dirs = []


def _cleanup_all():
    for d in _test_dirs:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_all)


import models as models_mod


def _init_test_db():
    close_db()
    tmpdir = tempfile.mkdtemp(prefix="vigil_test_")
    _test_dirs.append(tmpdir)
    db_path = os.path.join(tmpdir, "test.db")
    models_mod.DB_PATH = db_path
    os.environ["DB_PATH"] = db_path
    init_db()
    init_settings()
    return db_path


class TestIsValidDomain:
    def test_valid_domains(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("my-domain.io") is True
        assert is_valid_domain("xn--bcher-kva.ch") is True

    def test_invalid_domains(self):
        assert is_valid_domain("") is False
        assert is_valid_domain("-bad.com") is False
        assert is_valid_domain("bad-.com") is False
        assert is_valid_domain("a") is False
        assert is_valid_domain(".com") is False

    def test_strips_protocol(self):
        assert is_valid_domain("https://example.com") is True
        assert is_valid_domain("http://example.com") is True

    def test_strips_path(self):
        assert is_valid_domain("example.com/path") is True
        assert is_valid_domain("example.com:8080") is True


class TestCrud:
    def setup_method(self):
        _init_test_db()

    def test_add_and_get_domain(self):
        result = add_domain("example.com", "full", "test notes")
        assert result["ok"] is True
        domain = get_domain(result["id"])
        assert domain is not None
        assert domain["url"] == "example.com"
        assert domain["type"] == "full"
        assert domain["notes"] == "test notes"

    def test_add_duplicate_domain_fails(self):
        add_domain("example.com")
        result = add_domain("example.com")
        assert result["ok"] is False
        assert "already exists" in result.get("error", "")

    def test_delete_domain(self):
        result = add_domain("example.com")
        domain_id = result["id"]
        assert get_domain(domain_id) is not None
        delete_domain(domain_id)
        assert get_domain(domain_id) is None


class TestSettings:
    def setup_method(self):
        _init_test_db()

    def test_default_settings(self):
        settings = get_settings()
        assert settings is not None
        assert settings["smtp_server"] == "smtp.gmail.com"
        assert settings["smtp_port"] == 587
        assert settings["smtp_enabled"] == 0
        assert settings["ssl_alert_threshold"] == 30
        assert settings["domain_alert_threshold"] == 30

    def test_update_settings(self):
        update_settings({"ssl_alert_threshold": 15, "domain_alert_threshold": 60})
        settings = get_settings()
        assert settings["ssl_alert_threshold"] == 15
        assert settings["domain_alert_threshold"] == 60

    def test_webhook_settings_fields(self):
        update_settings({
            "slack_webhook_url": "https://hooks.slack.com/test",
            "slack_enabled": 1,
            "zulip_webhook_url": "https://zulip.example.com/webhook",
            "zulip_enabled": 1,
        })
        settings = get_settings()
        assert settings["slack_webhook_url"] == "https://hooks.slack.com/test"
        assert settings["slack_enabled"] == 1


class TestSecuritySettings:
    def setup_method(self):
        _init_test_db()

    def test_default_security_settings(self):
        sec = get_security_settings()
        assert sec["session_timeout"] == 60
        assert sec["max_login_attempts"] == 5
        assert sec["min_password_length"] == 8
        assert sec["require_uppercase"] == 1
        assert sec["require_special"] == 0
