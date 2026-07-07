from pg_test_utils import reset_test_schema

from models import is_valid_domain, add_domain, get_domain, delete_domain
from models import init_db, init_settings, get_settings, update_settings, get_security_settings
from models import add_user, get_users, get_user, update_user, delete_user, count_admins

TEST_SCHEMA = "vigil_test_models"


def _init_test_db():
    reset_test_schema(TEST_SCHEMA)
    init_db()
    init_settings()


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


class TestUsers:
    def setup_method(self):
        _init_test_db()

    def test_add_user_with_password(self):
        result = add_user("alice", password="Str0ng!Pass", role="user", email="alice@example.com")
        assert result["ok"] is True
        user = get_user(result["id"])
        assert user["username"] == "alice"
        assert user["email"] == "alice@example.com"
        assert user["role"] == "user"
        assert user["is_active"] == 1

    def test_add_user_without_password_is_inactive(self):
        result = add_user("bob", role="viewer", email="bob@example.com")
        assert result["ok"] is True
        user = get_user(result["id"])
        assert user["is_active"] == 0

    def test_add_duplicate_user_fails(self):
        add_user("alice", password="Str0ng!Pass")
        result = add_user("alice", password="Other!Pass1")
        assert result["ok"] is False
        assert "already exists" in result.get("error", "")

    def test_get_users(self):
        add_user("alice", password="Str0ng!Pass")
        add_user("bob", password="Str0ng!Pass")
        users = get_users()
        assert len(users) >= 2
        usernames = [u["username"] for u in users]
        assert "alice" in usernames
        assert "bob" in usernames

    def test_update_user_role(self):
        result = add_user("alice", password="Str0ng!Pass", role="user")
        update_user(result["id"], role="admin")
        user = get_user(result["id"])
        assert user["role"] == "admin"

    def test_update_user_deactivate(self):
        result = add_user("alice", password="Str0ng!Pass")
        update_user(result["id"], is_active=False)
        user = get_user(result["id"])
        assert user["is_active"] == 0

    def test_update_user_reactivate(self):
        result = add_user("alice", password="Str0ng!Pass")
        update_user(result["id"], is_active=True)
        user = get_user(result["id"])
        assert user["is_active"] == 1

    def test_delete_user(self):
        result = add_user("alice", password="Str0ng!Pass")
        user_id = result["id"]
        assert get_user(user_id) is not None
        delete_user(user_id, current_user_id=999)
        assert get_user(user_id) is None

    def test_delete_self_fails(self):
        result = add_user("alice", password="Str0ng!Pass")
        resp = delete_user(result["id"], current_user_id=result["id"])
        assert resp["ok"] is False
        assert "Cannot delete yourself" in resp.get("error", "")

    def test_count_admins_default(self):
        # Default init creates one admin
        assert count_admins() == 1

    def test_count_admins_after_promotion(self):
        result = add_user("alice", password="Str0ng!Pass", role="user")
        assert count_admins() == 1
        update_user(result["id"], role="admin")
        assert count_admins() == 2


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
