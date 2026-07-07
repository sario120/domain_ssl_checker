from pg_test_utils import reset_test_schema

from models import add_webapp, get_webapp, get_webapps, get_webapp_by_url, delete_webapp, update_webapp
from models import init_db, init_settings, get_webapp_stats, count_webapps
import models as models_mod

TEST_SCHEMA = "vigil_test_webapps"


def _init_test_db():
    reset_test_schema(TEST_SCHEMA)
    init_db()
    init_settings()


class TestWebappCrud:
    def setup_method(self):
        _init_test_db()

    def test_add_webapp(self):
        result = add_webapp("Test API", "https://api.example.com/health")
        assert result["ok"] is True
        assert "id" in result
        app = get_webapp(result["id"])
        assert app is not None
        assert app["name"] == "Test API"
        assert app["url"] == "https://api.example.com/health"
        assert app["method"] == "GET"

    def test_add_webapp_with_tags(self):
        result = add_webapp("Tagged API", "https://tagged.example.com", tags='["prod","api"]')
        assert result["ok"] is True
        app = get_webapp(result["id"])
        assert app is not None
        assert app["tags"] == '["prod","api"]'

    def test_get_webapp_by_url(self):
        add_webapp("My API", "https://my.api.com/health")
        app = get_webapp_by_url("https://my.api.com/health")
        assert app is not None
        assert app["name"] == "My API"
        assert get_webapp_by_url("https://nonexistent.com") is None

    def test_get_webapps_returns_all(self):
        add_webapp("API A", "https://a.example.com")
        add_webapp("API B", "https://b.example.com")
        apps = get_webapps()
        assert len(apps) == 2

    def test_get_webapps_filtered(self):
        add_webapp("API A", "https://a.example.com")
        add_webapp("API B", "https://b.example.com")
        apps = get_webapps(search="API A")
        assert len(apps) == 1
        assert apps[0]["name"] == "API A"

    def test_get_webapps_filtered_by_status(self):
        r1 = add_webapp("API A", "https://a.example.com")
        r2 = add_webapp("API B", "https://b.example.com")
        models_mod.save_webapp_check(r1["id"], {
            "status": "up", "response_time_ms": 100, "status_code": 200,
            "uptime_count": 1, "downtime_count": 0, "total_checks": 1, "successful_checks": 1
        })
        models_mod.save_webapp_check(r2["id"], {
            "status": "down", "response_time_ms": None, "status_code": 500,
            "error": "Timeout", "uptime_count": 0, "downtime_count": 1,
            "total_checks": 1, "successful_checks": 0
        })
        apps = get_webapps(status="up")
        assert len(apps) == 1
        assert apps[0]["name"] == "API A"

    def test_get_webapps_paginated(self):
        for i in range(5):
            add_webapp(f"API {i}", f"https://api{i}.example.com")
        page1 = get_webapps(page=1, page_size=2)
        assert len(page1) == 2
        page2 = get_webapps(page=2, page_size=2)
        assert len(page2) == 2
        page3 = get_webapps(page=3, page_size=2)
        assert len(page3) == 1

    def test_update_webapp(self):
        result = add_webapp("Old Name", "https://example.com")
        app_id = result["id"]
        update_webapp(app_id, name="New Name", check_interval=60)
        app = get_webapp(app_id)
        assert app["name"] == "New Name"
        assert app["check_interval"] == 60

    def test_delete_webapp(self):
        result = add_webapp("To Delete", "https://delete.example.com")
        app_id = result["id"]
        assert get_webapp(app_id) is not None
        delete_webapp(app_id)
        assert get_webapp(app_id) is None

    def test_count_webapps(self):
        assert count_webapps() == 0
        add_webapp("API A", "https://a.example.com")
        assert count_webapps() == 1
        add_webapp("API B", "https://b.example.com")
        assert count_webapps() == 2

    def test_get_webapp_stats(self):
        stats = get_webapp_stats()
        assert stats["total"] == 0
        r1 = add_webapp("API A", "https://a.example.com")
        models_mod.save_webapp_check(r1["id"], {
            "status": "up", "response_time_ms": 100, "status_code": 200,
            "uptime_count": 1, "downtime_count": 0, "total_checks": 1, "successful_checks": 1
        })
        stats = get_webapp_stats()
        assert stats["total"] == 1
        assert stats["up"] == 1


class TestWebappCheckHistory:
    def setup_method(self):
        _init_test_db()

    def test_save_and_get_check_result(self):
        r = add_webapp("Test", "https://test.example.com")
        app_id = r["id"]
        models_mod.save_webapp_check(app_id, {
            "status": "up", "response_time_ms": 150, "status_code": 200,
            "uptime_count": 1, "downtime_count": 0, "total_checks": 1, "successful_checks": 1
        })
        models_mod.save_webapp_check_result(app_id, {
            "status": "up", "response_time_ms": 150, "status_code": 200
        })
        history = models_mod.get_webapp_check_history(app_id, hours=24)
        assert len(history) == 1
        assert history[0]["response_time_ms"] == 150

    def test_get_webapp_detail_stats(self):
        r = add_webapp("Test", "https://test.example.com")
        app_id = r["id"]
        for i in range(5):
            models_mod.save_webapp_check_result(app_id, {
                "status": "up" if i < 4 else "down",
                "response_time_ms": 100 + i * 10,
                "status_code": 200
            })
        stats = models_mod.get_webapp_detail_stats(app_id)
        assert stats["recent_checks_total"] == 5
        assert stats["recent_checks_up"] == 4
        assert stats["uptime"]["24h"]["uptime_pct"] is not None
        assert stats["incident_count"] >= 1
