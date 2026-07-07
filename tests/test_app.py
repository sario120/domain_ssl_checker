import os

from pg_test_utils import reset_test_schema

TEST_SCHEMA = "vigil_test_app"
os.environ["POSTGRES_SCHEMA"] = TEST_SCHEMA

from app import app
import models


class TestAppRoutes:
    def setup_method(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self._init_db()

    def _init_db(self):
        reset_test_schema(TEST_SCHEMA)
        models.init_db()
        models.init_settings()

    def _login(self, username="admin", password="test-admin-password"):
        return self.client.post("/api/login", json={
            "username": username,
            "password": password,
        }, headers={"Content-Type": "application/json"})

    def _csrf_token(self):
        resp = self.client.get("/api/csrf-token")
        assert resp.status_code == 200
        return resp.get_json()["csrf_token"]

    def _auth_headers(self):
        return {"X-CSRF-Token": self._csrf_token()}

    # ─── Health ─────────────────────────────────────────────────
    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["database"]["status"] == "connected"

    # ─── Metrics ────────────────────────────────────────────────
    def test_metrics_no_auth_required_when_no_token(self):
        old = os.environ.pop("METRICS_TOKEN", None)
        try:
            resp = self.client.get("/api/metrics")
            assert resp.status_code == 200
            assert "vigil_domains_total" in resp.get_data(as_text=True)
        finally:
            if old is not None:
                os.environ["METRICS_TOKEN"] = old

    def test_metrics_requires_token_when_set(self):
        os.environ["METRICS_TOKEN"] = "s3cret"
        try:
            resp = self.client.get("/api/metrics")
            assert resp.status_code == 401
            resp2 = self.client.get("/api/metrics", headers={"Authorization": "Bearer s3cret"})
            assert resp2.status_code == 200
        finally:
            del os.environ["METRICS_TOKEN"]

    # ─── Login / Logout ─────────────────────────────────────────
    def test_login_success_admin(self):
        resp = self._login()
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_login_wrong_password(self):
        resp = self._login(password="wrong")
        assert resp.status_code == 401
        assert "Invalid" in resp.get_json()["error"]

    def test_login_unknown_user(self):
        resp = self._login(username="nobody")
        assert resp.status_code == 401
        assert "Invalid" in resp.get_json()["error"]

    def test_me_authenticated(self):
        self._login()
        resp = self.client.get("/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["authenticated"] is True
        assert data["username"] == "admin"

    def test_me_unauthenticated(self):
        resp = self.client.get("/api/me")
        assert resp.status_code == 401
        assert resp.get_json()["authenticated"] is False

    def test_logout(self):
        self._login()
        resp = self.client.post("/api/logout")
        assert resp.status_code == 200
        resp2 = self.client.get("/api/me")
        assert resp2.get_json()["authenticated"] is False

    # ─── CSRF ───────────────────────────────────────────────────
    def test_csrf_required_on_mutation(self):
        self._login()
        resp = self.client.post("/api/domains", json={"url": "example.com"},
                                headers={"Content-Type": "application/json"})
        assert resp.status_code == 403
        assert "CSRF" in resp.get_json()["error"]

    def test_csrf_rotates_after_use(self):
        self._login()
        token1 = self._csrf_token()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/domains", json={"url": "test-csrf-rotate.com"}, headers=headers)
        assert resp.status_code == 201
        token2 = self._csrf_token()
        assert token2 != token1

    # ─── Domain CRUD ────────────────────────────────────────────
    def test_add_domain(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/domains", json={"url": "example.com"}, headers=headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["id"] > 0

    def test_add_domain_invalid_url(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/domains", json={"url": "-bad-.com"}, headers=headers)
        assert resp.status_code == 400
        assert "Invalid" in resp.get_json()["error"]

    def test_add_domain_missing_url(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/domains", json={}, headers=headers)
        assert resp.status_code == 400

    def test_add_duplicate_domain(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        self.client.post("/api/domains", json={"url": "dup.com"}, headers=headers)
        # Second mutation needs a fresh CSRF token (nonce rotated after first)
        headers2 = self._auth_headers()
        headers2["Content-Type"] = "application/json"
        resp = self.client.post("/api/domains", json={"url": "dup.com"}, headers=headers2)
        assert resp.status_code == 400
        assert "already exists" in resp.get_json()["error"]

    def test_list_domains(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        self.client.post("/api/domains", json={"url": "alpha.com"}, headers=headers)
        headers2 = self._auth_headers()
        headers2["Content-Type"] = "application/json"
        self.client.post("/api/domains", json={"url": "beta.com"}, headers=headers2)
        resp = self.client.get("/api/domains")
        assert resp.status_code == 200
        domains = resp.get_json()
        assert len(domains) >= 2

    def test_get_domain_by_id(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/domains", json={"url": "getbyid.com"}, headers=headers)
        did = add.get_json()["id"]
        resp = self.client.get(f"/api/domains/{did}/cert")
        assert resp.status_code == 200
        assert resp.get_json()["url"] == "getbyid.com"

    def test_get_domain_not_found(self):
        self._login()
        resp = self.client.get("/api/domains/99999/cert")
        assert resp.status_code == 404

    def test_update_domain(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/domains", json={"url": "update-me.com"}, headers=headers)
        did = add.get_json()["id"]
        resp = self.client.put(f"/api/domains/{did}", json={"notes": "updated note"},
                               headers=self._auth_headers())
        assert resp.status_code == 200
        domain = self.client.get(f"/api/domains/{did}/cert").get_json()
        assert domain["notes"] == "updated note"

    def test_delete_domain(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/domains", json={"url": "delete-me.com"}, headers=headers)
        did = add.get_json()["id"]
        resp = self.client.delete(f"/api/domains/{did}", headers=self._auth_headers())
        assert resp.status_code == 200
        resp2 = self.client.get(f"/api/domains/{did}/cert")
        assert resp2.status_code == 404

    # ─── User CRUD ───────────────────────────────────────────────
    def test_list_users(self):
        self._login()
        resp = self.client.get("/api/users")
        assert resp.status_code == 200
        users = resp.get_json()
        assert len(users) >= 1
        assert users[0]["username"] == "admin"

    def test_create_user(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/users", json={
            "username": "newuser", "password": "Str0ng!Pass", "role": "user", "email": "user@test.com"
        }, headers=headers)
        assert resp.status_code == 201
        users = self.client.get("/api/users").get_json()
        assert any(u["username"] == "newuser" for u in users)

    def test_create_user_duplicate(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        self.client.post("/api/users", json={
            "username": "dupuser", "password": "Str0ng!Pass", "role": "user", "email": "dup@test.com"
        }, headers=headers)
        headers2 = self._auth_headers()
        headers2["Content-Type"] = "application/json"
        resp = self.client.post("/api/users", json={
            "username": "dupuser", "password": "Str0ng!Pass2", "role": "user", "email": "dup2@test.com"
        }, headers=headers2)
        assert resp.status_code == 400

    def test_create_user_missing_password(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/users", json={"username": "nopass"}, headers=headers)
        assert resp.status_code == 400

    def test_update_user_role(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/users", json={
            "username": "update-role", "password": "Str0ng!Pass", "role": "user", "email": "role@test.com"
        }, headers=headers)
        uid = add.get_json()["message"]
        # Find the user id
        users = self.client.get("/api/users").get_json()
        target = [u for u in users if u["username"] == "update-role"][0]
        resp = self.client.put(f"/api/users/{target['id']}", json={"role": "admin"},
                               headers=self._auth_headers())
        assert resp.status_code == 200

    def test_self_demote_fails(self):
        self._login()
        resp = self.client.put("/api/users/1", json={"role": "user"},
                               headers=self._auth_headers())
        assert resp.status_code == 403
        assert "Cannot demote your own role" in resp.get_json()["error"]

    def test_self_deactivate_fails(self):
        self._login()
        resp = self.client.put("/api/users/1", json={"is_active": False},
                               headers=self._auth_headers())
        assert resp.status_code == 403

    def test_self_delete_fails(self):
        self._login()
        resp = self.client.delete("/api/users/1", headers=self._auth_headers())
        assert resp.status_code == 403

    def test_deactivate_user(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/users", json={
            "username": "deact-me", "password": "Str0ng!Pass", "role": "user", "email": "deact@test.com"
        }, headers=headers)
        users = self.client.get("/api/users").get_json()
        target = [u for u in users if u["username"] == "deact-me"][0]
        assert target["is_active"] == 1
        resp = self.client.put(f"/api/users/{target['id']}", json={"is_active": False},
                               headers=self._auth_headers())
        assert resp.status_code == 200
        users = self.client.get("/api/users").get_json()
        updated = [u for u in users if u["username"] == "deact-me"][0]
        assert updated["is_active"] == 0

    def test_reactivate_user(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/users", json={
            "username": "react-me", "password": "Str0ng!Pass", "role": "user", "email": "react@test.com"
        }, headers=headers)
        users = self.client.get("/api/users").get_json()
        target = [u for u in users if u["username"] == "react-me"][0]
        # Deactivate first
        self.client.put(f"/api/users/{target['id']}", json={"is_active": False},
                        headers=self._auth_headers())
        # Reactivate
        resp = self.client.put(f"/api/users/{target['id']}", json={"is_active": True},
                               headers=self._auth_headers())
        assert resp.status_code == 200
        users = self.client.get("/api/users").get_json()
        updated = [u for u in users if u["username"] == "react-me"][0]
        assert updated["is_active"] == 1

    def test_delete_last_admin_fails(self):
        self._login()
        resp = self.client.delete("/api/users/1", headers=self._auth_headers())
        assert resp.status_code == 403

    def test_demote_last_admin_fails(self):
        self._login()
        resp = self.client.put("/api/users/1", json={"role": "user"},
                               headers=self._auth_headers())
        assert resp.status_code == 403
        assert "Cannot demote your own role" in resp.get_json()["error"]

    # ─── Cert details ───────────────────────────────────────────
    def test_cert_details_no_domain(self):
        self._login()
        resp = self.client.get("/api/domains/99999/cert")
        assert resp.status_code == 404

    def test_cert_details_pem_from_check_results(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/domains", json={"url": "cert-pem-test.com"}, headers=headers)
        did = add.get_json()["id"]
        # Insert a fake check result with ssl_pem to verify it's loaded from check_results
        models.save_check_results_batch([{
            "domain_id": did, "url": "cert-pem-test.com", "ssl_pem": "FAKE-PEM-DATA",
            "ssl_status": "healthy", "ssl_days_left": 365,
            "status": "healthy", "success": True,
        }])
        resp = self.client.get(f"/api/domains/{did}/cert")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ssl_pem"] == "FAKE-PEM-DATA"

    # ─── Check endpoints ────────────────────────────────────────
    def test_check_all_no_domains(self):
        self._login()
        headers = self._auth_headers()
        resp = self.client.post("/api/check-all", headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["message"] == "No domains to check"

    def test_manual_check_domain_not_found(self):
        self._login()
        headers = self._auth_headers()
        resp = self.client.post("/api/domains/99999/check", headers=headers)
        assert resp.status_code == 404

    # ─── Webapps ────────────────────────────────────────────────
    def test_list_webapps_empty(self):
        self._login()
        resp = self.client.get("/api/webapps")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_add_webapp(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/webapps", json={
            "name": "Test App", "url": "https://example.com/health",
        }, headers=headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["id"] > 0

    def test_add_webapp_missing_name(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        resp = self.client.post("/api/webapps", json={"url": "https://x.com"}, headers=headers)
        assert resp.status_code == 400

    def test_delete_webapp(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        add = self.client.post("/api/webapps", json={
            "name": "Del Me", "url": "https://example.com/del",
        }, headers=headers)
        wid = add.get_json()["id"]
        resp = self.client.delete(f"/api/webapps/{wid}", headers=self._auth_headers())
        assert resp.status_code == 200

    # ─── Unauthenticated access ─────────────────────────────────
    def test_api_requires_auth(self):
        protected = ["/api/domains", "/api/webapps", "/api/settings",
                     "/api/dashboard/summary", "/api/logs"]
        for path in protected:
            resp = self.client.get(path)
            assert resp.status_code in (401, 302), f"{path} returned {resp.status_code}"

    # ─── Dashboard summary ──────────────────────────────────────
    def test_dashboard_summary(self):
        self._login()
        resp = self.client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "full_count" in data

    # ─── Logs ───────────────────────────────────────────────────
    def test_logs_list(self):
        self._login()
        resp = self.client.get("/api/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "logs" in data
        assert isinstance(data["logs"], list)

    # ─── Settings ───────────────────────────────────────────────
    def test_get_settings(self):
        self._login()
        resp = self.client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["smtp_server"] == "smtp.gmail.com"

    # ─── Frontend redirect ──────────────────────────────────────
    def test_root_redirects_to_login(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert "login" in resp.get_data(as_text=True).lower()

    def test_root_redirects_to_dashboard_when_logged_in(self):
        self._login()
        resp = self.client.get("/")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/dashboard"

    def test_dashboard_requires_auth(self):
        resp = self.client.get("/dashboard")
        assert resp.status_code == 302

    # ─── Export ─────────────────────────────────────────────────
    def test_export_json(self):
        self._login()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        self.client.post("/api/domains", json={"url": "export-test.com"}, headers=headers)
        resp = self.client.get("/api/domains/export?format=json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert any(d["url"] == "export-test.com" for d in data)

    def test_export_csv(self):
        self._login()
        resp = self.client.get("/api/domains/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.content_type

    def test_webapp_export_json(self):
        self._login()
        resp = self.client.get("/api/webapps/export/json")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)
