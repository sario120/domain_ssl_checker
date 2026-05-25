"""
Tests for the webhook module.
"""
from unittest.mock import patch, MagicMock
from webhook import send_webhook_alerts


class TestWebhookAlerts:
    def test_no_webhooks_configured(self):
        settings = {}
        errors = send_webhook_alerts("example.com", "expired", 0, None, settings)
        assert errors == []

    def test_slack_webhook_success(self):
        settings = {"slack_webhook_url": "https://hooks.slack.com/test"}
        with patch("webhook.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            errors = send_webhook_alerts("example.com", "expired", 0, None, settings)
        assert errors == []

    def test_slack_webhook_http_error(self):
        settings = {"slack_webhook_url": "https://hooks.slack.com/test"}
        with patch("webhook.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_post.return_value = mock_response
            errors = send_webhook_alerts("example.com", "expired", 0, None, settings)
        assert len(errors) == 1
        assert "Slack" in errors[0]

    def test_zulip_webhook_success(self):
        settings = {"zulip_webhook_url": "https://zulip.example.com/webhook"}
        with patch("webhook.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            errors = send_webhook_alerts("example.com", "expired", None, 5, settings)
        assert errors == []

    def test_zulip_webhook_http_error(self):
        settings = {"zulip_webhook_url": "https://zulip.example.com/webhook"}
        with patch("webhook.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_post.return_value = mock_response
            errors = send_webhook_alerts("example.com", "expired", None, 5, settings)
        assert len(errors) == 1
        assert "Zulip" in errors[0]

    def test_both_webhooks(self):
        settings = {
            "slack_webhook_url": "https://hooks.slack.com/test",
            "zulip_webhook_url": "https://zulip.example.com/webhook",
        }
        with patch("webhook.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            errors = send_webhook_alerts("example.com", "warning", 10, 20, settings)
        assert errors == []
        assert mock_post.call_count == 2
