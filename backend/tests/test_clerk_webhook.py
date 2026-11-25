import base64
import hashlib
import hmac
import json
import time
from unittest.mock import patch

from app import create_app


def test_missing_webhook_secret():
    app = create_app()
    app.config["TESTING"] = True

    with patch.dict(
        "os.environ",
        {"CLERK_WEBHOOK_SIGNING_SECRET": ""},
    ):
        response = app.test_client().post(
            "/api/webhooks/clerk",
            json={"type": "user.created"},
        )

    assert response.status_code == 503
    assert (
        response.json["error"]["code"]
        == "WEBHOOK_NOT_CONFIGURED"
    )


def test_missing_webhook_signature():
    app = create_app()
    app.config["TESTING"] = True

    with patch.dict(
        "os.environ",
        {"CLERK_WEBHOOK_SIGNING_SECRET": "test-secret"},
    ):
        response = app.test_client().post(
            "/api/webhooks/clerk",
            json={"type": "user.created"},
        )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_WEBHOOK"


def test_valid_user_created_webhook():
    app = create_app()
    app.config["TESTING"] = True

    fake_event = {
        "type": "user.created",
        "data": {
            "id": "user_test123",
            "primary_email_address_id": "email_123",
            "email_addresses": [
                {
                    "id": "email_123",
                    "email_address": "student@example.com",
                    "verification": {
                        "status": "verified",
                    },
                }
            ],
        },
    }

    with (
        patch.dict(
            "os.environ",
            {
                "CLERK_WEBHOOK_SIGNING_SECRET": "test-secret",
            },
        ),
        patch("auth.clerk_webhook.Webhook") as mock_webhook,
        patch("auth.clerk_webhook.SessionLocal") as mock_db,
        patch("auth.clerk_webhook.sync_clerk_user") as mock_sync,
    ):
        # Simulate successful webhook signature verification.
        mock_webhook.return_value.verify.return_value = fake_event

        response = app.test_client().post(
            "/api/webhooks/clerk",
            json=fake_event,
            headers={
                "svix-id": "msg_test123",
                "svix-timestamp": "1234567890",
                "svix-signature": "v1,test-signature",
            },
        )

        mock_sync.assert_called_once()

        args = mock_sync.call_args.args

        assert args[1] == "user_test123"
        assert args[2] == "student@example.com"
        mock_db.begin.assert_called_once()

    assert response.status_code == 200
    assert response.json["status"] == "processed"


def test_valid_webhook_signature():
    app = create_app()
    app.config["TESTING"] = True

    # A test-only signing secret.
    secret_bytes = b"adaptiq-test-webhook-secret-123"
    secret = "whsec_" + base64.b64encode(
        secret_bytes
    ).decode()

    event = {
        "type": "user.created",
        "data": {
            "id": "user_test123",
            "primary_email_address_id": "email_123",
            "email_addresses": [
                {
                    "id": "email_123",
                    "email_address": "student@example.com",
                    "verification": {"status": "verified"},
                }
            ],
        },
    }

    body = json.dumps(event)
    message_id = "msg_adaptiq_test"
    timestamp = str(int(time.time()))

    signed_content = (
        f"{message_id}.{timestamp}.{body}"
    ).encode()

    signature = base64.b64encode(
        hmac.new(
            secret_bytes,
            signed_content,
            hashlib.sha256,
        ).digest()
    ).decode()

    headers = {
        "svix-id": message_id,
        "svix-timestamp": timestamp,
        "svix-signature": f"v1,{signature}",
        "Content-Type": "application/json",
    }

    with (
        patch.dict(
            "os.environ",
            {"CLERK_WEBHOOK_SIGNING_SECRET": secret},
        ),
        patch("auth.clerk_webhook.SessionLocal"),
        patch("auth.clerk_webhook.sync_clerk_user") as mock_sync,
    ):
        response = app.test_client().post(
            "/api/webhooks/clerk",
            data=body,
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json["status"] == "processed"
    mock_sync.assert_called_once()


def test_invalid_webhook_signature():
    app = create_app()
    app.config["TESTING"] = True

    secret_bytes = b"adaptiq-test-webhook-secret-123"

    secret = "whsec_" + base64.b64encode(
        secret_bytes
    ).decode()

    fake_event = {
        "type": "user.created",
        "data": {
            "id": "user_fake123",
        },
    }

    headers = {
        "svix-id": "msg_forged_test",
        "svix-timestamp": str(int(time.time())),
        "svix-signature": "v1," + base64.b64encode(
            b"\x00" * 32
        ).decode(),
    }

    with (
        patch.dict(
            "os.environ",
            {"CLERK_WEBHOOK_SIGNING_SECRET": secret},
        ),
        patch("auth.clerk_webhook.SessionLocal") as mock_db,
        patch(
            "auth.clerk_webhook.sync_clerk_user"
        ) as mock_sync,
    ):
        response = app.test_client().post(
            "/api/webhooks/clerk",
            data=json.dumps(fake_event),
            headers=headers,
            content_type="application/json",
        )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_WEBHOOK"

    # A forged event must never access the database.
    mock_db.begin.assert_not_called()
    mock_sync.assert_not_called()
