from types import SimpleNamespace
from unittest.mock import patch
from auth.session_sync import SessionAccessDenied
from app import create_app


def test_missing_token():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert response.json["error"]["code"] == "UNAUTHORIZED"



def test_disabled_user():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()

    fake_clerk_state = SimpleNamespace(
        is_signed_in=True,
        payload={
            "sub": "user_test123",
            "sid": "sess_test123",
            "iss": "https://test-clerk.example",
        },
    )

    with (
        patch.dict(
            "os.environ",
            {
                "CLERK_ISSUER": "https://test-clerk.example",
                "CLERK_SECRET_KEY": "test-secret",
                "CLERK_AUTHORIZED_PARTIES": "https://adaptiq.study",
                "CLERK_AUDIENCE": "adaptiq-flask-api",
            },
        ),
        patch(
            "auth.clerk_auth.authenticate_request",
            return_value=fake_clerk_state,
        ),
        patch(
            "auth.clerk_auth.resolve_clerk_session",
            side_effect=SessionAccessDenied(),
        ),
        patch("auth.clerk_auth.SessionLocal"),
    ):
        response = client.get("/api/auth/me")

    assert response.status_code == 403
    assert response.json["error"]["code"] == "ACCESS_DENIED"


def test_invalid_issuer():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()

    fake_clerk_state = SimpleNamespace(
        is_signed_in=True,
        payload={
            "sub": "user_test123",
            "sid": "sess_test123",
            "iss": "https://wrong-issuer.example",
        },
    )

    with (
        patch.dict(
            "os.environ",
            {
                "CLERK_ISSUER": "https://correct-issuer.example",
                "CLERK_SECRET_KEY": "test-secret",
                "CLERK_AUTHORIZED_PARTIES": "https://adaptiq.study",
            },
        ),
        patch(
            "auth.clerk_auth.authenticate_request",
            return_value=fake_clerk_state,
        ),
        patch("auth.clerk_auth.SessionLocal") as mock_db,
    ):
        response = client.get("/api/auth/me")

        # Invalid issuers must be rejected before database access.
        mock_db.assert_not_called()

    assert response.status_code == 401
    assert response.json["error"]["code"] == "UNAUTHORIZED"
