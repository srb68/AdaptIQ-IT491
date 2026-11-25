from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from auth.db_identity import validate_clerk_identity


@pytest.fixture
def identity_data():
    now = datetime.now(timezone.utc)

    user = SimpleNamespace(
        id="internal-user-id",
        is_active=True,
    )

    session = SimpleNamespace(
        user_id=user.id,
        revoked_at=None,
        expires_at=now + timedelta(hours=2),
        idle_expires_at=now + timedelta(minutes=30),
    )

    db = Mock()
    db.scalar.side_effect = [user, session]

    return db, user, session


def test_valid_identity(identity_data):
    db, user, session = identity_data

    result = validate_clerk_identity(
        db, "user_clerk123", "sess_clerk123"
    )

    assert result is user


def test_disabled_account(identity_data):
    db, user, session = identity_data
    user.is_active = False

    result = validate_clerk_identity(
        db, "user_clerk123", "sess_clerk123"
    )

    assert result is None


def test_revoked_session(identity_data):
    db, user, session = identity_data
    session.revoked_at = datetime.now(timezone.utc)

    result = validate_clerk_identity(
        db, "user_clerk123", "sess_clerk123"
    )

    assert result is None


def test_expired_session(identity_data):
    db, user, session = identity_data
    session.expires_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    )

    result = validate_clerk_identity(
        db, "user_clerk123", "sess_clerk123"
    )

    assert result is None


def test_idle_timeout(identity_data):
    db, user, session = identity_data
    session.idle_expires_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    )

    result = validate_clerk_identity(
        db, "user_clerk123", "sess_clerk123"
    )

    assert result is None


def test_unknown_user():
    db = Mock()
    db.scalar.return_value = None

    result = validate_clerk_identity(
        db, "user_unknown", "sess_unknown"
    )

    assert result is None
