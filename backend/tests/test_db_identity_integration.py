import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as DBSession

from auth.db_identity import validate_clerk_identity
from db.models import User, Session


load_dotenv(".env")

# Use a dedicated test database, never the development database.
source_url = make_url(os.environ["DATABASE_URL"])

if source_url.database != "adaptiq_dev":
    raise RuntimeError("Unexpected source database")

test_url = source_url.set(database="adaptiq_test")

engine = create_engine(
    test_url,
    pool_pre_ping=True,
)


@pytest.fixture
def db():
    # Outer transaction is rolled back after each test.
    with engine.connect() as connection:
        transaction = connection.begin()

        with DBSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
        ) as session:
            try:
                yield session
            finally:
                session.close()
                transaction.rollback()


@pytest.fixture
def identity(db):
    now = datetime.now(timezone.utc)

    user = User(
        id=uuid.uuid4(),
        clerk_user_id=f"user_test_{uuid.uuid4().hex}",
        email=f"test_{uuid.uuid4().hex}@example.com",
        is_active=True,
    )

    db.add(user)
    db.flush()

    session = Session(
        id=uuid.uuid4(),
        user_id=user.id,
        clerk_session_id=f"sess_test_{uuid.uuid4().hex}",
        expires_at=now + timedelta(hours=2),
        idle_expires_at=now + timedelta(minutes=30),
    )

    db.add(session)
    db.flush()

    return user, session


def test_valid_identity(db, identity):
    user, session = identity

    result = validate_clerk_identity(
        db, user.clerk_user_id, session.clerk_session_id
    )

    assert result is not None
    assert result.id == user.id


def test_disabled_user(db, identity):
    user, session = identity
    user.is_active = False
    db.flush()

    assert validate_clerk_identity(
        db, user.clerk_user_id, session.clerk_session_id
    ) is None


def test_revoked_session(db, identity):
    user, session = identity
    session.revoked_at = datetime.now(timezone.utc)
    db.flush()

    assert validate_clerk_identity(
        db, user.clerk_user_id, session.clerk_session_id
    ) is None



def test_expired_session(db, identity):
    user, session = identity

    session.created_at = (
        datetime.now(timezone.utc) - timedelta(days=2)
    )
    session.expires_at = (
        datetime.now(timezone.utc) - timedelta(days=1)
    )
    session.idle_expires_at = (
        datetime.now(timezone.utc) - timedelta(days=1, hours=1)
    )

    db.flush()

    assert validate_clerk_identity(
        db, user.clerk_user_id, session.clerk_session_id
    ) is None



def test_idle_timeout(db, identity):
    user, session = identity

    now = datetime.now(timezone.utc)

    # Simulate a session created two hours ago.
    session.created_at = now - timedelta(hours=2)

    # Its inactivity deadline passed one minute ago.
    session.idle_expires_at = now - timedelta(minutes=1)

    # The overall session is still valid.
    session.expires_at = now + timedelta(hours=2)

    db.flush()

    assert validate_clerk_identity(
        db,
        user.clerk_user_id,
        session.clerk_session_id,
    ) is None



def test_session_owner_mismatch(db, identity):
    user, session = identity

    other_user = User(
        id=uuid.uuid4(),
        clerk_user_id=f"user_other_{uuid.uuid4().hex}",
        email=f"other_{uuid.uuid4().hex}@example.com",
        is_active=True,
    )

    db.add(other_user)
    db.flush()

    # Try to pair another user's Clerk identity
    # with the original user's session.
    assert validate_clerk_identity(
        db,
        other_user.clerk_user_id,
        session.clerk_session_id,
    ) is None
