import os
import uuid

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as DBSession

from auth.session_sync import (
    resolve_clerk_session,
    SessionAccessDenied,
)
from db.models import User, Session


load_dotenv(".env")

source_url = make_url(os.environ["DATABASE_URL"])

if source_url.database != "adaptiq_dev":
    raise RuntimeError("Unexpected database configuration")

engine = create_engine(
    source_url.set(database="adaptiq_test")
)


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()

        try:
            with DBSession(
                bind=connection,
                join_transaction_mode="create_savepoint",
            ) as session:
                yield session
        finally:
            transaction.rollback()


@pytest.fixture
def user(db):
    user = User(
        clerk_user_id=f"user_test_{uuid.uuid4().hex}",
        email=f"test_{uuid.uuid4().hex}@example.com",
        is_active=True,
    )

    db.add(user)
    db.flush()

    return user


def test_create_session(db, user):
    clerk_session_id = f"sess_{uuid.uuid4().hex}"

    result = resolve_clerk_session(
        db,
        user.clerk_user_id,
        clerk_session_id,
    )

    assert result.id == user.id

    saved_session = db.scalar(
        select(Session).where(
            Session.clerk_session_id == clerk_session_id
        )
    )

    assert saved_session is not None
    assert saved_session.user_id == user.id


def test_existing_session_not_duplicated(db, user):
    clerk_session_id = f"sess_{uuid.uuid4().hex}"

    resolve_clerk_session(
        db, user.clerk_user_id, clerk_session_id
    )

    resolve_clerk_session(
        db, user.clerk_user_id, clerk_session_id
    )

    sessions = db.scalars(
        select(Session).where(
            Session.clerk_session_id == clerk_session_id
        )
    ).all()

    assert len(sessions) == 1


def test_revoked_session_rejected(db, user):
    clerk_session_id = f"sess_{uuid.uuid4().hex}"

    resolve_clerk_session(
        db, user.clerk_user_id, clerk_session_id
    )

    session = db.scalar(
        select(Session).where(
            Session.clerk_session_id == clerk_session_id
        )
    )

    from datetime import datetime, timezone

    session.revoked_at = datetime.now(timezone.utc)
    db.flush()

    with pytest.raises(SessionAccessDenied):
        resolve_clerk_session(
            db, user.clerk_user_id, clerk_session_id
        )


def test_disabled_user_rejected(db, user):
    user.is_active = False
    db.flush()

    with pytest.raises(SessionAccessDenied):
        resolve_clerk_session(
            db,
            user.clerk_user_id,
            f"sess_{uuid.uuid4().hex}",
        )


def test_session_owner_mismatch(db, user):
    clerk_session_id = f"sess_{uuid.uuid4().hex}"

    resolve_clerk_session(
        db, user.clerk_user_id, clerk_session_id
    )

    other_user = User(
        clerk_user_id=f"user_other_{uuid.uuid4().hex}",
        email=f"other_{uuid.uuid4().hex}@example.com",
        is_active=True,
    )

    db.add(other_user)
    db.flush()

    with pytest.raises(SessionAccessDenied):
        resolve_clerk_session(
            db,
            other_user.clerk_user_id,
            clerk_session_id,
        )
