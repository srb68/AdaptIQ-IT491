import os
import uuid

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from auth.clerk_sync import sync_clerk_user
from db.models import User


load_dotenv(".env")

source_url = make_url(os.environ["DATABASE_URL"])

if source_url.database != "adaptiq_dev":
    raise RuntimeError(
        "Tests must be configured from adaptiq_dev"
    )

test_engine = create_engine(
    source_url.set(database="adaptiq_test")
)


@pytest.fixture
def db():
    with test_engine.connect() as connection:
        transaction = connection.begin()

        with Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
        ) as session:
            try:
                yield session
            finally:
                session.close()
                transaction.rollback()


def test_create_clerk_user(db):
    clerk_id = f"user_test_{uuid.uuid4().hex}"
    email = f"student_{uuid.uuid4().hex}@example.com"

    user = sync_clerk_user(db, clerk_id, email)

    assert user.clerk_user_id == clerk_id
    assert user.email == email
    assert user.is_active is True

    # Confirm the user was actually inserted.
    saved_user = db.scalar(
        select(User).where(
            User.clerk_user_id == clerk_id
        )
    )

    assert saved_user is not None
    assert saved_user.id == user.id


def test_duplicate_clerk_user(db):
    clerk_id = f"user_test_{uuid.uuid4().hex}"
    email = f"student_{uuid.uuid4().hex}@example.com"

    first = sync_clerk_user(db, clerk_id, email)
    second = sync_clerk_user(db, clerk_id, email)

    assert first.id == second.id

    users = db.scalars(
        select(User).where(
            User.clerk_user_id == clerk_id
        )
    ).all()

    assert len(users) == 1


def test_existing_email_not_auto_linked(db):
    email = f"student_{uuid.uuid4().hex}@example.com"

    first = sync_clerk_user(
        db,
        f"user_original_{uuid.uuid4().hex}",
        email,
    )

    with pytest.raises(
        ValueError,
        match="Existing email requires account linking",
    ):
        sync_clerk_user(
            db,
            f"user_different_{uuid.uuid4().hex}",
            email,
        )

    assert first.id is not None
