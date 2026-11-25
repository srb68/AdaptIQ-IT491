from sqlalchemy import select
from db.models import User


def sync_clerk_user(db, clerk_user_id, email):
    """Create or update the database user linked to Clerk."""

    if not clerk_user_id or not email:
        raise ValueError("Clerk user ID and email are required")

    user = db.scalar(
        select(User).where(
            User.clerk_user_id == clerk_user_id
        )
    )

    if user is not None:
        return user

    # Avoid silently linking an existing account
    # based only on an email address.
    existing_email = db.scalar(
        select(User).where(User.email == email)
    )

    if existing_email is not None:
        raise ValueError(
            "Existing email requires account linking"
        )

    user = User(
        clerk_user_id=clerk_user_id,
        email=email,
        is_active=True,
    )

    db.add(user)
    db.flush()

    return user
