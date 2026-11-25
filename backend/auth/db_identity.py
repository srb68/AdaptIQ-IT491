from datetime import datetime, timezone

from sqlalchemy import select

from db.models import User, Session


def validate_clerk_identity(
    db,
    clerk_user_id: str,
    clerk_session_id: str,
):
    """
    Validate a Clerk identity against PostgreSQL.

    The Clerk IDs must come from a verified token,
    never directly from client-supplied parameters.
    """

    if not clerk_user_id or not clerk_session_id:
        return None

    # Find the user associated with Clerk.
    user = db.scalar(
        select(User).where(
            User.clerk_user_id == clerk_user_id
        )
    )

    if user is None or not user.is_active:
        return None

    # Find the session belonging to this user.
    session = db.scalar(
        select(Session).where(
            Session.clerk_session_id == clerk_session_id,
            Session.user_id == user.id,
        )
    )

    if session is None:
        return None

    now = datetime.now(timezone.utc)

    # Reject revoked sessions.
    if session.revoked_at is not None:
        return None

    # Reject expired sessions.
    if session.expires_at <= now:
        return None

    # Reject sessions that timed out due to inactivity.
    if session.idle_expires_at <= now:
        return None

    return user
