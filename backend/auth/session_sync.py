from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from db.models import User, Session


class SessionAccessDenied(Exception):
    pass


def resolve_clerk_session(
    db,
    clerk_user_id: str,
    clerk_session_id: str,
):
    """
    Resolve a verified Clerk identity to a local session.

    Call only AFTER Clerk has verified the token.
    The caller manages the database transaction.
    """
    if not clerk_user_id or not clerk_session_id:
        raise SessionAccessDenied()

    now = datetime.now(timezone.utc)

    # Lock the user so concurrent requests cannot
    # create duplicate local sessions.
    user = db.scalar(
        select(User)
        .where(User.clerk_user_id == clerk_user_id)
        .with_for_update()
    )

    if user is None or not user.is_active:
        raise SessionAccessDenied()

    session = db.scalar(
        select(Session).where(
            Session.clerk_session_id == clerk_session_id
        )
    )

    if session is None:
        # Initial local session policy. Coordinate these
        # values with the team's Clerk session settings.
        session = Session(
            user_id=user.id,
            clerk_session_id=clerk_session_id,
            expires_at=now + timedelta(hours=8),
            idle_expires_at=now + timedelta(minutes=30),
            last_activity_at=now,
        )

        db.add(session)
        db.flush()

    else:
        if session.user_id != user.id:
            raise SessionAccessDenied()

        if session.revoked_at is not None:
            raise SessionAccessDenied()

        if session.expires_at <= now:
            raise SessionAccessDenied()

        if session.idle_expires_at <= now:
            raise SessionAccessDenied()

        session.last_activity_at = now
        session.idle_expires_at = min(
            now + timedelta(minutes=30),
            session.expires_at,
        )

    return user
