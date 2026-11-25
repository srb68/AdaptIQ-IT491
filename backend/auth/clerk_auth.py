
import os
from functools import wraps

from dotenv import load_dotenv
from flask import g, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from clerk_backend_api import (
    AuthenticateRequestOptions,
    authenticate_request,
)

from db.connection import SessionLocal

from auth.session_sync import (
    resolve_clerk_session,
    SessionAccessDenied,
)

load_dotenv()


def auth_error(code, message, status):
    """Return a consistent authentication error."""
    response = jsonify({
        "error": {
            "code": code,
            "message": message,
        }
    })
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"

    if status == 401:
        response.headers["WWW-Authenticate"] = "Bearer"

    return response


def clerk_required(view):
    """Require a valid Clerk token and PostgreSQL session."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        secret_key = os.getenv("CLERK_SECRET_KEY")

        authorized_parties = [
            origin.strip()
            for origin in os.getenv(
                "CLERK_AUTHORIZED_PARTIES", ""
            ).split(",")
            if origin.strip()
        ]

        if (
            not secret_key
            or not authorized_parties
            or not os.getenv("CLERK_AUDIENCE")
        ):
            return auth_error(
                "AUTH_NOT_CONFIGURED",
                "Authentication unavailable",
                503,
            )

        # Verify the Clerk-issued token.
        try:
            state = authenticate_request(
                request,
                AuthenticateRequestOptions(
                    secret_key=secret_key,
                    authorized_parties=authorized_parties,
                    audience=os.environ["CLERK_AUDIENCE"],
                    accepts_token=["session_token"],
                ),
            )
        except Exception:
            return auth_error(
                "AUTH_SERVICE_ERROR",
                "Authentication unavailable",
                503,
            )

        if not state.is_signed_in:
            return auth_error(
                "UNAUTHORIZED",
                "Invalid or expired authentication",
                401,
            )


        # These claims come from the Clerk-verified token.
        payload = state.payload or {}

        expected_issuer = os.getenv("CLERK_ISSUER")

        if not expected_issuer:
            return auth_error(
                "AUTH_NOT_CONFIGURED",
                "Authentication unavailable",
                503,
            )

        if payload.get("iss") != expected_issuer:
            return auth_error(
                "UNAUTHORIZED",
                "Invalid authentication token",
                401,
            )

        clerk_user_id = payload.get("sub")
        clerk_session_id = payload.get("sid")

        if not clerk_user_id or not clerk_session_id:
            return auth_error(
                "UNAUTHORIZED",
                "Missing authenticated identity",
                401,
            )

        # Validate user and session in PostgreSQL.

        # Validate the verified Clerk identity in PostgreSQL.
        try:
            with SessionLocal.begin() as db:
                user = resolve_clerk_session(
                    db,
                    clerk_user_id,
                    clerk_session_id,
                )

                # Store the authenticated identity for
                # use by protected Flask routes.
                g.user_id = user.id
                g.clerk_user_id = clerk_user_id
                g.clerk_session_id = clerk_session_id

        except SessionAccessDenied:
            return auth_error(
                "ACCESS_DENIED",
                "Account or session is not authorized",
                403,
            )

        except SQLAlchemyError:
            return auth_error(
                "DATABASE_UNAVAILABLE",
                "Authentication temporarily unavailable",
                503,
            )

        return view(*args, **kwargs)

    return wrapper
