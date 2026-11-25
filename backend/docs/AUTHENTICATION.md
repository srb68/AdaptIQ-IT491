# AdaptIQ Flask Authentication

## Overview

AdaptIQ uses Clerk for user authentication and PostgreSQL
for application-specific user and session validation.

Protected Flask endpoints use the `@clerk_required` decorator.

## Authentication flow

1. The frontend signs the user in through Clerk.
2. Clerk issues an authenticated session token.
3. The frontend sends the token to the Flask backend.
4. Flask verifies the token using Clerk's Python SDK.
5. Flask validates the user and session in PostgreSQL.
6. The protected endpoint executes only if authorization succeeds.

## Protecting Coaching Routes

Justin can protect a Flask route using:

```python
from flask import Blueprint, g, jsonify
from auth.clerk_auth import clerk_required

coaching_bp = Blueprint("coaching", __name__)

@coaching_bp.get("/api/coaching/profile")
@clerk_required
def coaching_profile():
    return jsonify({
        "user_id": str(g.user_id),
        "authenticated": True,
    })
```

The blueprint must also be registered in the shared Flask application.

## Authenticated Identity

After successful authentication:

- `g.user_id` contains the internal PostgreSQL user UUID.
- `g.clerk_user_id` contains the verified Clerk user ID.
- `g.clerk_session_id` contains the verified Clerk session ID.

Use `g.user_id` to scope database queries to the authenticated user.

Authentication alone does not grant access to other users'
coaching records. Routes must enforce ownership and authorization.

## Authentication Errors

The backend returns structured JSON errors:

- `401 UNAUTHORIZED`: Missing, invalid, or expired authentication.
- `403 ACCESS_DENIED`: Account or local session is not authorized.
- `503 AUTH_NOT_CONFIGURED`: Authentication configuration missing.
- `503 DATABASE_UNAVAILABLE`: Authentication database unavailable.

## Environment Configuration

Required backend environment variables:

- `DATABASE_URL`
- `CLERK_SECRET_KEY`
- `CLERK_ISSUER`
- `CLERK_AUDIENCE`
- `CLERK_AUTHORIZED_PARTIES`

Webhook synchronization additionally requires:

- `CLERK_WEBHOOK_SIGNING_SECRET`

Never commit actual credentials to Git.

## Testing

Run the backend tests:

```bash
python -m pytest tests/ -v
```

## Integration Notes

Clerk user records are synchronized to PostgreSQL through
verified account events.

The frontend must send supported Clerk session tokens.

The frontend and backend teams must agree on the token
audience and authorized origins.

Live Clerk sign-in, webhook delivery, and account lifecycle
integration must be verified before production deployment.
