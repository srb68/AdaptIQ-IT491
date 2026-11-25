import os
import json
from sqlalchemy.exc import SQLAlchemyError

from auth.clerk_sync import sync_clerk_user
from db.connection import SessionLocal
from flask import Blueprint, jsonify, request
from svix.webhooks import Webhook, WebhookVerificationError


clerk_webhook_bp = Blueprint("clerk_webhook", __name__)


@clerk_webhook_bp.post("/api/webhooks/clerk")
def clerk_webhook():
    """Verify incoming Clerk webhook events."""

    signing_secret = os.getenv(
        "CLERK_WEBHOOK_SIGNING_SECRET"
    )

    if not signing_secret:
        return jsonify({
            "error": {
                "code": "WEBHOOK_NOT_CONFIGURED",
                "message": "Webhook unavailable",
            }
        }), 503

    # Use the original request body for signature verification.
    payload = request.get_data(as_text=True)

    headers = {
        "svix-id": request.headers.get("svix-id", ""),
        "svix-timestamp": request.headers.get(
            "svix-timestamp", ""
        ),
        "svix-signature": request.headers.get(
            "svix-signature", ""
        ),
    }

    if not all(headers.values()):
        return jsonify({
            "error": {
                "code": "INVALID_WEBHOOK",
                "message": "Missing webhook signature",
            }
        }), 400


    try:
        # Verify that the original request body
        # was signed using Clerk's webhook secret.
        Webhook(signing_secret).verify(
            payload,
            headers,
        )

    except WebhookVerificationError:
        return jsonify({
            "error": {
                "code": "INVALID_WEBHOOK",
                "message": "Invalid webhook signature",
            }
        }), 400

    # Parse the event only after successful verification.
    try:
        event = json.loads(payload)

        if not isinstance(event, dict):
            raise ValueError("Invalid event format")

    except (json.JSONDecodeError, ValueError):
        return jsonify({
            "error": {
                "code": "INVALID_WEBHOOK",
                "message": "Invalid webhook payload",
            }
        }), 400


    # For now, acknowledge only verified events.
    # Database synchronization will be added next.

    event_type = event.get("type")
    data = event.get("data") or {}

    # For now, process only new-user events.
    if event_type != "user.created":
        return jsonify({
            "error": {
                "code": "EVENT_NOT_IMPLEMENTED",
                "message": "Webhook event handling unavailable",
            }
        }), 503

    clerk_user_id = data.get("id")
    primary_email_id = data.get("primary_email_address_id")

    # Find the user's verified primary email.
    verified_email = None

    for email_record in data.get("email_addresses", []):
        verification = email_record.get("verification") or {}

        if (
            email_record.get("id") == primary_email_id
            and verification.get("status") == "verified"
        ):
            verified_email = email_record.get("email_address")
            break

    if not clerk_user_id or not verified_email:
        return jsonify({
            "error": {
                "code": "INVALID_USER_DATA",
                "message": "Verified primary email unavailable",
            }
        }), 422

    try:
        with SessionLocal.begin() as db:
            sync_clerk_user(
                db,
                clerk_user_id,
                verified_email,
            )

    except (SQLAlchemyError, ValueError):
        return jsonify({
            "error": {
                "code": "USER_SYNC_FAILED",
                "message": "Account synchronization failed",
            }
        }), 503

    return jsonify({
        "status": "processed",
    }), 200

