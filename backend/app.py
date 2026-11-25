from flask import Flask, jsonify, request
from auth.clerk_auth import clerk_required
from rate_limit import TokenBucketLimiter
from auth.clerk_webhook import clerk_webhook_bp

def create_app():
    app = Flask(__name__)
    app.register_blueprint(clerk_webhook_bp)
    demo_limiter = TokenBucketLimiter(capacity=5, refill_per_second=0.5)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/rate-limit-demo")
    def rate_limit_demo():
        retry_after = demo_limiter.consume(request.remote_addr or "unknown")
        headers = {"Cache-Control": "no-store"}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)
            return jsonify(error="rate_limit_exceeded"), 429, headers

        return jsonify(status="allowed"), 200, headers


    @app.get("/api/auth/me")
    @clerk_required
    def current_user():
        from flask import g

        return jsonify({
            "authenticated": True,
            "clerk_user_id": g.clerk_user_id,
            "clerk_session_id": g.clerk_session_id,
        })

    return app
