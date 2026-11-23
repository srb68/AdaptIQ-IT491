from flask import Flask, jsonify, request

from rate_limit import TokenBucketLimiter


def create_app():
    app = Flask(__name__)
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

    return app
