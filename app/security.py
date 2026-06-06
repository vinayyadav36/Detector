from __future__ import annotations

import logging
import sys
import time

import structlog
from flask import Flask, g, request
from flask_talisman import Talisman


def configure_security(app: Flask) -> None:
    Talisman(
        app,
        content_security_policy=app.config["CSP"],
        content_security_policy_nonce_in=[],
        force_https=app.config["FLASK_ENV"] == "production",
        frame_options="DENY",
        strict_transport_security=app.config["FLASK_ENV"] == "production",
        strict_transport_security_max_age=31536000,
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy={"geolocation": "()", "microphone": "()", "camera": "()"},
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=True,
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )

def configure_logging(app: Flask) -> None:
    import os
    log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    structlog.configure(
        processors=[
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stderr)
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    logging.getLogger("werkzeug").handlers.clear()
    logging.getLogger("werkzeug").addHandler(handler)

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)

    logger = structlog.get_logger("app")

    @app.before_request
    def start_request_timer() -> None:
        g.started_at = time.perf_counter()

    @app.after_request
    def log_request(response):
        duration_ms = round(
            (time.perf_counter() - getattr(g, "started_at", time.perf_counter()))
            * 1000,
            2,
        )
        logger.info(
            "request_complete",
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            remote_addr=request.remote_addr,
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response
