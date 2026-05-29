from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    send_from_directory,
)

from app.extensions import limiter
from app.models import Analysis, Feedback, db

from .heuristics import AnalysisInputError
from .services import filtered_reports, run_analysis, serialize_analysis

bp = Blueprint("phishing", __name__)


def _serve_index():
    return send_from_directory(current_app.static_folder, "index.html")


@bp.route("/")
def index():
    return _serve_index()


@bp.route("/result/<int:analysis_id>")
def result_detail(analysis_id: int):
    # Still want to 404 if it doesn't exist, though UI can handle that too
    return _serve_index()


@bp.route("/offline")
def offline():
    return _serve_index()


@bp.route("/disclaimer")
def disclaimer():
    return _serve_index()


@bp.route("/privacy")
def privacy():
    return _serve_index()


@bp.route("/terms")
def terms():
    return _serve_index()



@bp.route("/admin")
def admin():
    return _serve_index()

@bp.route("/manifest.json")
def manifest():
    return send_from_directory(current_app.static_folder, "manifest.json", mimetype="application/manifest+json")


@bp.route("/sw.js")
def service_worker():
    response = send_from_directory(current_app.static_folder, "sw.js", mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@bp.route("/api/analyze", methods=["POST"])
@limiter.limit(lambda: current_app.config["ANALYZE_RATE_LIMIT"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    try:
        result = run_analysis(url, current_app.config)
    except AnalysisInputError as exc:
        current_app.logger.warning("invalid_analysis_input", extra={"path": request.path, "method": request.method})
        return jsonify({"error": {"type": exc.error_type, "message": exc.message}}), 400
    analysis = db.session.get(Analysis, result.analysis_id)
    return jsonify(serialize_analysis(analysis))


@bp.route("/api/result/<int:analysis_id>")
def api_result(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    return jsonify(serialize_analysis(analysis))


@bp.route("/api/reports")
@limiter.limit(lambda: current_app.config["REPORTS_RATE_LIMIT"])
def api_reports():
    pagination = filtered_reports(
        page=max(int(request.args.get("page", 1)), 1),
        per_page=min(max(int(request.args.get("per_page", 20)), 1), 100),
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    return jsonify(
        {
            "items": [serialize_analysis(item) for item in pagination.items],
            "pagination": {
                "page": pagination.page,
                "pages": pagination.pages,
                "per_page": pagination.per_page,
                "total": pagination.total,
            },
        }
    )


@bp.route("/api/export/json")
@limiter.limit(lambda: current_app.config["REPORTS_RATE_LIMIT"])
def api_export_json():
    pagination = filtered_reports(
        page=1,
        per_page=min(max(int(request.args.get("per_page", 100)), 1), 500),
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    return jsonify({"items": [serialize_analysis(item) for item in pagination.items]})


@bp.route("/feedback/<int:analysis_id>", methods=["POST"])
def feedback(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    db.session.add(Feedback(analysis_id=analysis.id))
    db.session.commit()
    return jsonify({"status": "recorded"})

from flask_wtf.csrf import generate_csrf

@bp.route("/api/csrf-token")
def api_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})
