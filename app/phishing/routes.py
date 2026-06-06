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

from .services import filtered_reports, serialize_analysis

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
    if not url:
        return jsonify({"error": {"type": "invalid_url", "message": "URL is required"}}), 400

    # We validate URL before queueing to avoid queueing junk
    from .heuristics import validate_url
    ok, message = validate_url(url)
    if not ok:
        current_app.logger.warning("invalid_analysis_input", extra={"path": request.path, "method": request.method})
        return jsonify({"error": {"type": "invalid_url", "message": message}}), 400

    from app.celery_app import analyze_url_task
    task = analyze_url_task.delay(url)
    return jsonify({"job_id": task.id, "status": "queued"})

@bp.route("/api/status/<job_id>")
def api_status(job_id: str):
    from app.celery_app import analyze_url_task
    task = analyze_url_task.AsyncResult(job_id)
    if task.state == 'PENDING' or task.state == 'STARTED':
        return jsonify({"status": "queued"})
    elif task.state == 'SUCCESS':
        # The task returns the dict from run_analysis
        result_dict = task.result
        # Load from DB to serialize
        analysis_id = result_dict.get('analysis_id')
        if analysis_id:
            analysis = db.session.get(Analysis, analysis_id)
            if analysis:
                payload = serialize_analysis(analysis)
                payload["status"] = "completed"
                return jsonify(payload)
        return jsonify({"error": "Analysis completed but result not found"}), 404
    else:
        return jsonify({"status": "failed", "error": str(task.info)}), 500



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


@bp.route("/api/feedback", methods=["POST"])
def api_feedback():
    payload = request.get_json(silent=True) or {}
    analysis_id = payload.get("analysis_id")
    if not analysis_id:
        return jsonify({"error": "analysis_id is required"}), 400
    analysis = Analysis.query.get_or_404(analysis_id)
    user_label = payload.get("user_label")
    correct_label = payload.get("correct_label")
    db.session.add(Feedback(analysis_id=analysis.id, user_label=user_label, correct_label=correct_label))
    db.session.commit()
    return jsonify({"status": "recorded"})

from flask_wtf.csrf import generate_csrf


@bp.route("/api/csrf-token")
def api_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})
