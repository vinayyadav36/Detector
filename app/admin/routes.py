from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, current_app, jsonify, request, send_file
from flask_login import current_user, login_required, login_user, logout_user
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash

from app.extensions import limiter
from app.models import Analysis, Blacklist, Report, db, summary_counts
from app.phishing.heuristics import AnalysisInputError
from app.phishing.services import (
    analyses_to_csv,
    filtered_reports,
    label_counts_by_day,
    recent_analyses,
    run_analysis,
    serialize_analysis,
    top_phishing_domains,
)

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

@bp.route("/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def login():
    if current_user.is_authenticated:
        return jsonify({"status": "already_authenticated"})

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    from app.models import User

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid credentials"}), 401


@bp.route("/logout", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def logout():
    logout_user()
    return jsonify({"status": "success"})


@bp.route("/dashboard")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def dashboard():
    reports = filtered_reports(
        page=max(int(request.args.get("page", 1)), 1),
        per_page=20,
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    counts = summary_counts()
    total = sum(counts.values())
    phishing_pct = round((counts.get("phishing", 0) / total) * 100, 1) if total else 0.0

    return jsonify({
        "reports": [serialize_analysis(item) for item in reports.items],
        "pagination": {
            "page": reports.page,
            "pages": reports.pages,
            "total": reports.total
        },
        "counts": counts,
        "total": total,
        "phishing_pct": phishing_pct,
        "trends": label_counts_by_day(),
        "top_domains": top_phishing_domains(),
        "blacklist": [{"id": b.id, "domain": b.domain, "reason": b.reason} for b in Blacklist.query.order_by(Blacklist.created_at.desc()).all()],
        "recent": [serialize_analysis(a) for a in recent_analyses()]
    })


@bp.route("/blacklist", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def add_blacklist_entry():
    payload = request.get_json(silent=True) or {}
    domain = (payload.get("domain") or "").strip().lower()
    reason = (payload.get("reason") or "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    entry = Blacklist.query.filter_by(domain=domain).first()
    if entry is None:
        db.session.add(Blacklist(domain=domain, reason=reason))
        db.session.commit()
        return jsonify({"status": "added"})
    return jsonify({"status": "already_exists"})


@bp.route("/blacklist/<int:entry_id>/delete", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def delete_blacklist_entry(entry_id: int):
    entry = Blacklist.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"status": "deleted"})


@bp.route("/batch", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def batch_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file uploaded"}), 400

    data = io.StringIO(file.stream.read().decode("utf-8"))
    reader = csv.DictReader(data)
    rows = []
    for idx, row in enumerate(reader, start=1):
        if idx > current_app.config["BATCH_ANALYSIS_LIMIT"]:
            break
        url = (row.get("url") or "").strip()
        if not url:
            continue
        try:
            result = run_analysis(url, current_app.config)
            analysis = db.session.get(Analysis, result.analysis_id)
            rows.append(serialize_analysis(analysis))
        except (AnalysisInputError, ValueError) as exc:  # pragma: no cover
            current_app.logger.exception("batch_analysis_failed")
            rows.append({"analysis_id": "", "url": url, "risk_score": "", "label": "", "reasons": [str(exc)]})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["analysis_id", "url", "risk_score", "label", "reasons"])
    for row in rows:
        writer.writerow(
            [
                row.get("analysis_id", ""),
                row.get("url", ""),
                row.get("risk_score", ""),
                row.get("label", ""),
                "; ".join(row.get("reasons", [])),
            ]
        )
    db.session.add(Report(title="Batch CSV analysis", content=f"Processed {len(rows)} URLs"))
    db.session.commit()
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=batch-analysis-results.csv"},
    )


@bp.route("/export.csv")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def export_csv():
    rows = Analysis.query.order_by(Analysis.created_at.desc()).limit(500).all()
    db.session.add(Report(title="CSV export", content=f"Exported {len(rows)} rows"))
    db.session.commit()
    return Response(
        analyses_to_csv(rows),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=detector-report.csv"},
    )


@bp.route("/export.pdf")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def export_pdf():
    rows = Analysis.query.order_by(Analysis.created_at.desc()).limit(100).all()
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    _width, height = letter
    y = height - inch
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(inch, y, "Detector Report")
    y -= 0.4 * inch
    pdf.setFont("Helvetica", 10)
    for row in rows:
        line = f"{row.created_at:%Y-%m-%d %H:%M} | {row.label.upper():<10} | {row.risk_score:>3} | {row.domain}"
        pdf.drawString(inch, y, line[:110])
        y -= 0.25 * inch
        if y < inch:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - inch
    pdf.save()
    buffer.seek(0)
    db.session.add(Report(title="PDF export", content=f"Exported {len(rows)} rows"))
    db.session.commit()
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="detector-report.pdf")


@bp.route("/health")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def health_page():
    from app import gather_health_snapshot
    return jsonify(gather_health_snapshot())
