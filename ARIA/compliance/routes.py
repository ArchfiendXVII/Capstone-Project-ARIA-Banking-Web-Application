from __future__ import annotations

import json
import threading
from datetime import datetime
from functools import wraps

import markdown
from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for

from compliance.config import DEFAULT_DB_PATH
from compliance.metadata import (
    FRAMEWORK_HELP,
    VERDICT_HELP,
    enrich_verdict_row,
    get_control_catalog,
    get_kpi_catalog,
    get_kpi_list,
    parse_verdict_evidence,
)
from compliance.llm_reporter import MissingAPIKeyError
from compliance.investigation import investigation_for_live_job, rebuild_investigation_from_scan_row
from compliance.repository import (
    connect,
    get_expired_verdicts,
    get_kpi_trend,
    get_latest_scan,
    get_report,
    get_report_for_scan,
    get_reports,
    get_scan,
    get_scan_history,
    get_verdicts_for_scan,
    mark_report_reviewed,
)
from compliance.scan_progress import create_job, get_job
from compliance.scan_service import run_scan

compliance_bp = Blueprint("compliance", __name__, url_prefix="/admin/compliance")


@compliance_bp.context_processor
def inject_compliance_metadata():
    return {
        "kpi_catalog": get_kpi_catalog(),
        "control_catalog": get_control_catalog(),
        "verdict_help": VERDICT_HELP,
        "framework_help": FRAMEWORK_HELP,
    }


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from app import abort as app_abort
        from app import current_user, log_event, redirect as app_redirect, url_for as app_url_for
        from flask import flash as app_flash

        user = current_user()
        if not user:
            app_flash("Please sign in to continue.", "warning")
            return app_redirect(app_url_for("login"))
        if user["role"] != "admin":
            log_event(
                user["id"],
                "UNAUTHORIZED_ACCESS_ATTEMPT",
                f"Blocked admin-only compliance access to {request.path}",
                "High",
            )
            app_abort(403)
        return view(*args, **kwargs)

    return wrapped


def _get_conn():
    return connect(DEFAULT_DB_PATH)


def _run_scan_background(job_id: str, triggered_by: int | None) -> None:
    from app import app

    progress = get_job(job_id)
    if not progress:
        return
    with app.app_context():
        try:
            result = run_scan(triggered_by=triggered_by, scan_type="manual", progress=progress)
            progress.complete(
                {
                    "scan_id": result.scan_id,
                    "report_id": result.report_id,
                    "partial_checks": result.partial_checks,
                }
            )
        except MissingAPIKeyError as exc:
            progress.fail(str(exc))
        except Exception as exc:
            progress.fail(f"Compliance scan failed: {exc}")


@compliance_bp.route("")
@admin_required
def admin_compliance():
    conn = _get_conn()
    try:
        latest = get_latest_scan(conn)
        expired = get_expired_verdicts(conn)
        history = get_scan_history(conn, 5)
        trend = get_kpi_trend(conn, 5)
        kpi = json.loads(latest["kpi_snapshot"]) if latest else {}
        priority_metrics = [
            m for m in get_kpi_list(kpi)
            if m["label"] in (
                "Total Open Vulnerabilities",
                "Critical & High Severity Open",
                "Access Control Failures",
                "Automated Test Pass Rate",
                "Overall Compliance Score",
            )
        ]
        return render_template(
            "admin_compliance.html",
            latest=latest,
            kpi=kpi,
            priority_metrics=priority_metrics,
            expired=expired,
            history=history,
            trend=trend,
        )
    finally:
        conn.close()


@compliance_bp.route("/investigation")
@compliance_bp.route("/investigation/<int:scan_id>")
@admin_required
def admin_compliance_investigation(scan_id: int | None = None):
    conn = _get_conn()
    try:
        history = get_scan_history(conn, 15)
        job_id = request.args.get("job")
        selected = None
        investigation = None
        report = None

        if scan_id:
            selected = get_scan(conn, scan_id)
        elif not job_id:
            selected = get_latest_scan(conn)

        if selected:
            report = get_report_for_scan(conn, selected["id"])
            investigation = rebuild_investigation_from_scan_row(
                selected,
                report_id=report["id"] if report else None,
            )
        else:
            from compliance.investigation import FLOW_EDGES, PIPELINE_AGENTS

            investigation = {
                "pipeline": [{**a, "status": "idle"} for a in PIPELINE_AGENTS],
                "agents": {},
                "flow_edges": FLOW_EDGES,
                "evidence_chain": [],
                "summary": {},
            }

        return render_template(
            "admin_compliance_investigation.html",
            history=history,
            selected_scan=selected,
            investigation=investigation,
            report=report,
            job_id=job_id,
            scan_ok=request.args.get("scan_ok"),
            scan_error=request.args.get("scan_error"),
        )
    finally:
        conn.close()


@compliance_bp.route("/investigation/data/<int:scan_id>")
@admin_required
def admin_compliance_investigation_data(scan_id: int):
    conn = _get_conn()
    try:
        scan_row = get_scan(conn, scan_id)
        if not scan_row:
            return jsonify({"error": "Scan not found"}), 404
        report = get_report_for_scan(conn, scan_id)
        inv = rebuild_investigation_from_scan_row(scan_row, report_id=report["id"] if report else None)
        return jsonify(inv)
    finally:
        conn.close()


@compliance_bp.route("/findings")
@admin_required
def admin_compliance_findings():
    conn = _get_conn()
    try:
        latest = get_latest_scan(conn)
        verdicts = get_verdicts_for_scan(conn, latest["id"]) if latest else []
        controls = get_control_catalog()
        enriched = [enrich_verdict_row(dict(v), controls) for v in verdicts]
        return render_template(
            "admin_compliance_findings.html",
            verdicts=enriched,
            controls=controls,
            scan=latest,
        )
    finally:
        conn.close()


@compliance_bp.route("/reports")
@admin_required
def admin_compliance_reports():
    conn = _get_conn()
    try:
        reports = get_reports(conn)
        return render_template("admin_compliance_reports.html", reports=reports)
    finally:
        conn.close()


@compliance_bp.route("/reports/<int:report_id>")
@admin_required
def admin_compliance_report_detail(report_id: int):
    conn = _get_conn()
    try:
        report = get_report(conn, report_id)
        if not report:
            abort(404)
        html_body = report.get("report_html") or markdown.markdown(
            report["report_markdown"], extensions=["tables", "fenced_code", "nl2br"]
        )
        verdicts = json.loads(report.get("verdicts_json") or "[]")
        gaps = json.loads(report.get("disclosure_gaps_json") or "[]")
        controls = get_control_catalog()
        return render_template(
            "admin_compliance_report_detail.html",
            report=report,
            html_body=html_body,
            verdicts=verdicts,
            gaps=gaps,
            controls=controls,
        )
    finally:
        conn.close()


@compliance_bp.route("/run/start", methods=["POST"])
@admin_required
def admin_compliance_run_start():
    job = create_job()
    thread = threading.Thread(
        target=_run_scan_background,
        args=(job.job_id, session.get("user_id")),
        daemon=True,
    )
    thread.start()
    return jsonify(job.to_dict())


@compliance_bp.route("/run/status/<job_id>")
@admin_required
def admin_compliance_run_status(job_id: str):
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    payload = job.to_dict()
    payload["investigation"] = investigation_for_live_job(payload)
    return jsonify(payload)


@compliance_bp.route("/run", methods=["POST"])
@admin_required
def admin_compliance_run():
    """Legacy synchronous scan — prefer /run/start for progress UI."""
    if request.headers.get("Accept", "").startswith("application/json"):
        return admin_compliance_run_start()
    try:
        result = run_scan(triggered_by=session.get("user_id"), scan_type="manual")
        flash(
            f"Compliance scan completed (scan #{result.scan_id}, report #{result.report_id}).",
            "success",
        )
    except MissingAPIKeyError as exc:
        flash(str(exc), "danger")
    except Exception as exc:
        flash(f"Compliance scan failed: {exc}", "danger")
    return redirect(url_for("compliance.admin_compliance_investigation"))


@compliance_bp.route("/reports/<int:report_id>/review", methods=["POST"])
@admin_required
def admin_compliance_report_review(report_id: int):
    conn = _get_conn()
    try:
        mark_report_reviewed(conn, report_id, session.get("user_id"))
        flash("Report marked as human reviewed.", "success")
    finally:
        conn.close()
    return redirect(url_for("compliance.admin_compliance_report_detail", report_id=report_id))
