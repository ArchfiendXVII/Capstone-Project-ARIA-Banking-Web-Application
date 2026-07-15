from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from compliance.config import BASE_DIR, PRIVACY_ROUTES, REQUIRED_HEADERS
from compliance.evidence import build_evidence, find_line_number, rel, snippet_at_line
from compliance.execution_trace import attach_execution_trace
from compliance.state import CheckResult


def _app_path(ctx: dict[str, Any]) -> Path:
    return Path(ctx.get("app_path", BASE_DIR / "app.py"))


def _read_app(ctx: dict[str, Any]) -> tuple[str, str]:
    path = _app_path(ctx)
    return path.read_text(encoding="utf-8"), rel(path, BASE_DIR)


def enrich_check_result(result: CheckResult, ctx: dict[str, Any]) -> CheckResult:
    if result.evidence_detail.get("method") and result.evidence_detail.get("location"):
        result.evidence_detail = attach_execution_trace(result, ctx)
        result.evidence_detail.setdefault("test_name", result.evidence_detail.get("test_name", result.check_id))
        result.evidence_detail["status"] = result.status
        return result
    enricher = _ENRICHERS.get(result.check_id)
    if enricher:
        result.evidence_detail = enricher(result, ctx)
        result.evidence_detail.setdefault("test_name", result.evidence_detail.get("test_name", result.check_id))
        result.evidence_detail["status"] = result.status
    result.evidence_detail = attach_execution_trace(result, ctx)
    return result


def _e_cf_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    line = find_line_number(source, r"SECRET_KEY")
    hardcoded = result.status == "fail"
    return build_evidence(
        test_name="Hardcoded secret key",
        method="Static analysis — searched app.py for literal SECRET_KEY assignment",
        observation="Flask SECRET_KEY is hardcoded as a string literal in app configuration"
        if hardcoded
        else "No hardcoded SECRET_KEY literal pattern detected",
        location=app_file,
        file=app_file,
        line=line,
        snippet=snippet_at_line(source, line),
        tool="Python source scan",
    )


def _e_cf_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    line = find_line_number(source, r"debug\s*=\s*True")
    return build_evidence(
        test_name="Debug mode enabled",
        method="Static analysis — searched for debug=True in app entrypoint",
        observation=result.evidence,
        location=app_file,
        file=app_file,
        line=line,
        snippet=snippet_at_line(source, line),
        tool="Python source scan",
    )


def _e_cf_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    headers = ctx.get("response_headers", {})
    present = [h for h in REQUIRED_HEADERS if h.lower() in {k.lower() for k in headers}]
    missing = [h for h in REQUIRED_HEADERS if h.lower() not in {k.lower() for k in headers}]
    return build_evidence(
        test_name="HTTP security headers",
        method="HTTP GET request to application root — inspect response headers",
        observation=f"Present: {', '.join(present) or 'none'}. Missing: {', '.join(missing) or 'none'}.",
        location=f"http://127.0.0.1:5000/ (response headers)",
        route="/",
        tool="HTTP header probe",
        result_detail=result.evidence,
    )


def _e_cf_04(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    line = find_line_number(source, r"app\.run\(")
    return build_evidence(
        test_name="Production server configuration",
        method="Compared app.py __main__ block vs run_server.py entrypoint",
        observation=result.evidence,
        location=f"{app_file} and run_server.py",
        file=app_file,
        line=line,
        snippet=snippet_at_line(source, line),
        tool="Source code review",
    )


def _e_si_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    line = None
    for i, ln in enumerate(source.splitlines(), 1):
        if re.search(r'execute\(f["\']|f["\'].*SELECT', ln, re.I):
            line = i
            break
    return build_evidence(
        test_name="Unsafe SQL in source code",
        method="Regex scan of app.py for f-string SQL and .format() in execute() calls",
        observation=result.evidence,
        location=app_file,
        file=app_file,
        line=line,
        snippet=snippet_at_line(source, line),
        tool="Static analysis",
    )


def _e_si_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Statements SQL injection probe",
        method="Authenticated GET with malicious user_id query parameter",
        observation=result.evidence,
        location="HTTP route /statements",
        route="/statements?user_id=1 OR 1=1",
        request_detail="Logged in as john@aria.local, compared response size vs legitimate user_id=1",
        tool="Flask test client (DAST)",
    )


def _e_si_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    idx = source.find("def transactions")
    snippet = source[idx : idx + 400] if idx >= 0 else None
    return build_evidence(
        test_name="Transaction search parameterization",
        method="Source review of transactions route for parameterized LIKE queries",
        observation=result.evidence,
        location=f"{app_file} → transactions()",
        file=app_file,
        snippet=snippet[:300] if snippet else None,
        tool="Static analysis",
    )


def _e_ac_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    idx = source.find("def profile")
    return build_evidence(
        test_name="Profile role tampering test",
        method="POST /profile as customer with hidden role=admin field; verify role unchanged in response",
        observation=result.evidence,
        location=f"{app_file} → profile() and POST /profile",
        file=app_file,
        route="POST /profile",
        request_detail='Data: {"role": "admin", "full_name": "John Carter", ...} as john@aria.local',
        tool="Flask test client (DAST)",
    )


def _e_ac_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Customer blocked from admin",
        method="GET /admin as customer — expect HTTP 403 Forbidden",
        observation=result.evidence,
        location="HTTP route /admin",
        route="GET /admin",
        request_detail="Session: john@aria.local (customer role)",
        tool="Flask test client (DAST)",
    )


def _e_ac_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Customer blocked from employee portal",
        method="GET /employee-portal as customer — expect HTTP 403",
        observation=result.evidence,
        location="HTTP route /employee-portal",
        route="GET /employee-portal",
        request_detail="Session: john@aria.local (customer role)",
        tool="Flask test client (DAST)",
    )


def _e_ac_04(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Dashboard IDOR test",
        method="GET /dashboard?user_id=2 as user 1 — compare response to own dashboard",
        observation=result.evidence,
        location="HTTP route /dashboard",
        route="GET /dashboard?user_id=2",
        request_detail="Logged in as john@aria.local (user_id=1), requested user_id=2",
        tool="Flask test client (DAST)",
    )


def _e_ac_05(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    source, app_file = _read_app(ctx)
    return build_evidence(
        test_name="Admin role management route",
        method="Source review for /admin/users route and parameterized role UPDATE",
        observation=result.evidence,
        location=app_file,
        file=app_file,
        tool="Static analysis",
    )


def _e_wc_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="CSRF token on forms",
        method="Fetched HTML of /transfer, /profile, /login — searched for csrf hidden field",
        observation=result.evidence,
        location="HTML forms at /transfer, /profile, /login",
        route="/transfer, /profile, /login",
        tool="Flask test client (DAST)",
    )


def _e_wc_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Login rate limiting",
        method="Six rapid POST /login attempts with invalid credentials",
        observation=result.evidence,
        location="HTTP route POST /login",
        route="POST /login",
        request_detail="6 consecutive failed login attempts — checked for HTTP 429",
        tool="Flask test client (DAST)",
    )


def _e_wc_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Content-Security-Policy header",
        method="HTTP response header inspection on GET /",
        observation=result.evidence,
        location="Response headers from GET /",
        route="/",
        tool="HTTP header probe",
    )


def _e_tc_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Transfer idempotency test",
        method="Executed test_transfer_security.py automated test suite",
        observation="Idempotency and atomic transfer tests" if result.status == "pass" else "Transfer security tests failed",
        location="test_transfer_security.py",
        file="test_transfer_security.py",
        tool="pytest subprocess",
        result_detail=result.evidence[:500],
    )


def _e_tc_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    db = ctx.get("db_path", "aria_bank.db")
    return build_evidence(
        test_name="Self-transfer rejection",
        method="Ran test_self_transfer_rejected() + counted rejected_transfers rows",
        observation=result.evidence,
        location=str(db),
        database=str(db),
        table="rejected_transfers",
        tool="pytest + SQLite query",
    )


def _e_tc_04(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    db = ctx.get("db_path", "aria_bank.db")
    return build_evidence(
        test_name="Rejected transfer logging",
        method="SQLite schema inspection — verified rejected_transfers table exists and is queryable",
        observation=result.evidence,
        location=str(db),
        database=str(db),
        table="rejected_transfers",
        tool="SQLite PRAGMA / SELECT",
    )


def _e_tc_05(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Concurrent transfer race test",
        method="Not automated — requires manual Burp concurrent replay",
        observation=result.evidence,
        location="POST /transfer",
        route="POST /transfer",
        tool="Manual / Burp Suite (deferred)",
    )


def _e_lm_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    db = ctx.get("db_path", "aria_bank.db")
    return build_evidence(
        test_name="Failed login log completeness",
        method="Queried audit_logs WHERE event_type='LOGIN_FAILED' — checked ip_address and severity populated",
        observation=result.evidence,
        location=str(db),
        database=str(db),
        table="audit_logs",
        tool="SQLite query",
    )


def _e_lm_02(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    db = ctx.get("db_path", "aria_bank.db")
    return build_evidence(
        test_name="Unauthorized access logging",
        method="COUNT audit_logs WHERE event_type='UNAUTHORIZED_ACCESS_ATTEMPT'",
        observation=result.evidence,
        location=str(db),
        database=str(db),
        table="audit_logs",
        tool="SQLite query",
    )


def _e_lm_03(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    log_file = rel(BASE_DIR / "logs" / "compliance_events.jsonl", BASE_DIR)
    return build_evidence(
        test_name="Structured compliance event log",
        method="Filesystem check for JSON Lines compliance log file",
        observation=result.evidence,
        location=log_file,
        file=log_file,
        tool="Filesystem",
    )


def _e_lm_04(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    return build_evidence(
        test_name="Scan completion audit event",
        method="Verified COMPLIANCE_SCAN_COMPLETED written during scan pipeline",
        observation=result.evidence,
        location="logs/compliance_events.jsonl",
        file="logs/compliance_events.jsonl",
        tool="Structured logger",
    )


def _e_tc_01(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    if result.evidence_detail.get("method"):
        return result.evidence_detail
    return _e_tc_02(result, ctx)  # fallback unused if check sets detail


_ENRICHERS = {
    "CF-01": _e_cf_01,
    "CF-02": _e_cf_02,
    "CF-03": _e_cf_03,
    "CF-04": _e_cf_04,
    "SI-01": _e_si_01,
    "SI-02": _e_si_02,
    "SI-03": _e_si_03,
    "AC-01": _e_ac_01,
    "AC-02": _e_ac_02,
    "AC-03": _e_ac_03,
    "AC-04": _e_ac_04,
    "AC-05": _e_ac_05,
    "WC-01": _e_wc_01,
    "WC-02": _e_wc_02,
    "WC-03": _e_wc_03,
    "TC-01": lambda r, c: r.evidence_detail if r.evidence_detail.get("method") else build_evidence(
        test_name="Transfer service integration",
        method="Static import analysis",
        observation=r.evidence,
        location="app.py + transfer_service.py",
        file="app.py",
        tool="Source code review",
    ),
    "TC-02": _e_tc_02,
    "TC-03": _e_tc_03,
    "TC-04": _e_tc_04,
    "TC-05": _e_tc_05,
    "LM-01": _e_lm_01,
    "LM-02": _e_lm_02,
    "LM-03": _e_lm_03,
    "LM-04": _e_lm_04,
}
