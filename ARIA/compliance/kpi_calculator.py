from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from compliance.config import COMPLIANCE_SCORE_BASELINES, DATA_DIR, PRIVACY_ROUTES, REQUIRED_HEADERS
from compliance.metadata import get_kpi_catalog
from compliance.flask_adapter import get_test_client
from compliance.state import CheckResult, ControlDefinition

RISK_WEIGHTS = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}


def _failed(checks: list[CheckResult], prefix: str | None = None) -> list[CheckResult]:
    items = [c for c in checks if c.status in ("fail", "partial")]
    if prefix:
        items = [c for c in items if c.check_id.startswith(prefix)]
    return items


def _count_non_compliant_controls(controls: list[ControlDefinition], checks: list[CheckResult]) -> int:
    check_map = {c.check_id: c for c in checks}
    count = 0
    for control in controls:
        related = [check_map[cid] for cid in control.check_ids if cid in check_map]
        if not related:
            continue
        if any(r.status in ("fail", "partial") for r in related):
            count += 1
    return count


def _framework_scores(checks: list[CheckResult]) -> dict[str, float]:
    frameworks = {"owasp": [], "iso": [], "nist": [], "gdpr": []}
    for check in checks:
        weight = check.source_weight
        score = 100.0 if check.status == "pass" else 50.0 if check.status == "partial" else 0.0
        for std in check.standards:
            key = std.split()[0].lower()
            if key.startswith("owasp"):
                frameworks["owasp"].append(score * weight)
            elif key.startswith("iso"):
                frameworks["iso"].append(score * weight)
            elif key.startswith("nist"):
                frameworks["nist"].append(score * weight)
            elif key.startswith("gdpr"):
                frameworks["gdpr"].append(score * weight)
    result = {}
    for fw, values in frameworks.items():
        if values:
            result[fw] = round(sum(values) / len(values), 1)
        else:
            result[fw] = COMPLIANCE_SCORE_BASELINES.get(fw, 35.0)
    return result


def _privacy_route_count() -> int:
    client = get_test_client()
    count = 0
    for route in PRIVACY_ROUTES:
        resp = client.get(route, follow_redirects=False)
        if resp.status_code != 404:
            count += 1
    return count


def _header_count(headers: dict[str, str]) -> int:
    lower = {k.lower() for k in headers}
    return sum(1 for h in REQUIRED_HEADERS if h.lower() in lower)


def _session_flags() -> int:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"})
    with client.session_transaction() as sess:
        _ = sess.get("user_id")
    # Flask test client does not expose Set-Cookie flags reliably; heuristic from app config
    from app import app

    flags = 0
    if app.config.get("SESSION_COOKIE_HTTPONLY", True):
        flags += 1
    if app.config.get("SESSION_COOKIE_SECURE"):
        flags += 1
    if app.config.get("SESSION_COOKIE_SAMESITE"):
        flags += 1
    if app.config.get("PERMANENT_SESSION_LIFETIME"):
        flags += 1
    return flags


def _remediation_mean_days() -> float | None:
    path = DATA_DIR / "remediation_tracking.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    days: list[int] = []
    now = datetime.utcnow()
    for entry in data.values():
        opened = entry.get("opened")
        if not opened:
            continue
        start = datetime.fromisoformat(opened)
        days.append((now - start).days)
    return round(sum(days) / len(days), 1) if days else None


def calculate_kpis(
    *,
    controls: list[ControlDefinition],
    checks: list[CheckResult],
    audit_summary: dict[str, Any],
    tool_results: dict[str, Any],
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = response_headers or {}
    ac_failed = len(_failed(checks, "AC-"))
    auth_failed = len([c for c in _failed(checks) if c.check_id in ("WC-02", "CF-01") or "F-01" in c.finding_ids or "F-02" in c.finding_ids])
    si_failed = len(_failed(checks, "SI-"))
    csrf_fail = 1 if any(c.check_id == "WC-01" and c.status == "fail" for c in checks) else 0
    idor_fail = len([c for c in _failed(checks) if c.check_id == "AC-04"])
    pytest = tool_results.get("pytest", {})
    pass_rate = None
    if pytest.get("total"):
        pass_rate = round(100.0 * pytest.get("passed", 0) / pytest["total"], 1)
    fw_scores = _framework_scores(checks)
    kpi15 = round(sum(fw_scores.values()) / len(fw_scores), 1)

    snapshot = {
        "KPI-01": _count_non_compliant_controls(controls, checks),
        "KPI-02": sum(1 for c in controls if c.priority in ("critical", "high") and any(
            ch.status in ("fail", "partial") for ch in checks if c.id in ch.finding_ids
        )),
        "KPI-03": ac_failed,
        "KPI-04": auth_failed,
        "KPI-05": si_failed,
        "KPI-06": csrf_fail,
        "KPI-07": idor_fail,
        "KPI-08": audit_summary.get("critical_action_completeness_pct", 0),
        "KPI-09": audit_summary.get("failed_login_completeness_pct", 0),
        "KPI-10": _privacy_route_count(),
        "KPI-11": _header_count(headers),
        "KPI-12": _session_flags(),
        "KPI-13": _remediation_mean_days(),
        "KPI-14": pass_rate,
        "KPI-15": kpi15,
        "framework_scores": fw_scores,
        "baselines": get_kpi_catalog(),
    }
    return snapshot
