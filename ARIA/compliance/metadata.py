from __future__ import annotations

import json
from typing import Any

from compliance.config import DATA_DIR
from compliance.control_extractor import load_controls
from compliance.evidence import format_evidence_item

VERDICT_HELP = {
    "Compliant": "All automated checks for this control passed. The application's current behavior matches the stated security claim.",
    "Non-Compliant": "One or more checks failed. The control is not met — remediation is required before this area can be considered secure.",
    "Insufficient Evidence": "Checks were inconclusive, not run, or returned partial results. Manual verification or additional tooling is recommended.",
}

FRAMEWORK_HELP = {
    "owasp": "OWASP Top 10 alignment score based on web application security checks (access control, injection, misconfiguration, etc.).",
    "iso": "ISO 27001-themed control coverage derived from mapped security checks and standards references.",
    "nist": "NIST Cybersecurity Framework alignment (Identify, Protect, Detect) based on AC, AU, SI, and CM control families.",
    "gdpr": "GDPR readiness score focusing on privacy workflows, data minimization, and data subject rights routes.",
}

PRIORITY_HELP = {
    "critical": "Immediate remediation required — exploitable vulnerability with severe business impact (e.g. privilege escalation).",
    "high": "Remediate in current sprint — significant security or compliance risk.",
    "medium": "Plan remediation within 30 days — defense-in-depth or logging/configuration gaps.",
    "low": "Track for backlog — minor hardening opportunities.",
}


def get_check_catalog() -> dict[str, dict[str, Any]]:
    path = DATA_DIR / "check_catalog.json"
    return json.loads(path.read_text(encoding="utf-8"))


def get_check_name(check_id: str) -> str:
    return get_check_catalog().get(check_id, {}).get("name", check_id.replace("-", " ").title())


def control_title(control_id: str) -> str:
    return get_control_catalog().get(control_id, {}).get("title", control_id)


def get_kpi_list(kpi_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Ordered metrics with human labels for templates (no KPI-xx in UI)."""
    catalog = get_kpi_catalog()
    priority = [f"KPI-{i:02d}" for i in range(1, 16)]
    rows = []
    for kpi_id in priority:
        meta = catalog.get(kpi_id, {})
        rows.append(
            {
                "label": meta.get("label", kpi_id),
                "description": meta.get("description", ""),
                "value": kpi_snapshot.get(kpi_id),
                "target": meta.get("target"),
                "unit": meta.get("unit", ""),
                "direction": meta.get("direction", "lower_better"),
                "display": get_kpi_display(kpi_id, kpi_snapshot.get(kpi_id), catalog),
            }
        )
    return rows


def get_kpi_catalog() -> dict[str, dict[str, Any]]:
    path = DATA_DIR / "kpi_baselines.json"
    return json.loads(path.read_text(encoding="utf-8"))


def get_kpi_display(kpi_id: str, value: Any, catalog: dict | None = None) -> dict[str, Any]:
    catalog = catalog or get_kpi_catalog()
    meta = catalog.get(kpi_id, {})
    direction = meta.get("direction", "lower_better")
    target = meta.get("target")
    status = "unknown"
    if value is not None and target is not None:
        try:
            v = float(value)
            t = float(target)
            if direction == "lower_better":
                status = "good" if v <= t else "warn" if v <= t * 1.5 else "bad"
            else:
                status = "good" if v >= t else "warn" if v >= t * 0.75 else "bad"
        except (TypeError, ValueError):
            status = "unknown"
    return {
        "id": kpi_id,
        "value": value,
        "label": meta.get("label", kpi_id),
        "description": meta.get("description", ""),
        "direction": direction,
        "baseline": meta.get("baseline"),
        "target": target,
        "unit": meta.get("unit", ""),
        "status": status,
    }


def get_control_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    descriptions = _control_descriptions()
    for c in load_controls():
        catalog[c.id] = {
            "id": c.id,
            "title": c.title,
            "risk": c.risk,
            "priority": c.priority,
            "claim": c.claim,
            "description": descriptions.get(c.id, c.claim),
            "standard_refs": c.standard_refs,
            "gap_ids": c.gap_ids,
            "check_ids": c.check_ids,
            "priority_help": PRIORITY_HELP.get(c.priority, ""),
        }
    return catalog


def _control_descriptions() -> dict[str, str]:
    return {
        "F-01": "Passwords may be stored or validated insecurely. Attackers who obtain database access could read credentials in plaintext or crack weak hashes.",
        "F-02": "Login endpoint lacks multi-factor authentication, account lockout, or rate limiting — enabling brute-force and credential-stuffing attacks.",
        "F-03": "The customer dashboard accepts a user_id parameter, potentially exposing another customer's account summary (Insecure Direct Object Reference).",
        "F-04": "Transaction history may be accessible across user boundaries via parameter manipulation.",
        "F-05": "The profile update form accepts a role field — a customer could attempt to self-promote to admin (Broken Access Control / privilege escalation).",
        "F-06": "Customers may access the internal employee portal intended for staff-only operations.",
        "F-07": "Customers may reach admin-only routes such as user management or compliance dashboards.",
        "F-08": "HTML forms that change state (transfers, profile updates) lack CSRF tokens — attackers can trick logged-in users into unwanted actions.",
        "F-09": "The statements feature may build SQL queries from unsanitized input, enabling SQL injection.",
        "F-10": "Transaction search may concatenate user input into SQL rather than using bound parameters.",
        "F-11": "Application logs may capture raw user input including malicious payloads, complicating log analysis and risking log injection.",
        "F-12": "Document upload may accept dangerous file types without validation, enabling malware upload or stored XSS.",
        "F-13": "APIs and pages may return more data than necessary (excessive data exposure), increasing breach impact.",
        "F-14": "Security-relevant events are logged incompletely — missing IP, severity, or context needed for incident response.",
        "F-15": "HTTP responses lack standard security headers (CSP, HSTS, X-Frame-Options) that mitigate XSS and clickjacking.",
        "F-16": "Secret keys or session configuration may be hardcoded or use insecure defaults in source code.",
        "F-17": "GDPR-required privacy workflows (data export, deletion, consent) are not implemented as user-facing routes.",
        "F-18": "Money transfers may lack atomicity, idempotency keys, or rejected-transfer audit logging — risking double-spend or race conditions.",
    }


def parse_verdict_evidence(evidence_json: str | None) -> dict[str, Any]:
    if not evidence_json:
        return {"evidence_chain": [], "evidence_items": [], "standards": []}
    try:
        data = json.loads(evidence_json)
        if isinstance(data, dict):
            if "evidence_items" not in data and data.get("evidence_chain"):
                data["evidence_items"] = _legacy_chain_to_items(data["evidence_chain"])
            return data
    except json.JSONDecodeError:
        pass
    return {"evidence_chain": [str(evidence_json)], "evidence_items": [], "standards": []}


def _legacy_chain_to_items(chain: list[str]) -> list[dict[str, Any]]:
    items = []
    for entry in chain:
        if ": " in entry:
            _, rest = entry.split(": ", 1)
            status = "fail"
            if " — " in rest:
                status_part, obs = rest.split(" — ", 1)
                status = status_part.strip()
            else:
                obs = rest
                status_part = rest
            items.append(
                {
                    "test_name": "Automated check",
                    "method": "Prior scan",
                    "observation": obs,
                    "location": "See full report",
                    "status": status,
                }
            )
        else:
            items.append({"test_name": "Evidence", "observation": entry, "method": "Prior scan", "location": "—"})
    return items


def enrich_verdict_row(row: dict[str, Any], controls: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cid = row.get("control_id", "")
    ctrl = controls.get(cid, {})
    parsed = parse_verdict_evidence(row.get("evidence_json"))
    row = dict(row)
    row["title"] = ctrl.get("title", cid)
    row["parsed_evidence"] = parsed
    row["evidence_items"] = parsed.get("evidence_items", [])
    return row
