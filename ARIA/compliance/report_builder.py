from __future__ import annotations

from datetime import datetime
from typing import Any

from compliance.metadata import FRAMEWORK_HELP, VERDICT_HELP, get_check_name, get_control_catalog, get_kpi_catalog
from compliance.evidence import format_evidence_item


def _severity_emoji(verdict: str, priority: str) -> str:
    if verdict == "Compliant":
        return "PASS"
    if priority == "critical":
        return "CRITICAL"
    if priority == "high":
        return "HIGH"
    if priority == "medium":
        return "MEDIUM"
    return "LOW"


def _kpi_status_line(kpi_id: str, value: Any, meta: dict) -> str:
    target = meta.get("target")
    direction = meta.get("direction", "lower_better")
    if value is None or target is None:
        return "No target comparison"
    try:
        v, t = float(value), float(target)
        if direction == "lower_better":
            if v <= t:
                return f"On target (at or below {t})"
            return f"Above target — reduce from {v} to {t} or below"
        if v >= t:
            return f"On target (at or above {t})"
        return f"Below target — improve from {v} to {t} or above"
    except (TypeError, ValueError):
        return "—"


def build_professional_report(state_dict: dict[str, Any], *, scan_id: int | None = None, report_id: int | None = None) -> str:
    """Deterministic gap-analysis / bug-bounty style report from scan state."""
    kpi = state_dict.get("kpi_snapshot", {})
    kpi_catalog = get_kpi_catalog()
    control_catalog = get_control_catalog()
    verdicts = state_dict.get("verdicts", [])
    checks = state_dict.get("check_results", [])
    gaps = state_dict.get("disclosure_gaps", [])
    fw = kpi.get("framework_scores", {})
    scan_ts = state_dict.get("scan_id", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

    non_compliant = [v for v in verdicts if v.get("verdict") == "Non-Compliant"]
    compliant = [v for v in verdicts if v.get("verdict") == "Compliant"]
    insufficient = [v for v in verdicts if v.get("verdict") == "Insufficient Evidence"]
    failed_checks = [c for c in checks if c.get("status") in ("fail", "partial")]

    lines: list[str] = [
        "# ARIA Bank — Security & Compliance Gap Analysis Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Report generated** | {scan_ts} |",
        f"| **Scan identifier** | {scan_id or 'pending'} |",
        f"| **Report identifier** | {report_id or 'pending'} |",
        f"| **Classification** | Internal — Authorized Assessment |",
        f"| **Scope** | ARIA Bank web application (Flask), SQLite backend |",
        f"| **Methodology** | Automated control checks, multi-agent orchestration, Judge verdict scoring |",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"This assessment evaluated **18 security controls** against automated test evidence, "
        f"runtime audit signals, and mapped compliance standards (OWASP, ISO 27001 themes, NIST, GDPR).",
        "",
        f"- **Non-compliant controls:** {len(non_compliant)}",
        f"- **Compliant controls:** {len(compliant)}",
        f"- **Insufficient evidence:** {len(insufficient)}",
        f"- **Failed or partial automated checks:** {len(failed_checks)}",
        f"- **Disclosure gaps (missing/unimplemented controls):** {len(gaps)}",
        "",
    ]

    if fw:
        lines.extend([
            "**Framework sub-scores (current scan):**",
            f"- OWASP alignment: **{fw.get('owasp', '—')}%**",
            f"- ISO themes: **{fw.get('iso', '—')}%**",
            f"- NIST themes: **{fw.get('nist', '—')}%**",
            f"- GDPR readiness: **{fw.get('gdpr', '—')}%**",
            "",
        ])

    lines.extend([
        "### 1.1 Business impact (plain language)",
        "",
        "ARIA Bank handles customer accounts, transfers, and personal data. Findings marked **Non-Compliant** "
        "represent concrete paths an attacker or unauthorized user could abuse — including access to other customers' "
        "data, privilege escalation, or incomplete audit trails that would hinder incident response. "
        "This report is intended for security and engineering leadership to prioritize remediation.",
        "",
        "---",
        "",
        "## 2. Key Performance Indicators",
        "",
        "Each metric below maps to the continuous monitoring plan. **Lower is better** for vulnerability counts; "
        "**higher is better** for coverage and logging quality.",
        "",
        "| Metric | Current | Target | Assessment |",
        "|--------|---------|--------|------------|",
    ])

    for kpi_id in [f"KPI-{i:02d}" for i in range(1, 16)]:
        meta = kpi_catalog.get(kpi_id, {})
        val = kpi.get(kpi_id)
        val_str = str(val) if val is not None else "—"
        unit = meta.get("unit", "")
        if unit == "%" and val is not None:
            val_str = f"{val}%"
        target = meta.get("target")
        target_str = f"{target}%" if unit == "%" and target is not None else (str(target) if target is not None else "—")
        lines.append(
            f"| {meta.get('label', kpi_id)} | {val_str} | {target_str} | {_kpi_status_line(kpi_id, val, meta)} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Risk Summary by Severity",
        "",
    ])

    by_priority: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for v in non_compliant:
        cid = v.get("control_id", "")
        ctrl = control_catalog.get(cid, {})
        pri = ctrl.get("priority", "medium")
        by_priority.setdefault(pri, []).append(v)

    for pri in ("critical", "high", "medium", "low"):
        items = by_priority.get(pri, [])
        if items:
            lines.append(f"### {pri.upper()} ({len(items)})")
            for v in items:
                ctrl = control_catalog.get(v.get("control_id", ""), {})
                lines.append(f"- **{ctrl.get('title', 'Unknown')}** (confidence {v.get('score', '—')})")
            lines.append("")

    lines.extend([
        "---",
        "",
        "## 4. Detailed Findings Register",
        "",
        "Each finding documents the **security claim**, **verdict**, **evidence chain**, **standards mapping**, "
        "and **recommended remediation** in bug-bounty / gap-analysis format.",
        "",
    ])

    for v in sorted(verdicts, key=lambda x: x.get("control_id", "")):
        cid = v.get("control_id", "")
        ctrl = control_catalog.get(cid, {})
        verdict = v.get("verdict", "Unknown")
        pri = ctrl.get("priority", "medium")
        title = ctrl.get("title", "Unknown")
        lines.extend([
            f"### {title} [{_severity_emoji(verdict, pri)}]",
            "",
            f"| Attribute | Detail |",
            f"|-----------|--------|",
            f"| **Verdict** | {verdict} |",
            f"| **Priority** | {pri.title()} |",
            f"| **Risk rating** | {ctrl.get('risk', '—')} |",
            f"| **Confidence score** | {v.get('score', '—')} |",
            f"| **Security claim** | {ctrl.get('claim', '—')} |",
            "",
            "#### Description",
            "",
            ctrl.get("description", ctrl.get("claim", "No description available.")),
            "",
            "#### Evidence",
            "",
        ])
        items = v.get("evidence_items") or []
        if items:
            for item in items:
                lines.append(format_evidence_item(item))
                lines.append("")
        else:
            chain = v.get("evidence_chain") or []
            if chain:
                for item in chain:
                    lines.append(item)
                    lines.append("")
            else:
                lines.append("No automated evidence captured for this control.")
                lines.append("")
        lines.extend([
            "#### Standards & frameworks",
            "",
        ])
        standards = v.get("standards") or ctrl.get("standard_refs", [])
        if standards:
            for s in standards:
                lines.append(f"- {s}")
        else:
            lines.append("- No standards mapping recorded.")
        lines.extend([
            "",
            "#### Verdict interpretation",
            "",
            VERDICT_HELP.get(verdict, "See security team for manual review."),
            "",
        ])
        if verdict == "Non-Compliant":
            lines.extend([
                "#### Recommended remediation",
                "",
                f"1. Review the evidence above for **{title}**.",
                f"2. Implement controls so the application enforces: *{ctrl.get('claim', '')}*",
                "3. Re-run compliance scan to verify verdict moves to Compliant.",
                "",
            ])
        lines.append("---")
        lines.append("")

    lines.extend([
        "## 5. Disclosure Gaps (Controls Never Implemented)",
        "",
        "Disclosure gaps are controls or features **absent from the application** — distinct from "
        "findings where a feature exists but is misconfigured.",
        "",
    ])
    if gaps:
        for gap in gaps:
            lines.extend([
                f"### {gap.get('title', 'Unknown')}",
                "",
                f"- **Status:** {gap.get('status', 'open')}",
                f"- **Severity:** {gap.get('severity', 'medium')}",
                f"- **Detail:** {gap.get('detail', '—')}",
                "",
            ])
    else:
        lines.append("No disclosure gaps detected in this scan.")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 6. Automated Check Log (Appendix A)",
        "",
        "| Test | Status | Method | Location | Finding |",
        "|------|--------|--------|----------|---------|",
    ])
    for c in checks:
        detail = c.get("evidence_detail") or {}
        name = detail.get("test_name") or get_check_name(c.get("check_id", ""))
        loc = detail.get("file") or detail.get("route") or detail.get("location") or "—"
        if detail.get("line"):
            loc = f"{loc}:{detail['line']}"
        obs = (detail.get("observation") or c.get("evidence") or "")[:80].replace("|", "/")
        method = (detail.get("method") or c.get("agent", ""))[:50].replace("|", "/")
        lines.append(f"| {name} | {c.get('status', '—')} | {method} | {loc} | {obs} |")

    lines.extend([
        "",
        "---",
        "",
        "## 7. Framework Reference (Appendix B)",
        "",
    ])
    for key, help_text in FRAMEWORK_HELP.items():
        score = fw.get(key, "—")
        lines.append(f"- **{key.upper()}** ({score}%): {help_text}")

    lines.extend([
        "",
        "---",
        "",
        "*End of report — generated by ARIA Bank Compliance Monitor (Milestone 7).*",
    ])
    return "\n".join(lines)


def build_report_sections(state_dict: dict[str, Any]) -> dict[str, Any]:
    kpi = state_dict.get("kpi_snapshot", {})
    verdicts = state_dict.get("verdicts", [])
    return {
        "executive_summary": {
            "non_compliant": sum(1 for v in verdicts if v.get("verdict") == "Non-Compliant"),
            "compliant": sum(1 for v in verdicts if v.get("verdict") == "Compliant"),
            "insufficient": sum(1 for v in verdicts if v.get("verdict") == "Insufficient Evidence"),
            "kpi_15": kpi.get("KPI-15"),
            "framework_scores": kpi.get("framework_scores", {}),
        },
        "finding_count": len(verdicts),
        "check_count": len(state_dict.get("check_results", [])),
        "disclosure_gap_count": len(state_dict.get("disclosure_gaps", [])),
    }
