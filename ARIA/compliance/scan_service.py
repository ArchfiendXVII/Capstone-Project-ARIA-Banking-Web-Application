from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
import time

from compliance.collector import collect_signals
from compliance.config import DEFAULT_DB_PATH, REPORTS_DIR
from compliance.disclosure import evaluate_disclosure_gaps
from compliance.llm_reporter import LLMReport, MissingAPIKeyError, generate_report
from compliance.investigation import build_investigation_from_state
from compliance.orchestrator import run_orchestration
from compliance.repository import connect, get_latest_scan, save_report, save_scan, update_scan_investigation
from compliance.structured_log import log_check_failure, log_event


@dataclass
class ScanResult:
    scan_id: int
    report_id: int
    state: Any
    markdown_path: Path
    partial_checks: bool = False
    errors: list[str] = field(default_factory=list)


def run_scan(
    *,
    db_path: Path | str | None = None,
    triggered_by: int | None = None,
    scan_type: str = "manual",
    llm_client: Any | None = None,
    progress=None,
) -> ScanResult:
    db_path = Path(db_path or DEFAULT_DB_PATH)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if progress:
        progress.advance(2, "Preparing compliance scan pipeline", agent="system", phase="starting")

    ctx = collect_signals(db_path, progress=progress)
    if progress:
        progress.merge_state({"audit_summary": ctx.get("audit_summary"), "tool_results": ctx.get("tool_results")})
    previous = None
    conn = connect(db_path)
    try:
        latest = get_latest_scan(conn)
        if latest:
            previous = latest.get("scan_timestamp")
    finally:
        conn.close()

    if progress:
        progress.advance(29, "Launching multi-agent orchestrator (Rhea, Columbo, Izzy, Mike)", agent="system", phase="orchestrating")
    ctx["_progress"] = progress
    state = run_orchestration(ctx, scan_type=scan_type, previous_scan_id=previous, progress=progress)
    if progress:
        progress.merge_state(state.to_dict())

    if progress:
        progress.advance(72, "Checking for missing privacy, CSRF, and header disclosures", agent="disclosure", phase="disclosure")
        progress.agent_start("disclosure", "Evaluating public route disclosures", 72)
    evaluate_disclosure_gaps(state)
    if progress:
        progress.agent_done("disclosure", "Disclosure evaluation complete", 74)
        progress.merge_state(state.to_dict())

    partial = any(c.status in ("partial", "not_tested") for c in state.check_results)
    for check in state.check_results:
        if check.status in ("fail", "partial"):
            log_check_failure(check.check_id, check.status, check.evidence, check.finding_ids)

    if progress:
        progress.advance(75, "Saving scan results and control verdicts to database", agent="system", phase="saving")
    conn = connect(db_path)
    try:
        scan_row_id = save_scan(conn, state, triggered_by=triggered_by)
    finally:
        conn.close()

    if progress:
        progress.advance(82, "Writing professional gap analysis report with OpenAI", agent="reporter", phase="llm")
        progress.agent_start("reporter", "Generating gap analysis report", 82)
    llm_report: LLMReport = generate_report(
        state.to_dict(),
        client=llm_client,
        scan_id=scan_row_id,
    )
    ctx["scan_logged"] = True

    if progress:
        progress.advance(93, "Persisting report HTML and markdown to database", agent="reporter", phase="saving")
    conn = connect(db_path)
    try:
        report_id = save_report(
            conn,
            scan_id=scan_row_id,
            markdown=llm_report.markdown,
            html=llm_report.html,
            sections=llm_report.sections,
            executive_summary=llm_report.executive_summary,
            state=state,
            llm_model=llm_report.model,
        )
    finally:
        conn.close()

    if progress:
        progress.advance(97, "Writing report file to reports/ folder", agent="reporter", phase="saving")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    markdown_path = REPORTS_DIR / f"compliance_{timestamp}.md"
    markdown_path.write_text(llm_report.markdown, encoding="utf-8")

    log_event(
        "COMPLIANCE_SCAN_COMPLETED",
        {
            "scan_id": scan_row_id,
            "report_id": report_id,
            "iteration_count": state.iteration_count,
            "findings_open": sum(1 for v in state.verdicts if v.verdict == "Non-Compliant"),
            "partial_checks": partial,
        },
    )

    elapsed = int(time.time() - progress.started_at) if progress else None
    investigation = build_investigation_from_state(
        state.to_dict(),
        timeline=progress.full_timeline if progress else [],
        agent_status=dict(progress.agent_status) if progress else {},
        duration_seconds=elapsed,
        scan_row_id=scan_row_id,
        report_id=report_id,
        scan_complete=True,
    )
    conn = connect(db_path)
    try:
        update_scan_investigation(conn, scan_row_id, investigation)
    finally:
        conn.close()

    if progress:
        progress.agent_done("reporter", f"Report #{report_id} saved to database", 99)
        progress.merge_state(state.to_dict())

    return ScanResult(
        scan_id=scan_row_id,
        report_id=report_id,
        state=state,
        markdown_path=markdown_path,
        partial_checks=partial,
    )
