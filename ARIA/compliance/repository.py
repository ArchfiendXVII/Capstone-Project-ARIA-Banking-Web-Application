from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from compliance.config import VERDICT_TTL_DAYS
from compliance.state import ScanState


def save_scan(conn: sqlite3.Connection, state: ScanState, *, triggered_by: int | None = None) -> int:
    kpi = state.kpi_snapshot
    fw = kpi.get("framework_scores", {})
    open_findings = sum(1 for v in state.verdicts if v.verdict == "Non-Compliant")
    resolved = sum(1 for v in state.verdicts if v.verdict == "Compliant")
    cur = conn.execute(
        """
        INSERT INTO compliance_scans (
            scan_timestamp, scan_type, triggered_by, kpi_snapshot, check_results,
            tool_results, compliance_score_owasp, compliance_score_iso,
            compliance_score_nist, compliance_score_gdpr, findings_open,
            findings_resolved, iteration_count, shared_state, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            state.scan_id,
            state.scan_type,
            triggered_by,
            json.dumps(kpi),
            json.dumps([c.__dict__ for c in state.check_results]),
            json.dumps(state.tool_results),
            fw.get("owasp"),
            fw.get("iso"),
            fw.get("nist"),
            fw.get("gdpr"),
            open_findings,
            resolved,
            state.iteration_count,
            state.to_json(),
            "completed",
        ),
    )
    scan_id = cur.lastrowid
    for verdict in state.verdicts:
        conn.execute(
            """
            INSERT INTO compliance_control_verdicts (
                control_id, scan_id, verdict, score, evidence_json,
                last_verified_at, verdict_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict.control_id,
                scan_id,
                verdict.verdict,
                verdict.score,
                json.dumps({
                    "evidence_chain": verdict.evidence_chain,
                    "evidence_items": verdict.evidence_items,
                    "standards": verdict.standards,
                }),
                verdict.last_verified_at,
                verdict.verdict_expires_at,
            ),
        )
    conn.commit()
    return scan_id


def save_report(
    conn: sqlite3.Connection,
    *,
    scan_id: int,
    markdown: str,
    html: str = "",
    sections: dict[str, Any] | None = None,
    executive_summary: str = "",
    state: ScanState,
    llm_model: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO compliance_reports (
            scan_id, report_markdown, report_html, report_sections_json,
            executive_summary, verdicts_json, disclosure_gaps_json, llm_model, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            markdown,
            html,
            json.dumps(sections or {}),
            executive_summary,
            json.dumps([v.__dict__ for v in state.verdicts]),
            json.dumps(state.disclosure_gaps),
            llm_model,
            datetime.utcnow().isoformat(timespec="seconds"),
        ),
    )
    report_id = cur.lastrowid
    # Update markdown header with final report id
    if report_id and "| **Report identifier** | pending |" in markdown:
        updated = markdown.replace(
            "| **Report identifier** | pending |",
            f"| **Report identifier** | {report_id} |",
            1,
        )
        conn.execute(
            "UPDATE compliance_reports SET report_markdown = ?, report_html = ? WHERE id = ?",
            (updated, html.replace("pending", str(report_id)) if "pending" in html else html, report_id),
        )
    conn.commit()
    return report_id


def get_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM compliance_scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def get_report_for_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM compliance_reports WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,),
    ).fetchone()
    return dict(row) if row else None


def update_scan_investigation(conn: sqlite3.Connection, scan_id: int, investigation: dict[str, Any]) -> None:
    conn.execute(
        "UPDATE compliance_scans SET investigation_json = ? WHERE id = ?",
        (json.dumps(investigation), scan_id),
    )
    conn.commit()


def get_latest_scan(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM compliance_scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def get_scan_history(conn: sqlite3.Connection, limit: int = 10) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, scan_timestamp, scan_type, findings_open, findings_resolved, iteration_count, status FROM compliance_scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_reports(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT r.*, s.scan_timestamp, s.scan_type
        FROM compliance_reports r
        JOIN compliance_scans s ON s.id = r.scan_id
        ORDER BY r.id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_report(conn: sqlite3.Connection, report_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT r.*, s.scan_timestamp, s.kpi_snapshot, s.shared_state
        FROM compliance_reports r
        JOIN compliance_scans s ON s.id = r.scan_id
        WHERE r.id = ?
        """,
        (report_id,),
    ).fetchone()
    return dict(row) if row else None


def mark_report_reviewed(conn: sqlite3.Connection, report_id: int, reviewer_id: int) -> None:
    conn.execute(
        """
        UPDATE compliance_reports
        SET human_reviewed = 1, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (reviewer_id, datetime.utcnow().isoformat(timespec="seconds"), report_id),
    )
    conn.commit()


def get_expired_verdicts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    now = datetime.utcnow().isoformat(timespec="seconds")
    rows = conn.execute(
        """
        SELECT v.*, s.scan_timestamp
        FROM compliance_control_verdicts v
        JOIN compliance_scans s ON s.id = v.scan_id
        WHERE v.verdict_expires_at < ?
        ORDER BY v.verdict_expires_at ASC
        """,
        (now,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_verdicts_for_scan(conn: sqlite3.Connection, scan_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM compliance_control_verdicts WHERE scan_id = ? ORDER BY control_id",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_kpi_trend(conn: sqlite3.Connection, last_n: int = 5) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, scan_timestamp, kpi_snapshot, compliance_score_owasp,
               compliance_score_iso, compliance_score_nist, compliance_score_gdpr
        FROM compliance_scans ORDER BY id DESC LIMIT ?
        """,
        (last_n,),
    ).fetchall()
    trend = []
    for row in rows:
        item = dict(row)
        item["kpi_snapshot"] = json.loads(item["kpi_snapshot"])
        trend.append(item)
    return trend


def _ensure_investigation_column(conn: sqlite3.Connection) -> None:
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(compliance_scans)").fetchall()}
        if cols and "investigation_json" not in cols:
            conn.execute("ALTER TABLE compliance_scans ADD COLUMN investigation_json TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass


def connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_investigation_column(conn)
    return conn
