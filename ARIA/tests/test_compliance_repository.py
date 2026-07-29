from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from compliance.repository import (
    connect,
    get_expired_verdicts,
    get_kpi_trend,
    get_latest_scan,
    mark_report_reviewed,
    save_report,
    save_scan,
)
from compliance.state import ScanState, Verdict, expiry_from_now, new_scan_id
from compliance.control_extractor import load_controls


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE compliance_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_timestamp TEXT, scan_type TEXT, triggered_by INTEGER,
            kpi_snapshot TEXT, check_results TEXT, tool_results TEXT,
            compliance_score_owasp REAL, compliance_score_iso REAL,
            compliance_score_nist REAL, compliance_score_gdpr REAL,
            findings_open INTEGER, findings_resolved INTEGER,
            iteration_count INTEGER, shared_state TEXT, status TEXT
        );
            CREATE TABLE compliance_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER, report_markdown TEXT, report_html TEXT,
                report_sections_json TEXT, executive_summary TEXT,
                verdicts_json TEXT, disclosure_gaps_json TEXT, llm_model TEXT,
                human_reviewed INTEGER DEFAULT 0, reviewed_by INTEGER,
                reviewed_at TEXT, created_at TEXT
            );
        CREATE TABLE compliance_control_verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id TEXT, scan_id INTEGER, verdict TEXT, score REAL,
            evidence_json TEXT, last_verified_at TEXT, verdict_expires_at TEXT
        );
        """
    )
    conn.close()


def test_save_and_load_scan():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "repo.db"
        _init_db(db)
        state = ScanState(scan_id=new_scan_id(), controls=load_controls())
        state.kpi_snapshot = {"KPI-01": 5, "framework_scores": {"owasp": 40}}
        state.verdicts = [
            Verdict(
                control_id="F-01",
                verdict="Non-Compliant",
                score=0.2,
                evidence_chain=["CF-01: fail"],
                last_verified_at=expiry_from_now(0),
                verdict_expires_at="2000-01-01T00:00:00",
            )
        ]
        conn = connect(db)
        scan_id = save_scan(conn, state)
        report_id = save_report(
            conn,
            scan_id=scan_id,
            markdown="# R",
            html="<p>R</p>",
            sections={},
            executive_summary="Test summary",
            state=state,
            llm_model="test",
        )
        latest = get_latest_scan(conn)
        assert latest["id"] == scan_id
        mark_report_reviewed(conn, report_id, 1)
        expired = get_expired_verdicts(conn)
        assert any(e["control_id"] == "F-01" for e in expired)
        trend = get_kpi_trend(conn, 1)
        assert trend[0]["kpi_snapshot"]["KPI-01"] == 5
        conn.close()
