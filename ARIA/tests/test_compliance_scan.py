from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from compliance.llm_reporter import MissingAPIKeyError
from compliance.config import BASE_DIR, DEFAULT_DB_PATH
from compliance.orchestrator import run_orchestration
from compliance.repository import connect, get_latest_scan, mark_report_reviewed, save_report, save_scan
from compliance.scan_service import run_scan
from compliance.state import ScanState, new_scan_id


class FakeMessage:
    content = json.dumps(
        {
            "executive_summary": "ARIA Bank has material access-control and logging gaps requiring prioritized remediation.",
            "risk_narrative": "Overall posture is below target for a production banking application.",
            "top_recommendations": [
                "Fix profile role tampering (F-05)",
                "Implement CSRF tokens (F-08)",
                "Add security headers (F-15)",
            ],
            "finding_impacts": {"F-05": "Customers could escalate privileges to admin."},
            "markdown_addendum": "",
        }
    )


class FakeChoice:
    message = FakeMessage()


class FakeResponse:
    choices = [FakeChoice()]
    model = "test-model"


def test_orchestrator_runs_iterations():
    ctx = {
        "db_path": str(DEFAULT_DB_PATH),
        "app_path": str(BASE_DIR / "app.py"),
        "audit_summary": {"failed_login_completeness_pct": 50, "critical_action_completeness_pct": 60},
        "tool_results": {"pytest": {"passed": 1, "total": 2}},
        "response_headers": {},
    }
    state = run_orchestration(ctx, scan_type="manual")
    assert state.iteration_count >= 1
    assert len(state.controls) == 18
    assert len(state.verdicts) == 18


def test_scan_with_mocked_llm(monkeypatch):
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = FakeResponse()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    import compliance.config as cfg

    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "test-key")

    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "test.db"
        conn = sqlite3.connect(db)
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
            CREATE TABLE rejected_transfers (id INTEGER PRIMARY KEY, reason_code TEXT);
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY, timestamp TEXT, user_id INTEGER,
                event_type TEXT, description TEXT, ip_address TEXT, severity TEXT
            );
            """
        )
        conn.close()

        import compliance.scan_service as scan_svc

        monkeypatch.setattr(scan_svc, "REPORTS_DIR", Path(tmp) / "reports")

        result = run_scan(db_path=db, llm_client=fake_client)
        assert result.scan_id == 1
        assert result.report_id == 1
        assert result.markdown_path.exists()


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    import compliance.config as cfg

    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "")
    with pytest.raises(MissingAPIKeyError):
        from compliance.llm_reporter import generate_report

        generate_report({"verdicts": []})
