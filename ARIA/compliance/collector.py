from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from compliance.checks import fetch_response_headers, run_pytest_suite, run_semgrep
from compliance.config import BASE_DIR, DEFAULT_DB_PATH


def collect_signals(db_path: Path | str | None = None, progress=None) -> dict[str, Any]:
    db_path = Path(db_path or DEFAULT_DB_PATH)

    if progress:
        progress.agent_start("collector", "Collecting DB signals and running baseline tests", 3)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        audit_summary = _audit_summary(conn)

        if progress:
            progress.advance(6, "Analyzing rejected transfers table", agent="collector", phase="collecting")

        transfer_summary = _transfer_summary(conn)

        if progress:
            progress.advance(9, "Running smoke_tests.py", agent="collector", phase="collecting")

        pytest_transfer = _run_single_test("test_transfer_security.py", progress, 12, "Running transfer security tests")
        if progress:
            progress.advance(18, "Running smoke_tests.py", agent="collector", phase="collecting")
        pytest_smoke = _run_single_test("smoke_tests.py", progress, 22, "Running application smoke tests")

        if progress:
            progress.advance(24, "Running Semgrep static analysis (optional)", agent="collector", phase="collecting")
        semgrep = run_semgrep()

        if progress:
            progress.advance(26, "Probing HTTP security headers", agent="collector", phase="collecting")
        headers = fetch_response_headers()

        if progress:
            progress.advance(28, "Signal collection complete", agent="collector", phase="collecting")
            progress.agent_done("collector", "All signals collected — handing off to agents", 28)

        return {
            "db_path": str(db_path),
            "app_path": str(BASE_DIR / "app.py"),
            "audit_summary": audit_summary,
            "transfer_summary": transfer_summary,
            "tool_results": {
                "pytest": {
                    "tests": {**pytest_transfer, **pytest_smoke},
                    "passed": sum(1 for t in {**pytest_transfer, **pytest_smoke}.values() if t.get("passed")),
                    "total": 2,
                },
                "semgrep": semgrep,
            },
            "response_headers": headers,
            "scan_logged": False,
        }
    finally:
        conn.close()


def _run_single_test(name: str, progress, pct: int, message: str) -> dict[str, Any]:
    import subprocess
    import sys

    if progress:
        progress.advance(pct, message, agent="collector", phase="collecting")
    proc = subprocess.run(
        [sys.executable, str(BASE_DIR / name)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        timeout=180,
    )
    return {name: {"returncode": proc.returncode, "passed": proc.returncode == 0}}


def _audit_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    since = (datetime.utcnow() - timedelta(days=7)).isoformat(timespec="seconds")
    critical_types = ("LOGIN_FAILED", "UNAUTHORIZED_ACCESS_ATTEMPT", "TRANSFER", "ADMIN_VIEW_REJECTED_TRANSFERS")
    rows = conn.execute(
        """
        SELECT event_type, ip_address, severity, description
        FROM audit_logs
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 500
        """,
        (since,),
    ).fetchall()
    failed_logins = [r for r in rows if r["event_type"] == "LOGIN_FAILED"]
    login_complete = 0.0
    if failed_logins:
        login_complete = sum(1 for r in failed_logins if r["ip_address"] and r["severity"]) / len(failed_logins) * 100

    critical_rows = [r for r in rows if r["event_type"] in critical_types]
    critical_complete = 0.0
    if critical_rows:
        critical_complete = sum(
            1 for r in critical_rows if r["ip_address"] and r["severity"] and r["description"]
        ) / len(critical_rows) * 100

    unauthorized = conn.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type='UNAUTHORIZED_ACCESS_ATTEMPT'"
    ).fetchone()[0]
    return {
        "window_days": 7,
        "total_events": len(rows),
        "failed_login_count": len(failed_logins),
        "failed_login_completeness_pct": round(login_complete, 1),
        "critical_action_completeness_pct": round(critical_complete, 1),
        "unauthorized_attempts": unauthorized,
    }


def _transfer_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "rejected_transfers" not in tables:
        return {"rejected_count": 0, "reason_breakdown": {}}
    rows = conn.execute(
        "SELECT reason_code, COUNT(*) AS cnt FROM rejected_transfers GROUP BY reason_code"
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM rejected_transfers").fetchone()[0]
    return {
        "rejected_count": total,
        "reason_breakdown": {r["reason_code"]: r["cnt"] for r in rows},
    }
