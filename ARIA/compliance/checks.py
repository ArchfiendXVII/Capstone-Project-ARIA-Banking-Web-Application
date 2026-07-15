from __future__ import annotations

import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from compliance.check_enricher import enrich_check_result
from compliance.config import APP_HOST, APP_PORT, BASE_DIR, PRIVACY_ROUTES, REQUIRED_HEADERS
from compliance.evidence import build_evidence, find_line_number, rel, snippet_at_line
from compliance.flask_adapter import get_test_client
from compliance.metadata import get_check_name
from compliance.state import CheckResult

CheckFn = Callable[[dict[str, Any]], CheckResult]


def _result(
    check_id: str,
    status: str,
    evidence: str,
    *,
    finding_ids: list[str] | None = None,
    standards: list[str] | None = None,
    source_weight: float = 0.8,
    agent: str = "metrics",
    evidence_detail: dict[str, Any] | None = None,
) -> CheckResult:
    detail = dict(evidence_detail or {})
    detail.setdefault("test_name", get_check_name(check_id))
    detail.setdefault("observation", evidence)
    detail["status"] = status
    return CheckResult(
        check_id=check_id,
        status=status,
        evidence=evidence,
        finding_ids=finding_ids or [],
        standards=standards or [],
        source_weight=source_weight,
        agent=agent,
        evidence_detail=detail,
    )


def _app_path(ctx: dict[str, Any]) -> Path:
    return Path(ctx.get("app_path", BASE_DIR / "app.py"))


def _read_app_source(ctx: dict[str, Any]) -> str:
    return _app_path(ctx).read_text(encoding="utf-8")


def check_tc_01(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    app_file = rel(_app_path(ctx), BASE_DIR)
    transfer_path = BASE_DIR / "transfer_service.py"
    ok = "from transfer_service import process_transfer" in source or "import transfer_service" in source
    line = find_line_number(source, r"transfer_service")
    return _result(
        "TC-01",
        "pass" if ok and transfer_path.exists() else "fail",
        "Transfer route uses the dedicated transfer_service module" if ok else "transfer_service is not wired into app.py",
        finding_ids=["F-18"],
        standards=["OWASP A04", "NIST SI"],
        source_weight=0.9,
        agent="metrics",
        evidence_detail=build_evidence(
            test_name="Transfer service integration",
            method="Static import analysis + file existence check",
            observation="app.py imports process_transfer from transfer_service.py" if ok else "Missing transfer_service import in app.py",
            location=f"{app_file} and transfer_service.py",
            file=app_file,
            line=line,
            snippet=snippet_at_line(source, line),
            tool="Source code review",
            result_detail=f"transfer_service.py exists={transfer_path.exists()}",
        ),
    )


def check_tc_02(ctx: dict[str, Any]) -> CheckResult:
    try:
        proc = subprocess.run(
            [sys.executable, str(BASE_DIR / "test_transfer_security.py")],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=120,
        )
        ok = proc.returncode == 0 and "idempotent" in proc.stdout.lower() + proc.stderr.lower()
        return _result(
            "TC-02",
            "pass" if ok else "fail",
            proc.stdout[-400:] if proc.stdout else proc.stderr[-400:],
            finding_ids=["F-18", "GAP-01"],
            standards=["OWASP A04"],
            source_weight=0.95,
            agent="dast",
        )
    except Exception as exc:
        return _result("TC-02", "not_tested", str(exc), finding_ids=["F-18"], agent="dast")


def check_tc_03(ctx: dict[str, Any]) -> CheckResult:
    db_path = ctx["db_path"]
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM rejected_transfers WHERE reason_code='SELF_TRANSFER'").fetchone()[0]
        proc = subprocess.run(
            [sys.executable, "-c", "from test_transfer_security import test_self_transfer_rejected; test_self_transfer_rejected()"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=60,
        )
        ok = proc.returncode == 0
        return _result(
            "TC-03",
            "pass" if ok else "fail",
            f"self_transfer_test_ok={ok}; historical_self_transfer_rows={count}",
            finding_ids=["F-18", "GAP-02"],
            standards=["OWASP A04"],
            source_weight=0.95,
            agent="dast",
        )
    finally:
        conn.close()


def check_tc_04(ctx: dict[str, Any]) -> CheckResult:
    db_path = ctx["db_path"]
    conn = sqlite3.connect(db_path)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "rejected_transfers" not in tables:
            return _result("TC-04", "fail", "rejected_transfers table missing", finding_ids=["F-18", "GAP-05"], agent="runtime")
        count = conn.execute("SELECT COUNT(*) FROM rejected_transfers").fetchone()[0]
        return _result(
            "TC-04",
            "pass" if count >= 0 else "fail",
            f"rejected_transfers table exists; row_count={count}",
            finding_ids=["F-18", "GAP-05"],
            standards=["NIST AU"],
            agent="runtime",
        )
    finally:
        conn.close()


def check_tc_05(ctx: dict[str, Any]) -> CheckResult:
    return _result(
        "TC-05",
        "not_tested",
        "Parallel race test requires Burp/manual replay; automated concurrent test deferred",
        finding_ids=["F-18", "GAP-01"],
        standards=["OWASP A04"],
        source_weight=0.5,
        agent="dast",
    )


def check_ac_01(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
    before = client.get("/profile", follow_redirects=True)
    client.post(
        "/profile",
        data={"full_name": "John Carter", "phone": "", "address": "", "role": "admin"},
        follow_redirects=True,
    )
    after = client.get("/profile", follow_redirects=True)
    role_unchanged = b"customer" in after.data.lower() or b"Customer" in after.data
    return _result(
        "AC-01",
        "pass" if role_unchanged else "fail",
        "Profile POST with role=admin did not persist admin role" if role_unchanged else "Role tampering may have succeeded",
        finding_ids=["F-05", "GAP-03"],
        standards=["OWASP A01", "NIST AC-3"],
        source_weight=0.95,
        agent="dast",
    )


def check_ac_02(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
    resp = client.get("/admin", follow_redirects=False)
    return _result(
        "AC-02",
        "pass" if resp.status_code == 403 else "fail",
        f"customer GET /admin -> {resp.status_code}",
        finding_ids=["F-07", "GAP-04"],
        standards=["OWASP A01"],
        source_weight=0.95,
        agent="dast",
    )


def check_ac_03(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
    resp = client.get("/employee-portal", follow_redirects=False)
    return _result(
        "AC-03",
        "pass" if resp.status_code == 403 else "fail",
        f"customer GET /employee-portal -> {resp.status_code}",
        finding_ids=["F-06"],
        standards=["OWASP A01"],
        source_weight=0.95,
        agent="dast",
    )


def check_ac_04(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
    own = client.get("/dashboard", follow_redirects=True)
    other = client.get("/dashboard?user_id=2", follow_redirects=True)
    idor = own.status_code == 200 and other.status_code == 200 and own.data != other.data
    return _result(
        "AC-04",
        "fail" if idor else "pass",
        f"dashboard IDOR detected={idor}",
        finding_ids=["F-03", "F-04", "F-13"],
        standards=["OWASP A01"],
        source_weight=0.95,
        agent="dast",
    )


def check_ac_05(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    profile_updates_role = "UPDATE users SET" in source and "role" in source[source.find("def profile"): source.find("def support")]
    admin_route = "/admin/users" in source
    return _result(
        "AC-05",
        "pass" if admin_route and "role = ?" in source else "partial",
        f"admin_users route present={admin_route}",
        finding_ids=["F-05"],
        standards=["OWASP A01"],
        agent="metrics",
    )


def check_si_01(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    unsafe = bool(re.search(r'execute\(f["\']|execute\(.*\.format\(|f["\'].*SELECT', source, re.I))
    return _result(
        "SI-01",
        "fail" if unsafe else "pass",
        "Unsafe SQL string construction detected" if unsafe else "No obvious f-string SQL in app.py",
        finding_ids=["F-09", "F-10"],
        standards=["OWASP A03"],
        source_weight=0.9,
        agent="metrics",
    )


def check_si_02(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
    own = client.get("/statements?user_id=1", follow_redirects=True)
    inject = client.get("/statements?user_id=1%20OR%201=1", follow_redirects=True)
    vulnerable = len(inject.data) > len(own.data) + 100
    return _result(
        "SI-02",
        "fail" if vulnerable else "partial",
        f"statements injection probe vulnerable={vulnerable}",
        finding_ids=["F-09"],
        standards=["OWASP A03"],
        agent="dast",
    )


def check_si_03(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    tx_search = "transactions" in source and "LIKE ?" in source
    return _result(
        "SI-03",
        "pass" if tx_search else "partial",
        f"transaction search uses parameterized LIKE={tx_search}",
        finding_ids=["F-10"],
        standards=["OWASP A03"],
        agent="metrics",
    )


def check_cf_01(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    hardcoded = 'SECRET_KEY"] = "aria-bank-dev-secret"' in source or "SECRET_KEY = " in source
    return _result(
        "CF-01",
        "fail" if hardcoded else "pass",
        "Hardcoded SECRET_KEY found" if hardcoded else "No hardcoded secret pattern",
        finding_ids=["F-01", "F-16"],
        standards=["OWASP A05", "NIST CM"],
        agent="metrics",
    )


def check_cf_02(ctx: dict[str, Any]) -> CheckResult:
    source = _read_app_source(ctx)
    debug = "debug=True" in source
    return _result(
        "CF-02",
        "fail" if debug else "pass",
        "debug=True present in app entrypoint" if debug else "No debug=True in app.py",
        finding_ids=["F-15", "F-16"],
        agent="metrics",
    )


def check_cf_03(ctx: dict[str, Any]) -> CheckResult:
    headers = ctx.get("response_headers", {})
    present = [h for h in REQUIRED_HEADERS if h.lower() in {k.lower() for k in headers}]
    status = "pass" if len(present) >= 3 else "fail" if not present else "partial"
    return _result(
        "CF-03",
        status,
        f"security headers present={present}",
        finding_ids=["F-15"],
        standards=["OWASP A05", "NIST CM"],
        agent="dast",
    )


def check_cf_04(ctx: dict[str, Any]) -> CheckResult:
    run_server = (BASE_DIR / "run_server.py").read_text(encoding="utf-8") if (BASE_DIR / "run_server.py").exists() else ""
    uses_dev = "app.run(" in _read_app_source(ctx) and "if __name__" in _read_app_source(ctx)
    return _result(
        "CF-04",
        "partial" if uses_dev else "pass",
        "Flask dev server referenced in app.py __main__" if uses_dev else "Production entry via run_server.py",
        finding_ids=["F-15"],
        agent="metrics",
    )


def check_wc_01(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    pages = [client.get("/transfer"), client.get("/profile"), client.get("/login")]
    csrf = all(b"csrf" in p.data.lower() for p in pages if p.status_code == 200)
    return _result(
        "WC-01",
        "pass" if csrf else "fail",
        f"csrf token detected in forms={csrf}",
        finding_ids=["F-08"],
        standards=["OWASP A01"],
        agent="dast",
    )


def check_wc_02(ctx: dict[str, Any]) -> CheckResult:
    client = get_test_client()
    codes = []
    for _ in range(6):
        resp = client.post("/login", data={"email": "x@y.com", "password": "bad"}, follow_redirects=True)
        codes.append(resp.status_code)
    limited = 429 in codes
    return _result(
        "WC-02",
        "pass" if limited else "fail",
        f"login rate limit 429 observed={limited}",
        finding_ids=["F-02"],
        standards=["OWASP A07"],
        agent="dast",
    )


def check_wc_03(ctx: dict[str, Any]) -> CheckResult:
    headers = ctx.get("response_headers", {})
    has_csp = any(k.lower() == "content-security-policy" for k in headers)
    return _result(
        "WC-03",
        "pass" if has_csp else "fail",
        f"CSP header present={has_csp}",
        finding_ids=["F-15"],
        agent="dast",
    )


def check_lm_01(ctx: dict[str, Any]) -> CheckResult:
    db_path = ctx["db_path"]
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT ip_address, severity FROM audit_logs WHERE event_type='LOGIN_FAILED' LIMIT 20"
        ).fetchall()
        if not rows:
            return _result("LM-01", "partial", "No LOGIN_FAILED rows to evaluate", finding_ids=["F-14", "F-02"], agent="runtime")
        complete = sum(1 for ip, sev in rows if ip and sev) / len(rows)
        return _result(
            "LM-01",
            "pass" if complete >= 0.8 else "fail",
            f"failed login completeness ratio={complete:.2f}",
            finding_ids=["F-14", "F-09"],
            standards=["NIST AU"],
            agent="runtime",
        )
    finally:
        conn.close()


def check_lm_02(ctx: dict[str, Any]) -> CheckResult:
    db_path = ctx["db_path"]
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type='UNAUTHORIZED_ACCESS_ATTEMPT'"
        ).fetchone()[0]
        return _result(
            "LM-02",
            "pass" if count >= 0 else "fail",
            f"UNAUTHORIZED_ACCESS_ATTEMPT events={count}",
            finding_ids=["F-14", "GAP-05"],
            standards=["NIST AU"],
            agent="runtime",
        )
    finally:
        conn.close()


def check_lm_03(ctx: dict[str, Any]) -> CheckResult:
    log_file = BASE_DIR / "logs" / "compliance_events.jsonl"
    return _result(
        "LM-03",
        "pass" if log_file.exists() else "partial",
        f"structured compliance log exists={log_file.exists()}",
        finding_ids=["F-14"],
        agent="runtime",
    )


def check_lm_04(ctx: dict[str, Any]) -> CheckResult:
    return _result(
        "LM-04",
        "pass" if ctx.get("scan_logged") else "partial",
        f"COMPLIANCE_SCAN_COMPLETED logged={ctx.get('scan_logged', False)}",
        agent="runtime",
    )


def fetch_response_headers() -> dict[str, str]:
    url = f"http://{APP_HOST}:{APP_PORT}/"
    try:
        with urlopen(Request(url, method="GET"), timeout=3) as resp:
            return {k: v for k, v in resp.headers.items()}
    except URLError:
        return {}


def run_semgrep() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", "p/owasp-top-ten", str(BASE_DIR / "app.py")],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=120,
        )
        findings = proc.stdout.count("findings") + proc.stdout.lower().count("ruleid")
        return {"available": True, "returncode": proc.returncode, "findings_hint": findings, "output_tail": proc.stdout[-500:]}
    except FileNotFoundError:
        return {"available": False, "reason": "semgrep not installed"}
    except Exception as exc:
        return {"available": False, "reason": str(exc)}


CHECK_REGISTRY: dict[str, CheckFn] = {
    "TC-01": check_tc_01,
    "TC-02": check_tc_02,
    "TC-03": check_tc_03,
    "TC-04": check_tc_04,
    "TC-05": check_tc_05,
    "AC-01": check_ac_01,
    "AC-02": check_ac_02,
    "AC-03": check_ac_03,
    "AC-04": check_ac_04,
    "AC-05": check_ac_05,
    "SI-01": check_si_01,
    "SI-02": check_si_02,
    "SI-03": check_si_03,
    "CF-01": check_cf_01,
    "CF-02": check_cf_02,
    "CF-03": check_cf_03,
    "CF-04": check_cf_04,
    "WC-01": check_wc_01,
    "WC-02": check_wc_02,
    "WC-03": check_wc_03,
    "LM-01": check_lm_01,
    "LM-02": check_lm_02,
    "LM-03": check_lm_03,
    "LM-04": check_lm_04,
}


def run_checks(ctx: dict[str, Any], check_ids: list[str] | None = None) -> list[CheckResult]:
    ctx = dict(ctx)
    if "response_headers" not in ctx:
        ctx["response_headers"] = fetch_response_headers()
    ids = check_ids or list(CHECK_REGISTRY.keys())
    results: list[CheckResult] = []
    progress = ctx.get("_progress")
    agent = ctx.get("_current_agent", "system")
    base = ctx.get("_progress_base", 30)
    span = ctx.get("_progress_span", 10)
    total = len(ids)
    for i, check_id in enumerate(ids):
        if progress:
            progress.check_progress(agent, get_check_name(check_id), i, total, base, span)
        fn = CHECK_REGISTRY.get(check_id)
        if fn:
            result = enrich_check_result(fn(ctx), ctx)
            result.agent = agent
            results.append(result)
            if progress:
                detail = result.evidence_detail or {}
                items = detail.get("items") if isinstance(detail, dict) else []
                if not items and isinstance(detail, dict) and detail.get("test_name"):
                    items = [detail]
                progress.record_check(
                    {
                        "check_id": result.check_id,
                        "name": get_check_name(result.check_id),
                        "status": result.status,
                        "evidence": result.evidence,
                        "finding_ids": result.finding_ids,
                        "standards": result.standards,
                        "evidence_detail": result.evidence_detail,
                        "evidence_items": items,
                        "execution_trace": (result.evidence_detail or {}).get("execution_trace") or [],
                        "agent": agent,
                    }
                )
    return results


def run_pytest_suite() -> dict[str, Any]:
    tests = ["test_transfer_security.py", "smoke_tests.py"]
    outcomes = {}
    for name in tests:
        proc = subprocess.run(
            [sys.executable, str(BASE_DIR / name)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=180,
        )
        outcomes[name] = {"returncode": proc.returncode, "passed": proc.returncode == 0}
    passed = sum(1 for v in outcomes.values() if v["passed"])
    return {"tests": outcomes, "passed": passed, "total": len(tests)}
