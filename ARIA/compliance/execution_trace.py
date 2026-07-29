from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from compliance.config import APP_HOST, APP_PORT, BASE_DIR, PRIVACY_ROUTES, REQUIRED_HEADERS
from compliance.evidence import find_line_number, rel, snippet_at_line
from compliance.state import CheckResult


def _step(n: int, action: str, detail: str, *, code: str | None = None, output: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"step": n, "action": action, "detail": detail}
    if code:
        row["code"] = code
    if output:
        row["output"] = output
    return row


def _app_path(ctx: dict[str, Any]) -> Path:
    return Path(ctx.get("app_path", BASE_DIR / "app.py"))


def _read_app(ctx: dict[str, Any]) -> tuple[str, str]:
    path = _app_path(ctx)
    return path.read_text(encoding="utf-8"), rel(path, BASE_DIR)


def attach_execution_trace(result: CheckResult, ctx: dict[str, Any]) -> dict[str, Any]:
    detail = dict(result.evidence_detail or {})
    if not detail.get("execution_trace"):
        builder = _TRACE_BUILDERS.get(result.check_id)
        if builder:
            detail["execution_trace"] = builder(result, ctx, detail)
    return detail


def _trace_tc_01(result: CheckResult, ctx: dict[str, Any], detail: dict[str, Any]) -> list[dict[str, Any]]:
    app_path = _app_path(ctx)
    transfer_path = BASE_DIR / "transfer_service.py"
    source, app_file = _read_app(ctx)
    patterns = ["from transfer_service import process_transfer", "import transfer_service"]
    matched = [p for p in patterns if p in source]
    line = find_line_number(source, r"transfer_service")
    line_text = source.splitlines()[line - 1].strip() if line else None
    return [
        _step(
            1,
            "Read application entrypoint",
            f"Loaded `{app_file}` from disk ({len(source):,} bytes, {len(source.splitlines())} lines).",
            code=f'Path("{app_path}").read_text(encoding="utf-8")',
        ),
        _step(
            2,
            "Search for transfer_service import statements",
            "Performed literal substring search for known import patterns.",
            code="\n".join(f'"{p}" in source  →  {p in source}' for p in patterns),
            output=f"Matched patterns: {matched or ['(none)']}",
        ),
        _step(
            3,
            "Resolve import line number",
            f"Scanned each line with re.search(r'transfer_service', line) — first hit at line {line}.",
            code=f"find_line_number(source, r'transfer_service')  →  {line}",
            output=line_text or "No line matched",
        ),
        _step(
            4,
            "Verify transfer_service module file",
            f"Checked companion module `{rel(transfer_path, BASE_DIR)}` exists on filesystem.",
            code=f'Path("{transfer_path}").exists()  →  {transfer_path.exists()}',
            output=f"exists={transfer_path.exists()}, size={transfer_path.stat().st_size if transfer_path.exists() else 0} bytes",
        ),
        _step(
            5,
            "Record matched source excerpt",
            "Captured surrounding lines for the investigation audit trail.",
            code=detail.get("snippet") or "(no snippet)",
        ),
        _step(
            6,
            "Determine check verdict",
            f"PASS requires import match AND module file present → status={result.status.upper()}.",
            output=result.evidence,
        ),
    ]


def _trace_file_pattern(result: CheckResult, ctx: dict[str, Any], detail: dict[str, Any], *, patterns: list[tuple[str, str]]) -> list[dict[str, Any]]:
    source, app_file = _read_app(ctx)
    trace = [
        _step(1, "Read application source", f"Loaded `{app_file}`.", code=f'Path("{_app_path(ctx)}").read_text()'),
    ]
    n = 2
    for label, pattern in patterns:
        hit = bool(__import__("re").search(pattern, source, __import__("re").I))
        line = find_line_number(source, pattern)
        trace.append(
            _step(
                n,
                label,
                f"Pattern `{pattern}` → matched={hit}, line={line}",
                code=f"re.search(r'{pattern}', source, re.I)",
                output=snippet_at_line(source, line) if line else "No match",
            )
        )
        n += 1
    trace.append(_step(n, "Verdict", result.evidence, output=f"status={result.status}"))
    return trace


def _trace_http_dast(
    result: CheckResult,
    ctx: dict[str, Any],
    detail: dict[str, Any],
    *,
    login: bool,
    requests: list[dict[str, str]],
) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = [
        _step(
            1,
            "Initialize Flask test client",
            "Created in-process WSGI client — no external network; app imported from app.py.",
            code="from compliance.flask_adapter import get_test_client\nclient = get_test_client()",
        ),
    ]
    n = 2
    if login:
        trace.append(
            _step(
                n,
                "Authenticate test user",
                "POST /login with john@aria.local / password123, follow_redirects=True.",
                code='client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)',
                output="Session cookie stored on client",
            )
        )
        n += 1
    for req in requests:
        trace.append(
            _step(
                n,
                req.get("label", "HTTP request"),
                req.get("detail", ""),
                code=req.get("code", ""),
                output=result.evidence,
            )
        )
        n += 1
    trace.append(_step(n, "Verdict", f"Check {result.check_id} → {result.status.upper()}", output=result.evidence))
    return trace


def _trace_sql(
    result: CheckResult,
    ctx: dict[str, Any],
    detail: dict[str, Any],
    *,
    sql: str,
    purpose: str,
) -> list[dict[str, Any]]:
    db = ctx.get("db_path", "aria_bank.db")
    return [
        _step(1, "Open SQLite connection", f"Connected to `{db}`.", code=f'sqlite3.connect("{db}")'),
        _step(2, "Execute query", purpose, code=sql, output=result.evidence),
        _step(3, "Close connection", "Connection closed in finally block.", output=f"status={result.status}"),
    ]


def _trace_subprocess(result: CheckResult, ctx: dict[str, Any], detail: dict[str, Any], *, cmd: list[str], cwd: str) -> list[dict[str, Any]]:
    return [
        _step(
            1,
            "Spawn subprocess",
            f"Working directory: `{cwd}`",
            code=f"subprocess.run({cmd!r}, cwd={cwd!r}, capture_output=True, text=True, timeout=120)",
        ),
        _step(2, "Capture output", "stdout/stderr captured for evidence.", output=(result.evidence or "")[:800]),
        _step(3, "Verdict", f"Exit-driven status → {result.status.upper()}"),
    ]


def _trace_headers(result: CheckResult, ctx: dict[str, Any], detail: dict[str, Any], *, url: str) -> list[dict[str, Any]]:
    headers = ctx.get("response_headers") or {}
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items()) or "(no headers captured)"
    return [
        _step(
            1,
            "HTTP GET request",
            f"Probed live application at {url}.",
            code=f'urlopen(Request("{url}", method="GET"), timeout=3)',
        ),
        _step(2, "Read response headers", f"Collected {len(headers)} header(s).", output=header_lines),
        _step(
            3,
            "Compare against required headers",
            f"Required: {REQUIRED_HEADERS}",
            output=result.evidence,
        ),
        _step(4, "Verdict", f"status={result.status.upper()}"),
    ]


_TRACE_BUILDERS = {
    "TC-01": _trace_tc_01,
    "TC-02": lambda r, c, d: _trace_subprocess(
        r, c, d, cmd=[sys.executable, str(BASE_DIR / "test_transfer_security.py")], cwd=str(BASE_DIR)
    ),
    "TC-03": lambda r, c, d: [
        _step(1, "Query historical self-transfers", "Count rejected SELF_TRANSFER rows.", code="SELECT COUNT(*) FROM rejected_transfers WHERE reason_code='SELF_TRANSFER'"),
        _step(
            2,
            "Run pytest function",
            "Invoked test_self_transfer_rejected in isolated subprocess.",
            code=f'{sys.executable} -c "from test_transfer_security import test_self_transfer_rejected; test_self_transfer_rejected()"',
            output=r.evidence,
        ),
        _step(3, "Verdict", f"status={r.status.upper()}"),
    ],
    "TC-04": lambda r, c, d: _trace_sql(
        r, c, d, sql="SELECT name FROM sqlite_master WHERE type='table'; SELECT COUNT(*) FROM rejected_transfers;", purpose="Verify rejected_transfers table schema and row count"
    ),
    "TC-05": lambda r, c, d: [
        _step(1, "Check automation availability", "Concurrent race test is not automated in this build.", output=r.evidence),
        _step(2, "Verdict", "Marked not_tested — requires Burp/manual replay.", output=f"status={r.status}"),
    ],
    "CF-01": lambda r, c, d: _trace_file_pattern(
        r, c, d, patterns=[("Search hardcoded SECRET_KEY", r'SECRET_KEY["\']?\s*=\s*["\']')]
    ),
    "CF-02": lambda r, c, d: _trace_file_pattern(r, c, d, patterns=[("Search debug=True", r"debug\s*=\s*True")]),
    "CF-03": lambda r, c, d: _trace_headers(r, c, d, url=f"http://{APP_HOST}:{APP_PORT}/"),
    "CF-04": lambda r, c, d: [
        _step(1, "Read app.py __main__ block", "Checked for app.run() dev server usage.", code='grep "app.run(" app.py'),
        _step(2, "Read run_server.py", "Verified production entrypoint exists.", code="Path('run_server.py').exists()"),
        _step(3, "Verdict", r.evidence, output=f"status={r.status}"),
    ],
    "SI-01": lambda r, c, d: _trace_file_pattern(
        r, c, d, patterns=[("Unsafe f-string SQL", r'execute\(f["\']'), ("format() SQL", r"execute\(.*\.format\(")]
    ),
    "SI-02": lambda r, c, d: _trace_http_dast(
        r,
        c,
        d,
        login=True,
        requests=[
            {
                "label": "Baseline GET /statements",
                "detail": "Legitimate user_id=1 request for size comparison.",
                "code": 'client.get("/statements?user_id=1", follow_redirects=True)',
            },
            {
                "label": "Injection GET /statements",
                "detail": "Malicious user_id=1 OR 1=1 — compare response body length.",
                "code": 'client.get("/statements?user_id=1%20OR%201=1", follow_redirects=True)',
            },
        ],
    ),
    "SI-03": lambda r, c, d: _trace_file_pattern(r, c, d, patterns=[("Parameterized LIKE in transactions", r"LIKE \?")]),
    "AC-01": lambda r, c, d: _trace_http_dast(
        r,
        c,
        d,
        login=True,
        requests=[
            {"label": "GET /profile (before)", "detail": "Capture baseline role in HTML.", "code": 'client.get("/profile", follow_redirects=True)'},
            {
                "label": "POST /profile with role=admin",
                "detail": "Attempt privilege escalation via form field tampering.",
                "code": 'client.post("/profile", data={"full_name": "John Carter", "phone": "", "address": "", "role": "admin"}, follow_redirects=True)',
            },
            {"label": "GET /profile (after)", "detail": "Verify role unchanged in rendered profile.", "code": 'client.get("/profile", follow_redirects=True)'},
        ],
    ),
    "AC-02": lambda r, c, d: _trace_http_dast(
        r, c, d, login=True, requests=[{"label": "GET /admin as customer", "detail": "Expect HTTP 403 Forbidden.", "code": 'client.get("/admin", follow_redirects=False)'}]
    ),
    "AC-03": lambda r, c, d: _trace_http_dast(
        r, c, d, login=True, requests=[{"label": "GET /employee-portal as customer", "detail": "Expect HTTP 403.", "code": 'client.get("/employee-portal", follow_redirects=False)'}]
    ),
    "AC-04": lambda r, c, d: _trace_http_dast(
        r,
        c,
        d,
        login=True,
        requests=[
            {"label": "GET own dashboard", "detail": "Baseline dashboard for user 1.", "code": 'client.get("/dashboard", follow_redirects=True)'},
            {"label": "GET dashboard user_id=2", "detail": "IDOR probe — compare response bodies.", "code": 'client.get("/dashboard?user_id=2", follow_redirects=True)'},
        ],
    ),
    "AC-05": lambda r, c, d: _trace_file_pattern(
        r, c, d, patterns=[("Admin users route", r"/admin/users"), ("Parameterized role UPDATE", r"role = \?")]
    ),
    "WC-01": lambda r, c, d: _trace_http_dast(
        r,
        c,
        d,
        login=False,
        requests=[
            {"label": "Fetch /transfer HTML", "detail": "Search response for csrf hidden input.", "code": 'client.get("/transfer")'},
            {"label": "Fetch /profile HTML", "detail": "Search response for csrf token.", "code": 'client.get("/profile")'},
            {"label": "Fetch /login HTML", "detail": "Search response for csrf token.", "code": 'client.get("/login")'},
        ],
    ),
    "WC-02": lambda r, c, d: _trace_http_dast(
        r,
        c,
        d,
        login=False,
        requests=[
            {
                "label": "Six failed login attempts",
                "detail": "POST /login with invalid credentials — watch for HTTP 429.",
                "code": 'for _ in range(6): client.post("/login", data={"email": "x@y.com", "password": "bad"}, follow_redirects=True)',
            },
        ],
    ),
    "WC-03": lambda r, c, d: _trace_headers(r, c, d, url=f"http://{APP_HOST}:{APP_PORT}/"),
    "LM-01": lambda r, c, d: _trace_sql(
        r,
        c,
        d,
        sql="SELECT ip_address, severity FROM audit_logs WHERE event_type='LOGIN_FAILED' LIMIT 20",
        purpose="Measure ip_address + severity completeness on failed login rows",
    ),
    "LM-02": lambda r, c, d: _trace_sql(
        r, c, d, sql="SELECT COUNT(*) FROM audit_logs WHERE event_type='UNAUTHORIZED_ACCESS_ATTEMPT'", purpose="Count unauthorized access audit events"
    ),
    "LM-03": lambda r, c, d: [
        _step(
            1,
            "Filesystem check",
            "Verify structured JSON Lines compliance log exists.",
            code=f'Path("{BASE_DIR / "logs" / "compliance_events.jsonl"}").exists()',
            output=r.evidence,
        ),
        _step(2, "Verdict", f"status={r.status.upper()}"),
    ],
    "LM-04": lambda r, c, d: [
        _step(1, "Scan pipeline flag", "Checked ctx['scan_logged'] after COMPLIANCE_SCAN_COMPLETED event.", output=str(c.get("scan_logged"))),
        _step(2, "Verdict", r.evidence, output=f"status={r.status}"),
    ],
}
