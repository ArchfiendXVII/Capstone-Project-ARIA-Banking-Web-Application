# Milestone 7 — Continuous Compliance Monitoring
## Full Implementation Report (ARIA Bank)

**Project:** ARIA Bank Web Application — Group 5 Capstone  
**Document type:** Technical implementation reference  
**Status:** Implemented and operational  
**Last updated:** July 2026  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Philosophy](#2-design-philosophy)
3. [System Architecture](#3-system-architecture)
4. [End-to-End Scan Pipeline](#4-end-to-end-scan-pipeline)
5. [Agents — Roles, Interactions, and Responsibilities](#5-agents--roles-interactions-and-responsibilities)
6. [Signal Collector (Pre-Agent Phase)](#6-signal-collector-pre-agent-phase)
7. [The 24 Security Checks — Full Catalog](#7-the-24-security-checks--full-catalog)
8. [How Checks Interact With the Real Application](#8-how-checks-interact-with-the-real-application)
9. [Evidence Model and Internal Execution Traces](#9-evidence-model-and-internal-execution-traces)
10. [Judge Agent — Scoring and Verdicts](#10-judge-agent--scoring-and-verdicts)
11. [Standards Mapping (Mike)](#11-standards-mapping-mike)
12. [KPI Engine (15 Metrics)](#12-kpi-engine-15-metrics)
13. [Controls Register (F-01 … F-18)](#13-controls-register-f-01--f-18)
14. [Disclosure Evaluator](#14-disclosure-evaluator)
15. [LLM Report Generator (Reporter)](#15-llm-report-generator-reporter)
16. [Investigation Workspace UI](#16-investigation-workspace-ui)
17. [Database Schema and Persistence](#17-database-schema-and-persistence)
18. [HTTP API and Admin Routes](#18-http-api-and-admin-routes)
19. [Helper Scripts (`test_transfer_security.py`, `smoke_tests.py`)](#19-helper-scripts-test_transfer_securitypy-smoke_testspy)
20. [Source File Map](#20-source-file-map)
21. [Business Value — How This Helps ARIA Bank](#21-business-value--how-this-helps-aria-bank)
22. [Known Limitations and Honest Scope](#22-known-limitations-and-honest-scope)

---

## 1. Executive Summary

Milestone 7 implements a **Continuous Compliance Monitoring (CCM)** system for ARIA Bank. It is **not a UI mockup**: when an admin runs a scan, the system executes real Python code against the real Flask application (`app.py`), real SQLite database (`aria_bank.db`), and real transfer module (`transfer_service.py`).

The system follows a **Sibyl-inspired multi-agent orchestration** model:

- Specialized agents gather **deterministic evidence** (tests, SQL queries, static analysis, HTTP probes).
- A **Judge agent** scores controls and issues verdicts **only when evidence exists**.
- An **LLM reporter** writes executive narrative **without overriding** deterministic pass/fail results.
- An **Investigation workspace** visualizes the full agent pipeline, reasoning steps, evidence chains, and per-check execution traces.

**What was built:**

| Layer | Implementation |
|-------|----------------|
| Signal collection | DB audit analysis, smoke tests, Semgrep, HTTP header probe |
| Multi-agent orchestrator | Rhea (metrics), Columbo (DAST), Izzy (runtime), Mike (standards), Judy (judge) |
| 24 automated security checks | TC, AC, SI, CF, WC, LM families |
| 18 control definitions | F-01 … F-18 mapped to Week 2 findings |
| 15 KPIs | KPI-01 … KPI-15 with baselines |
| Admin UI | Dashboard, Investigation, Findings, Reports |
| Persistence | `compliance_scans`, `compliance_control_verdicts`, `compliance_reports`, `investigation_json` |
| Live progress | Background scan jobs with ETA, timeline, partial state polling |

---

## 2. Design Philosophy

### 2.1 Proof, not trust

Week 4 Burp testing showed controls that *looked* present (audit logs, role labels) but failed under verification (race conditions, role tampering). Milestone 7 encodes that lesson:

> **The LLM does not decide compliance.** Rule-based checks run first. The Judge scores evidence. The LLM explains results for leadership.

### 2.2 Deterministic before generative

| Step | Deterministic? | Component |
|------|----------------|-----------|
| Run security checks | Yes | `compliance/checks.py` |
| Score controls | Yes | `compliance/scoring.py` |
| Build verdicts | Yes | `compliance/agents/judge.py` |
| Write executive narrative | LLM-assisted | `compliance/llm_reporter.py` |

The LLM prompt explicitly forbids contradicting check statuses or verdicts.

### 2.3 Reuse of prior milestone work

| Prior work | Reused in Milestone 7 |
|------------|----------------------|
| Week 2 findings F-01 … F-18 | Control registry |
| Week 3 KPI-01 … KPI-15 | KPI calculator |
| Week 4 GAP-01 … GAP-05 | Check mapping, retest matrix |
| Week 5 remediation themes | Check categories (transfers, AC, SQL, config, web, logging) |
| `test_transfer_security.py`, `smoke_tests.py` | Collector + TC-02/TC-03 checks |

---

## 3. System Architecture

### 3.1 High-level diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Admin UI (Flask Blueprint)                          │
│  /admin/compliance  ·  /investigation  ·  /findings  ·  /reports            │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ POST /run/start  →  background thread
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         compliance/scan_service.py                          │
│                              run_scan()                                     │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ Signal Collector │    │ Multi-Agent          │    │ Post-processing      │
│ collect_signals  │───▶│ Orchestrator         │───▶│ disclosure, save,    │
│                  │    │ run_orchestration    │    │ LLM report, persist  │
└──────────────────┘    └──────────────────────┘    └──────────────────────┘
          │                         │
          │                         ├── Rhea · Metrics Agent
          │                         ├── Columbo · DAST Agent
          │                         ├── Izzy · Runtime Agent
          │                         ├── Mike · Standards Agent
          │                         └── Judy · Judge Agent (loop ≤ MAX_ITERATIONS)
          │
          ▼
   aria_bank.db · app.py · test scripts · Semgrep · HTTP probe
```

### 3.2 Core modules

| Module | Path | Responsibility |
|--------|------|----------------|
| Scan entry | `compliance/scan_service.py` | Orchestrates full scan lifecycle |
| Collector | `compliance/collector.py` | Pre-scan signal gathering |
| Orchestrator | `compliance/orchestrator.py` | Agent loop + reinvestigation |
| Checks | `compliance/checks.py` | 24 check implementations |
| Check enricher | `compliance/check_enricher.py` | Structured evidence + execution traces |
| Execution trace | `compliance/execution_trace.py` | Step-by-step internal audit trail per check |
| Investigation | `compliance/investigation.py` | Builds Investigation JSON for UI |
| Progress | `compliance/scan_progress.py` | Live job tracking, timeline, ETA |
| Repository | `compliance/repository.py` | SQLite persistence |
| Routes | `compliance/routes.py` | Admin blueprint |
| Scoring | `compliance/scoring.py` | Control scores and verdict labels |
| KPI | `compliance/kpi_calculator.py` | KPI-01 … KPI-15 snapshot |
| LLM reporter | `compliance/llm_reporter.py` | OpenAI gap analysis narrative |
| Flask adapter | `compliance/flask_adapter.py` | In-process test client for real app |

### 3.3 Agent naming (Sibyl mapping)

| Agent ID | Display name | Sibyl inspiration | Primary domain |
|----------|--------------|-------------------|----------------|
| `system` | Orchestrator | Orchestrator | Pipeline coordination |
| `collector` | Signal Collector | Data ingestion | DB + baseline tests |
| `metrics` | Rhea · Metrics Agent | Metrics specialist | Config, transfers (static), KPIs |
| `dast` | Columbo · DAST Agent | Geography/satellite verification | Dynamic HTTP probes |
| `runtime` | Izzy · Runtime Agent | Runtime behaviour | DB logging, audit completeness |
| `standards` | Mike · Standards Agent | Standards corpus | OWASP/ISO/NIST/GDPR mapping |
| `judge` | Judy · Judge Agent | Judge | Verdicts, reinvestigation |
| `disclosure` | Disclosure Evaluator | Policy gaps | Missing routes/disclosures |
| `reporter` | Report Generator | Reporter | LLM + markdown reports |

---

## 4. End-to-End Scan Pipeline

When an admin clicks **Run Scan** on the Investigation tab:

### Phase 1 — Job creation (0–2%)

1. `POST /admin/compliance/run/start` creates a `ScanProgressTracker` job with UUID.
2. Background thread starts `run_scan(progress=job)` inside Flask app context.
3. UI polls `GET /admin/compliance/run/status/<job_id>` every ~1.5s.

### Phase 2 — Signal collection (3–28%)

`collect_signals(db_path)` runs **before** agents:

- Opens real `aria_bank.db`
- Computes 7-day audit summary (failed logins, unauthorized attempts, completeness %)
- Summarizes `rejected_transfers` by reason code
- Subprocess: `python test_transfer_security.py`
- Subprocess: `python smoke_tests.py`
- Optional: `semgrep scan --config p/owasp-top-ten app.py`
- Live HTTP GET `http://127.0.0.1:5000/` for response headers (if server running)

Returns shared context `ctx` passed to all agents:

```python
{
    "db_path": ".../aria_bank.db",
    "app_path": ".../app.py",
    "audit_summary": {...},
    "transfer_summary": {...},
    "tool_results": {"pytest": {...}, "semgrep": {...}},
    "response_headers": {...},
    "scan_logged": False,
}
```

### Phase 3 — Multi-agent orchestration (29–70%)

`run_orchestration(ctx)` creates `ScanState` with 18 controls from `control_extractor.py`.

**First iteration** — agents run in fixed order:

| Order | Agent | Progress range | Checks executed |
|-------|-------|----------------|-----------------|
| 1 | Rhea (metrics) | 30–40% | TC-*, CF-*, LM-04 |
| 2 | Columbo (dast) | 40–58% | AC-*, SI-*, WC-*, TC-* (not already run) |
| 3 | Izzy (runtime) | 58–64% | TC-04, LM-01 … LM-04 |
| 4 | Mike (standards) | 64–68% | Standards corpus mapping (no new checks) |
| 5 | Judy (judge) | 68–70% | Score all controls, build verdicts |

**Reinvestigation loop** (up to `MAX_ITERATIONS=3`):

- If Judge score < 0.7 **and** reinvestigation requests exist, weak checks re-run.
- Judge runs again until score ≥ 0.7, no requests, or max iterations.

### Phase 4 — Disclosure evaluation (72–74%)

`evaluate_disclosure_gaps(state)` checks CSRF, privacy routes, rate limiting, headers, rejected-transfer logging against `disclosure_rules.json`.

### Phase 5 — Persistence (75–82%)

- Failed/partial checks logged to `logs/compliance_events.jsonl`
- Full scan state saved to `compliance_scans`
- Per-control verdicts saved to `compliance_control_verdicts`

### Phase 6 — LLM report (82–99%)

- `generate_report()` builds deterministic markdown skeleton + OpenAI JSON narrative
- Report saved to `compliance_reports` and `reports/compliance_YYYYMMDD_HHMMSS.md`
- `COMPLIANCE_SCAN_COMPLETED` audit event logged

### Phase 7 — Investigation JSON (97–100%)

- `build_investigation_from_state()` assembles pipeline, agent reasoning, evidence chains
- Stored in `compliance_scans.investigation_json` for post-scan viewing

---

## 5. Agents — Roles, Interactions, and Responsibilities

### 5.1 Agent interaction flow

```
Orchestrator
    │
    ▼
Signal Collector ──ctx──▶ Rhea (Metrics)
                              │
                              ▼
                         Columbo (DAST)
                              │
                              ▼
                         Izzy (Runtime)
                              │
                              ▼
                         Mike (Standards)
                              │
                              ▼
                         Judy (Judge) ──reinvestigation──▶ DAST/Metrics (optional loop)
                              │
                              ▼
                    Disclosure Evaluator
                              │
                              ▼
                    Report Generator (LLM)
```

**Shared state:** All agents read/write the same `ScanState` object and shared `ctx` dict. Checks accumulate in `state.check_results` without duplication (agents skip already-run check IDs).

### 5.2 Orchestrator (`system`)

**File:** `compliance/orchestrator.py`, `compliance/scan_service.py`

**Does:**
- Creates `ScanState` with scan ID timestamp
- Loads 18 controls and builds routing plan (which agent owns which control)
- Sequences specialist agents
- Invokes Judge after each iteration
- Breaks reinvestigation loop when evidence sufficient

**Does not:** Run checks itself — delegates to agents.

### 5.3 Rhea · Metrics Agent (`metrics`)

**File:** `compliance/agents/metrics.py`

**Assigned checks:**

```
TC-01, TC-02, TC-03, TC-04, TC-05, CF-01, CF-02, CF-03, CF-04, LM-04
```

**Does:**
1. Calls `run_checks(ctx, metrics_check_ids)`
2. Computes full KPI snapshot via `calculate_kpis()`
3. Stores KPI count in `state.tool_results["metrics"]`

**Interaction with app:**
- Static reads of `app.py` (imports, secrets, debug flags)
- Subprocess execution of `test_transfer_security.py` (TC-02, TC-03)
- HTTP header comparison (CF-03) using headers from collector
- Scan pipeline flag check (LM-04)

**Why separate from DAST:** Configuration and transfer *design* checks (code structure, module wiring) vs. runtime HTTP attack simulation.

### 5.4 Columbo · DAST Agent (`dast`)

**File:** `compliance/agents/dast.py`

**Assigned checks:**

```
AC-01 … AC-05, SI-01 … SI-03, WC-01 … WC-03, TC-* (any not yet run by metrics)
```

**Does:**
1. Runs remaining dynamic checks via Flask test client
2. Attaches pytest and Semgrep results from collector to `state.tool_results`
3. Records count of DAST checks run

**Interaction with app:**
- `get_test_client()` imports real `app` and sets `TESTING=True`
- Simulates login, form POST tampering, IDOR URLs, SQL injection query strings
- Inspects HTTP status codes and response body content
- No external network — in-process WSGI simulation

**Attack scenarios simulated:**

| Check | Attack |
|-------|--------|
| AC-01 | POST `role=admin` on `/profile` |
| AC-02 | Customer GET `/admin` |
| AC-03 | Customer GET `/employee-portal` |
| AC-04 | GET `/dashboard?user_id=2` as user 1 |
| SI-02 | GET `/statements?user_id=1 OR 1=1` |
| WC-01 | Search HTML for CSRF hidden fields |
| WC-02 | Six failed login POSTs, watch for 429 |

### 5.5 Izzy · Runtime Agent (`runtime`)

**File:** `compliance/agents/runtime.py`

**Assigned checks:**

```
TC-04, LM-01, LM-02, LM-03, LM-04
```

**Does:**
1. Runs logging and DB runtime checks
2. Re-queries `rejected_transfers` count for runtime summary
3. Stores audit event counts in `state.tool_results["runtime"]`

**Interaction with app:**
- Direct SQLite queries on `aria_bank.db` (production database path)
- Filesystem check for `logs/compliance_events.jsonl`
- Validates audit log row completeness (IP, severity fields)

**Note:** LM-04 checks whether scan completion was logged (`ctx["scan_logged"]`), set true after report generation.

### 5.6 Mike · Standards Agent (`standards`)

**File:** `compliance/agents/standards.py`

**Does not run security checks.** Instead:

1. Loads `compliance/data/standards_corpus.json`
2. For each control F-01 … F-18, matches keywords and finding IDs to corpus chunks
3. Produces up to 3 excerpt strings per control in `state.standards_mappings`

**Purpose:** Attach OWASP / ISO 27001 / NIST / GDPR textual references to verdicts for auditor-readable reports.

**Example output shape:**

```python
state.standards_mappings["F-05"] = [
    "OWASP A01 Broken Access Control: ...",
    "NIST AC-3 Access Enforcement: ...",
]
```

### 5.7 Judy · Judge Agent (`judge`)

**File:** `compliance/agents/judge.py`, `compliance/scoring.py`

**Does:**
1. `score_state()` — overall compliance score from all controls
2. `score_control()` per F-xx — sufficiency, consistency, quality, completeness dimensions
3. `build_verdicts()` — Compliant / Non-Compliant / Insufficient Evidence
4. `_reinvestigation_requests()` — identifies weak/not_tested checks for optional re-run

**Verdict rules:**

| Condition | Verdict |
|-----------|---------|
| Any related check `fail` | Non-Compliant |
| All related checks `pass` | Compliant |
| Score ≥ 0.7 | Compliant |
| Score 0.4–0.7 or not_tested with low score | Insufficient Evidence |
| Score < 0.4 | Non-Compliant |

**Verdict TTL:** 7 days (`VERDICT_TTL_DAYS`) — expired verdicts surfaced on dashboard.

**Reinvestigation triggers:**
- Control has `not_tested` checks (e.g. TC-05)
- High/critical priority control with `partial` checks and judge score < 0.7

### 5.8 Disclosure Evaluator (`disclosure`)

**File:** `compliance/disclosure.py`

**Runs after Judge.** Evaluates `disclosure_rules.json`:

| Rule ID | What it checks |
|---------|----------------|
| DG-CSRF | WC-01 must pass |
| DG-PRIVACY | Routes `/privacy/*` must exist |
| DG-RATE-LIMIT | WC-02 must pass |
| DG-HEADERS | CF-03 must pass |
| DG-REJECTED-LOG | TC-04 must pass |

Uses Flask test client to probe missing privacy routes (404 = gap).

### 5.9 Report Generator (`reporter`)

**File:** `compliance/llm_reporter.py`, `compliance/report_builder.py`

**Does:**
1. Builds deterministic professional markdown report (tables, verdicts, check matrix)
2. Calls OpenAI with scan state JSON (requires `OPENAI_API_KEY`)
3. Merges LLM executive summary, recommendations, finding impacts
4. Saves HTML + markdown to DB and filesystem

**Important:** LLM cannot override check results — prompt enforces consistency with deterministic verdicts.

---

## 6. Signal Collector (Pre-Agent Phase)

**File:** `compliance/collector.py`

The Collector is not a “mock agent” — it performs real work before specialists run.

### 6.1 Audit summary (7-day window)

SQL on `audit_logs`:

- Total events in window
- Failed login count
- **Failed login completeness %** — rows with both `ip_address` and `severity`
- **Critical action completeness %** — TRANSFER, UNAUTHORIZED_ACCESS_ATTEMPT, etc.
- Unauthorized access attempt count (all time)

Feeds **KPI-08**, **KPI-09**, and runtime agent context.

### 6.2 Transfer summary

- Counts rows in `rejected_transfers` grouped by `reason_code`
- Detects missing table (pre-remediation state)

### 6.3 Baseline test subprocesses

| Script | Purpose | Pass condition |
|--------|---------|--------------|
| `test_transfer_security.py` | Idempotency + self-transfer | Exit code 0 |
| `smoke_tests.py` | Full app smoke (customer + admin flows) | Exit code 0 |

Results feed **KPI-14** (automated test pass rate).

### 6.4 Semgrep (optional)

```bash
semgrep scan --config p/owasp-top-ten app.py
```

If not installed: `{"available": false, "reason": "semgrep not installed"}` — scan continues.

### 6.5 HTTP header probe

```python
urlopen(Request("http://127.0.0.1:5000/", method="GET"), timeout=3)
```

If app not running: empty headers dict — CF-03/WC-03 may score poorly.

---

## 7. The 24 Security Checks — Full Catalog

Each check returns:

```python
CheckResult(
    check_id="AC-01",
    status="pass|fail|partial|not_tested",
    evidence="human-readable summary",
    finding_ids=["F-05", "GAP-03"],
    standards=["OWASP A01", "NIST AC-3"],
    source_weight=0.95,  # evidence quality weight for Judge
    agent="dast",
    evidence_detail={... structured evidence ...}
)
```

### 7.1 Transfer checks (TC)

| ID | Name | Agent | Method | Pass condition |
|----|------|-------|--------|----------------|
| **TC-01** | Transfer service integration | metrics | Static import analysis + file existence | `app.py` imports `transfer_service`; file exists |
| **TC-02** | Transfer idempotency test | metrics/dast | Subprocess `test_transfer_security.py` | Exit 0; output mentions idempotent |
| **TC-03** | Self-transfer rejection | metrics/dast | Subprocess single test function + DB count | Test passes; `SELF_TRANSFER` rows queryable |
| **TC-04** | Rejected transfer logging | runtime | SQLite schema query | `rejected_transfers` table exists |
| **TC-05** | Concurrent transfer race | dast | **Not automated** | `not_tested` — Burp/manual deferred |

### 7.2 Access control checks (AC)

| ID | Name | Method | Pass condition |
|----|------|--------|----------------|
| **AC-01** | Profile role tampering | Flask test client POST | Role unchanged after `role=admin` tamper |
| **AC-02** | Customer blocked from admin | GET `/admin` | HTTP 403 |
| **AC-03** | Customer blocked from employee portal | GET `/employee-portal` | HTTP 403 |
| **AC-04** | Dashboard IDOR | GET `/dashboard?user_id=2` | Different body or denied vs own dashboard |
| **AC-05** | Admin role management route | Static source analysis | `/admin/users` route + parameterized `role = ?` |

### 7.3 SQL injection checks (SI)

| ID | Name | Method | Pass condition |
|----|------|--------|----------------|
| **SI-01** | Unsafe SQL in source | Regex on `app.py` | No f-string / `.format()` SQL patterns |
| **SI-02** | Statements SQL injection probe | HTTP GET with `1 OR 1=1` | Injection response not significantly larger |
| **SI-03** | Transaction search parameterization | Static analysis | `LIKE ?` parameterized pattern found |

### 7.4 Configuration checks (CF)

| ID | Name | Method | Pass condition |
|----|------|--------|----------------|
| **CF-01** | Hardcoded secret key | String search in `app.py` | No hardcoded SECRET_KEY literal |
| **CF-02** | Debug mode enabled | String search | No `debug=True` |
| **CF-03** | HTTP security headers | Live response headers | ≥3 of REQUIRED_HEADERS present |
| **CF-04** | Production server configuration | Source read | No dev `app.run()` or `run_server.py` exists |

### 7.5 Web security checks (WC)

| ID | Name | Method | Pass condition |
|----|------|--------|----------------|
| **WC-01** | CSRF token on forms | HTML inspection | "csrf" in `/transfer`, `/profile`, `/login` |
| **WC-02** | Login rate limiting | 6 failed POSTs | HTTP 429 observed |
| **WC-03** | Content-Security-Policy header | Response headers | CSP header present |

### 7.6 Logging & monitoring checks (LM)

| ID | Name | Method | Pass condition |
|----|------|--------|----------------|
| **LM-01** | Failed login log completeness | SQL on `audit_logs` | ≥80% rows have IP + severity |
| **LM-02** | Unauthorized access logging | SQL COUNT | Events exist (informational) |
| **LM-03** | Structured compliance event log | Filesystem | `logs/compliance_events.jsonl` exists |
| **LM-04** | Scan completion audit event | Context flag | `COMPLIANCE_SCAN_COMPLETED` logged |

---

## 8. How Checks Interact With the Real Application

### 8.1 Three interaction modes

| Mode | Description | Examples |
|------|-------------|----------|
| **Static analysis** | Read source files as text | TC-01, CF-01, SI-01, AC-05 |
| **In-process HTTP (Flask test client)** | Real app routes, simulated HTTP | AC-01–04, SI-02, WC-01/02 |
| **Direct database / filesystem** | Query `aria_bank.db`, check log files | TC-04, LM-01/02/03 |
| **Subprocess helper scripts** | Run project test files | TC-02, TC-03, collector pytest |
| **Live HTTP (optional)** | TCP request to running server | CF-03, WC-03 headers via collector |

### 8.2 Flask test client adapter

```python
# compliance/flask_adapter.py
from app import app
app.config.update(TESTING=True)
return app.test_client()
```

This imports the **production application module** — same routes, same `transfer_service`, same auth decorators. It is not a mock app.

### 8.3 What is NOT tested

- External network penetration (no ZAP/Nikto wired yet — planned)
- Production HTTPS deployment configuration
- Real concurrent race under load (TC-05 deferred)
- Customer data in live DB during transfer security tests (helper scripts reset DB)

---

## 9. Evidence Model and Internal Execution Traces

### 9.1 Structured evidence (`evidence_detail`)

Built by `compliance/evidence.py` → `build_evidence()` and enriched by `compliance/check_enricher.py`:

| Field | Meaning |
|-------|---------|
| `test_name` | Human-readable check name |
| `method` | How the check was executed |
| `observation` | What was found |
| `location` / `file` / `line` | Where in codebase or route |
| `snippet` | Source code excerpt |
| `tool` | Tool used (Source code review, pytest subprocess, etc.) |
| `request_detail` | HTTP request description |
| `result_detail` | Machine-readable result |
| `execution_trace` | Step-by-step internal trace |

### 9.2 Execution traces

**File:** `compliance/execution_trace.py`

After each check runs, `attach_execution_trace()` adds 3–6 steps documenting:

- Files read
- Commands executed (literal Python/code strings)
- Outputs observed
- Verdict reasoning

**Example TC-01 trace steps:**

1. Read `app.py` (byte count, line count)
2. Substring search for import patterns
3. `find_line_number()` for `transfer_service`
4. `Path.exists()` for `transfer_service.py`
5. Record snippet
6. Determine pass/fail

Displayed in Investigation UI under **"Internal execution trace"** with expandable `<details>` per agent step.

### 9.3 Investigation reasoning model

**File:** `compliance/investigation.py`

Each agent gets **reasoning steps** with:

- **Why** — purpose of this step
- **What I did** — actions taken
- **Conclusion** — outcome

Verdict steps parse markdown evidence into structured `evidence_blocks` (not raw JSON dumps).

---

## 10. Judge Agent — Scoring and Verdicts

### 10.1 Per-check score contribution

```python
pass       → full source_weight
partial    → source_weight × 0.5
not_tested → source_weight × 0.25
fail       → 0.0
```

### 10.2 Per-control dimensions

| Dimension | Weight | Meaning |
|-----------|--------|---------|
| Sufficiency | 30% | Average check pass rate |
| Consistency | 25% | All checks agree vs mixed |
| Quality | 25% | Average source_weight |
| Completeness | 20% | Fraction not `not_tested` |

### 10.3 Source weights

| Source type | Weight |
|-------------|--------|
| pytest | 0.95 |
| semgrep | 0.90 |
| audit | 0.85 |
| static | 0.80 |
| llm | 0.50 |

### 10.4 Evidence chain

Each verdict includes formatted markdown evidence strings plus structured `evidence_items` for UI rendering — one block per related check.

---

## 11. Standards Mapping (Mike)

**Input:** `compliance/data/standards_corpus.json` — chunks with `framework`, `topic`, `text`, `keywords`, `finding_ids`.

**Algorithm:**
1. Extract keywords from control title + claim + standard refs
2. Match chunks by finding ID or keyword overlap (length > 3)
3. Keep top 3 excerpts per control

**Output:** Attached to verdict `standards` field in reports and Findings tab.

---

## 12. KPI Engine (15 Metrics)

**File:** `compliance/kpi_calculator.py`  
**Baselines:** `compliance/data/kpi_baselines.json`

| KPI | Description | Primary source |
|-----|-------------|----------------|
| KPI-01 | Total open vulnerabilities (non-compliant controls) | Control + check mapping |
| KPI-02 | Critical & high severity open | Priority filter on controls |
| KPI-03 | Access control failures | AC-* failed checks |
| KPI-04 | Authentication failures | WC-02, CF-01, F-01/F-02 |
| KPI-05 | Injection-prone features | SI-* failures |
| KPI-06 | CSRF failures | WC-01 |
| KPI-07 | IDOR failures | AC-04 |
| KPI-08 | Critical audit action completeness % | Collector audit summary |
| KPI-09 | Failed login log completeness % | Collector audit summary |
| KPI-10 | Privacy routes implemented | Count of PRIVACY_ROUTES not 404 |
| KPI-11 | Security headers present | Header count vs REQUIRED_HEADERS |
| KPI-12 | Session cookie flags | Flask app.config heuristics |
| KPI-13 | Mean remediation days | `remediation_tracking.json` |
| KPI-14 | Automated test pass rate | smoke + transfer tests |
| KPI-15 | Overall compliance score | Average framework scores |

**Framework scores:** OWASP, ISO, NIST, GDPR percentages derived from check standards tags.

---

## 13. Controls Register (F-01 … F-18)

**File:** `compliance/control_extractor.py`

Each control links findings → checks → agents:

```python
ControlDefinition(
    id="F-05",
    title="Profile role tampering",
    risk="Critical",
    claim="Profile route must ignore role parameter",
    standard_refs=["OWASP A01", "NIST AC-3"],
    gap_ids=["GAP-03"],
    check_ids=["AC-01", "AC-05"],
    assigned_agents=["dast"],
    priority="critical",
)
```

Full mapping (18 controls):

| Control | Risk | Checks | Agents |
|---------|------|--------|--------|
| F-01 Weak passwords | High | CF-01 | metrics |
| F-02 No MFA/lockout | High | WC-02 | dast, runtime |
| F-03 Dashboard IDOR | High | AC-04 | dast |
| F-04 Transaction IDOR | High | AC-04 | dast |
| F-05 Profile role tampering | Critical | AC-01, AC-05 | dast |
| F-06 Employee portal access | High | AC-03 | dast |
| F-07 Admin dashboard access | High | AC-02 | dast |
| F-08 Missing CSRF | Medium | WC-01 | dast |
| F-09 Unsafe SQL statements | High | SI-01, SI-02 | dast, metrics |
| F-10 Unsafe SQL search | Medium | SI-01, SI-03 | dast |
| F-11 Unsafe logging | Medium | LM-01 | runtime |
| F-12 Weak document upload | Medium | WC-01 | dast |
| F-13 Excessive data exposure | High | AC-04 | dast |
| F-14 Incomplete audit logging | Medium | LM-01, LM-02 | runtime |
| F-15 Missing secure headers | Medium | CF-03, WC-03 | dast |
| F-16 Weak session/secret mgmt | Medium | CF-01, CF-02 | metrics |
| F-17 Missing privacy workflows | High | KPI-10 | metrics |
| F-18 Weak transaction design | Medium | TC-01…TC-05 | metrics, dast, runtime |

---

## 14. Disclosure Evaluator

**Purpose:** Bridge security checks → policy/disclosure gaps visible to compliance officers.

**Rules file:** `compliance/data/disclosure_rules.json`

Combines:
- Check result status (fail/partial/not_tested → open gap)
- Route existence probes (privacy workflows)

Output: `state.disclosure_gaps[]` saved in report and shown on dashboard.

---

## 15. LLM Report Generator (Reporter)

### 15.1 Two-layer report

1. **Deterministic layer** (`report_builder.py`) — tables, KPIs, verdict matrix, check listing
2. **LLM layer** (`llm_reporter.py`) — executive summary, risk narrative, top 5 recommendations, per-finding impact paragraphs

### 15.2 OpenAI integration

- Model: `OPENAI_MODEL` env (default `gpt-4-turbo`)
- Response format: JSON object
- Max input: ~14,000 chars of scan state
- **Requires** `OPENAI_API_KEY` — scan fails at report step without it (checks still run)

### 15.3 Output artifacts

| Artifact | Location |
|----------|----------|
| Markdown report | `reports/compliance_YYYYMMDD_HHMMSS.md` |
| DB record | `compliance_reports.report_markdown`, `report_html` |
| Executive summary | `compliance_reports.executive_summary` |

---

## 16. Investigation Workspace UI

**Route:** `/admin/compliance/investigation` and `/admin/compliance/investigation/<scan_id>`

**Template:** `templates/admin_compliance_investigation.html`  
**Styles:** `static/css/styles.css` (`.exec-trace-*`, pipeline nodes, reasoning cards)

### 16.1 Features

| Feature | Description |
|---------|-------------|
| Visual agent pipeline | 9 nodes with idle/running/done colors |
| Clickable agents | Select agent → detail panel with checks and reasoning |
| Live scan mode | Poll `/run/status/<job_id>` with progress bar + ETA |
| Agent reasoning cards | Why / What I did / Conclusion per step |
| Expandable evidence | `<details>` per step — preserves open state during polling |
| Internal execution trace | Step-by-step code/actions/outputs per check |
| Evidence chain | Cross-agent linked evidence for audit trail |
| Key outputs | Formatted stats (not raw JSON) |
| Scan history | Dropdown of last 15 scans |

### 16.2 Navigation

Sub-nav in `templates/compliance_nav.html`:

```
Dashboard | Investigation | Findings | Reports
```

Run Scan button lives on Investigation tab; dashboard links to "Open Investigation".

### 16.3 Live polling fix

`expandedKeys` Set + `syncExpandedFromDom()` prevents expandable sections from collapsing on each poll during active scans.

---

## 17. Database Schema and Persistence

**File:** `compliance/repository.py`

### 17.1 Tables

**`compliance_scans`**
- Scan metadata, KPI snapshot JSON, check results JSON, tool results
- Framework scores (OWASP, ISO, NIST, GDPR)
- `shared_state` — full ScanState JSON
- `investigation_json` — Investigation workspace payload
- `iteration_count`, `findings_open`, `findings_resolved`

**`compliance_control_verdicts`**
- Per control per scan: verdict, score, evidence JSON, expiry timestamp

**`compliance_reports`**
- Markdown, HTML, LLM sections, verdicts, disclosure gaps
- `human_reviewed` flag + reviewer tracking

### 17.2 Structured logging

**File:** `compliance/structured_log.py`

Append-only JSON Lines: `logs/compliance_events.jsonl`

Events: `compliance_check_failed`, `COMPLIANCE_SCAN_COMPLETED`

---

## 18. HTTP API and Admin Routes

**Blueprint:** `compliance_bp` at `/admin/compliance`

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Dashboard — KPIs, history, expired verdicts |
| `/investigation` | GET | Investigation workspace (latest or empty) |
| `/investigation/<scan_id>` | GET | Investigation for specific scan |
| `/investigation/data/<scan_id>` | GET | JSON API for investigation payload |
| `/findings` | GET | Control verdicts with evidence |
| `/reports` | GET | Report list |
| `/reports/<id>` | GET | Report detail with HTML render |
| `/run/start` | POST | Start background scan job |
| `/run/status/<job_id>` | GET | Poll progress + live investigation |
| `/run` | POST | Legacy sync scan |
| `/reports/<id>/review` | POST | Mark human reviewed |

All routes require `admin` role — unauthorized access logged as `UNAUTHORIZED_ACCESS_ATTEMPT`.

---

## 19. Helper Scripts (`test_transfer_security.py`, `smoke_tests.py`)

These are **real security regression tests**, not mock data generators.

### 19.1 `test_transfer_security.py`

**Why created:** Week 5 transfer remediation (GAP-01 idempotency, GAP-02 self-transfer) requires behavioural proof.

**Test 1 — `test_self_transfer_rejected`:**
1. Deletes and recreates `aria_bank.db`
2. Login as john@aria.local
3. POST transfer to self
4. Assert error message + `rejected_transfers.reason_code = 'SELF_TRANSFER'`

**Test 2 — `test_idempotent_replay`:**
1. Fresh DB
2. POST same transfer twice with same idempotency key
3. Assert second response says already completed
4. Assert only one transaction row

**Used by:** Collector (both tests), TC-02 (full file), TC-03 (test 1 only)

### 19.2 `smoke_tests.py`

**Why created:** End-to-end regression — verify all major routes work and RBAC holds.

**Coverage:**
- Public pages (/, login, register)
- Customer routes + forbidden admin/employee-portal
- Real transfer, support ticket, document upload
- Privacy routes must 404 (intentionally removed)
- Admin full route tour
- Customer blocked from compliance admin UI

**Used by:** Collector only (feeds KPI-14)

---

## 20. Source File Map

```
compliance/
├── __init__.py
├── __main__.py              # CLI entry: python -m compliance
├── config.py                # Paths, API keys, headers, KPI baselines
├── scan_service.py          # run_scan() — main entry
├── collector.py             # Signal collection
├── orchestrator.py          # Agent sequencing + reinvestigation
├── checks.py                # 24 check implementations
├── check_enricher.py        # Evidence enrichment
├── execution_trace.py       # Per-check internal traces
├── evidence.py              # build_evidence, find_line_number
├── flask_adapter.py         # get_test_client()
├── investigation.py         # Investigation JSON builder
├── scan_progress.py         # Live job tracker
├── repository.py            # SQLite CRUD
├── routes.py                # Admin blueprint
├── scoring.py               # Judge scoring logic
├── state.py                 # ScanState, CheckResult, Verdict dataclasses
├── kpi_calculator.py        # KPI-01 … KPI-15
├── llm_reporter.py          # OpenAI report generation
├── report_builder.py        # Deterministic report skeleton
├── disclosure.py            # Disclosure gap evaluator
├── structured_log.py        # JSON Lines compliance log
├── metadata.py              # Catalogs, verdict help text
├── control_extractor.py     # F-01 … F-18 registry
├── run_scan.py              # CLI wrapper
├── agents/
│   ├── base.py
│   ├── metrics.py           # Rhea
│   ├── dast.py              # Columbo
│   ├── runtime.py           # Izzy
│   ├── standards.py         # Mike
│   └── judge.py             # Judy
└── data/
    ├── check_catalog.json
    ├── controls.json
    ├── disclosure_rules.json
    ├── kpi_baselines.json
    ├── standards_corpus.json
    └── remediation_tracking.json

templates/
├── compliance_nav.html
├── admin_compliance.html
├── admin_compliance_investigation.html
├── admin_compliance_findings.html
├── admin_compliance_reports.html
└── admin_compliance_report_detail.html

test_transfer_security.py    # Transfer security regression tests
smoke_tests.py               # Application smoke tests
tests/test_compliance_*.py   # Unit tests for compliance module (CI)
```

---

## 21. Business Value — How This Helps ARIA Bank

### 21.1 Closes the Week 2 → Week 7 loop

| Week | Question | Milestone 7 answer |
|------|----------|-------------------|
| Week 2 | What is wrong? | F-01 … F-18 register |
| Week 3 | How do we measure? | KPI-01 … KPI-15 |
| Week 4 | What gaps exist? | GAP-01 … GAP-05 + evidence |
| Week 5 | How do we fix? | Remediation + retest matrix |
| **Week 7** | **Are fixes still working?** | **Automated continuous verification** |

### 21.2 Operational benefits

1. **Repeatable audits** — Same 24 checks every scan; comparable results over time
2. **Evidence for sign-off** — Investigation tab shows exactly how each control was verified
3. **Regression detection** — Failed smoke/transfer tests or Semgrep findings reopen controls
4. **Executive reporting** — LLM narrative + KPI dashboard for non-technical stakeholders
5. **Human review workflow** — Reports markable as reviewed; verdict expiry forces refresh
6. **Audit trail** — Structured logs + `COMPLIANCE_SCAN_COMPLETED` in `audit_logs`

### 21.3 Security verification examples

| Business risk | How the system verifies |
|---------------|-------------------------|
| Customer becomes admin | AC-01 tamper test on `/profile` |
| Customer accesses admin panel | AC-02 HTTP 403 check |
| Double-spend on transfer | TC-02 idempotency test |
| Self-transfer fraud | TC-03 rejection + DB row |
| SQL injection on statements | SI-02 live probe |
| Missing CSRF protection | WC-01 HTML token search |
| Brute force login | WC-02 rate limit check |
| Incomplete security logs | LM-01 SQL completeness ratio |

---

## 22. Known Limitations and Honest Scope

This system is a **working capstone CCM platform**, not a bank-regulator-certified production GRC tool.

| Limitation | Current state |
|------------|---------------|
| External DAST (ZAP/Nikto) | Planned in Milestone 7 doc; Semgrep only wired |
| TC-05 race condition | `not_tested` — manual Burp |
| Live HTTP headers | Requires Flask running on :5000 during scan |
| Transfer tests | `test_transfer_security.py` wipes `aria_bank.db` |
| LLM report | Requires OpenAI API key |
| Test client vs production traffic | In-process simulation, not real HTTPS users |
| Privacy routes | Intentionally 404 — tracked as disclosure gap DG-PRIVACY |

---

## Appendix A — Reinvestigation Loop Pseudocode

```python
state = ScanState(controls=load_controls())
iteration = 0

while iteration < MAX_ITERATIONS:
    if iteration == 0:
        for agent in [metrics, dast, runtime, standards]:
            agent.run(state, ctx)
    else:
        for request in state.reinvestigation_requests:
            rerun_checks(request.check_ids)
            AGENTS[request.requested_agent].run(state, ctx)

    judge_agent.run(state, ctx)
    iteration += 1

    if state.kpi_snapshot["judge_score"] >= 0.7:
        break
    if not state.reinvestigation_requests:
        break
```

---

## Appendix B — Check Run Pipeline (per check)

```python
result = CHECK_REGISTRY[check_id](ctx)           # Run check function
result = enrich_check_result(result, ctx)       # Add structured evidence
# enrich_check_result calls attach_execution_trace()
progress.record_check({...})                    # Live UI update
state.check_results.append(result)              # Accumulate in ScanState
```

---

## Appendix C — Running a Scan

**From admin UI:**
1. Login as admin@aria.local
2. Navigate to Admin → Compliance → Investigation
3. Click **Run Scan**
4. Watch live pipeline; results persist automatically

**From CLI:**
```bash
python -m compliance.run_scan
```

**Environment variables:**
```
OPENAI_API_KEY=sk-...          # Required for report generation
OPENAI_MODEL=gpt-4-turbo       # Optional
COMPLIANCE_SCAN_MAX_ITERATIONS=3
COMPLIANCE_APP_HOST=127.0.0.1
COMPLIANCE_APP_PORT=5000
```

---

*End of Milestone 7 Implementation Report*
