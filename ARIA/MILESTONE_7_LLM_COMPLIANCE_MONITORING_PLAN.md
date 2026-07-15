# Milestone 7: LLM Continuous Compliance Monitoring Plan
## ARIA Bank — Group 5 (CYT300 Capstone)

**Prepared for:** Milestone 7 — Integration of LLM for Continuous Compliance Monitoring  
**Application:** ARIA Bank Web Application  
**Group members:** Viktor Zaia, Yusuf Devrim Pasahan, Mohamed Soliman, Poonnawit Sukhowattanakit, Variya Chaimongkoltrakul  
**Status:** Planning document (builds on Weeks 2–5 deliverables)

---

## 1. Executive Summary

Milestones 1–6 established **what is wrong** with ARIA Bank and **how to fix it**. Milestone 7 closes the loop by building a **Continuous Compliance Monitoring (CCM) system** that:

1. Collects signals automatically from the app, database, tests, and scanners
2. Runs rule-based control checks against your existing findings register and KPI baseline
3. Uses a **Sibyl-inspired multi-agent orchestration** model — specialized agents verify controls, a Judge issues verdicts only when evidence is sufficient
4. Stores results for admin review, evidence chains, disclosure gaps, and before/after comparison

This plan is tailored to your prior work:

| Prior milestone | What we reuse in Milestone 7 |
|---|---|
| Week 2 Part 2 — Initial assessment | Findings register **F-01 to F-18**, LLM prompt workflow, standards mapping |
| Week 3 — KPI report | **KPI-01 to KPI-15** as automated metrics; compliance score baseline (OWASP 35%, ISO 40%, NIST 35%, GDPR 30%) |
| Week 4 — Gap analysis | **GAP-01 to GAP-05**, Burp/Semgrep/Nikto/ZAP/SonarQube evidence and retest matrix |
| Week 5 — Remediation plans | Transfer, access control, SQL injection, config hardening, web controls, SIEM vision, retesting sign-off criteria |

**Key shift from Week 2 → Milestone 7:**  
Week 2 used the LLM for a **one-time** policy-vs-practice analysis. Milestone 7 uses the LLM for **ongoing** assessment — comparing each scan cycle’s signals against your baseline and tracking KPI improvement after remediation (e.g., transfer security fixes).

---

## 2. Objective and Requirements Mapping

### Milestone 7 objective
Utilize LLM technology for ongoing compliance monitoring and reporting.

### How we meet it
| Requirement | Our approach |
|---|---|
| Develop or integrate LLM-based tools | Python `compliance/` module with orchestrated agents + `/admin/compliance` dashboard |
| Continually assess compliance | Scheduled or on-demand scans; KPI auto-calculation; specialist agents + Judge loop |
| Generate reports | LLM Judge generates verdicts, evidence chains, disclosure gaps; Markdown reports in DB + `reports/` |

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONTINUOUS COMPLIANCE LOOP                    │
└─────────────────────────────────────────────────────────────────┘

  [1] Signal Collection          [2] Rule-Based Checks
  ─────────────────────          ────────────────────────
  • audit_logs                   • Map to F-01..F-18
  • rejected_transfers           • Map to KPI-01..KPI-15
  • transactions (flagged)       • Map to GAP-01..GAP-05
  • users (auth checks)          • Pass / Fail / Partial
  • test results                 • Evidence references
  • Semgrep / ZAP output (opt.)
           │                              │
           └──────────┬───────────────────┘
                      ▼
              [3] LLM Analysis Layer
              ─────────────────────
              • Compare to Week 2 baseline
              • Detect new / resolved / unchanged findings
              • Draft executive summary + findings updates
              • Map to OWASP / ISO / NIST / GDPR
              • Human review required (from Week 2 guardrails)
                      │
                      ▼
              [4] Reporting & Dashboard
              ───────────────────────
              • compliance_reports table
              • /admin/compliance dashboard
              • KPI trend charts (before/after remediation)
              • Exportable Markdown/PDF for capstone submission
```

This directly addresses **GAP-05** (Week 4): *"Logging exists but does not prevent high-risk actions"* and Week 5 Section 3.1: *"Shifting from passive logging to active prevention"* — the monitor detects and reports; optional future phase adds auto-blocking.

Section 4 below adapts the **Sibyl** multi-agent orchestration model (proof-based verification, specialized investigators, Judge re-investigation loop) to ARIA Bank. The three-layer design in Section 3 remains the foundation; Section 4 describes how we implement it as orchestrated agents.

---

## 4. Sibyl-Inspired Multi-Agent Orchestration

### 4.1 Inspiration and Core Idea

**Reference project:** Sibyl — a multi-agent system that verifies sustainability report claims against real-world evidence (satellite imagery, legal standards, news, academic research, quantitative analysis). Its core thesis: *compliance should be a matter of proof, not trust.*

**Why this fits ARIA Bank:** Week 4 Burp testing showed the same pattern — the app *looked* compliant (audit logs, role labels) but failed under verification (race conditions, role tampering). Sibyl formalizes that approach: extract verifiable controls, route them to specialized evidence gatherers, and only issue verdicts when proof is sufficient.

| Sibyl principle | ARIA equivalent |
|---|---|
| Claims must be verified, not trusted | F-01–F-18 and KPI baselines are *claims*; Burp/ZAP/Semgrep/pytest are *proof* |
| Strategic omission matters | **Disclosure gaps** = controls never implemented (CSRF, privacy workflows, headers) |
| Multi-agent specialists in parallel | Route each control to the right evidence source (code scan vs live test vs audit log) |
| Orchestrator + shared state | One coordinator; all agents read/write a JSON scan state pool |
| Judge + re-investigation loop | If evidence is thin → request more tests before a verdict |
| Don't let LLM do math | KPI calculator + rule engine = Sibyl's deterministic metrics pattern |
| Continuous monitoring with expiry | Re-scan weekly; a pass from last month is not valid forever |

**Capstone pitch (Sibyl-style):**

> *Banking security compliance should be a matter of proof, not trust. ARIA Bank had audit logs and role labels, but Week 4 Burp testing showed controls that looked present but failed under verification. We built an orchestrated compliance monitor where specialized agents verify each control against live tests, scanner output, and audit data. A Judge agent only issues verdicts when evidence is sufficient, and re-opens investigations when it isn't. Verdicts expire and refresh on each scan cycle.*

### 4.2 ARIA Agent Orchestration Flow

Lightweight **5-agent model** (Sibyl uses 8 + LangGraph; we simplify for capstone scope):

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         INGESTION                                         │
│  Policies + Week 2–5 Reports + APP_SECURITY Reference + Live Signals     │
│  (DB, audit_logs, tests, Semgrep/ZAP output) + Standards RAG corpus       │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │  CONTROL EXTRACTOR (Menny)    │
                    │  Loads F-01..F-18 as          │
                    │  verifiable control objects     │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │  ORCHESTRATOR (Bron)          │
                    │  Routes each control to         │
                    │  the right specialist           │
                    └──────────────┬───────────────┘
                                   ▼
              ┌────────────────────────────────────────────┐
              │         SHARED SCAN STATE (Message Pool)    │
              │  controls[], findings[], routing_plan[],    │
              │  verdicts[], iteration_count,               │
              │  reinvestigation_requests[]                 │
              └────────────────────────────────────────────┘
                     │         │         │         │
         ┌───────────┘         │         │         └───────────┐
         ▼                     ▼         ▼                     ▼
  ┌─────────────┐    ┌─────────────┐ ┌─────────────┐  ┌─────────────┐
  │ STANDARDS   │    │ METRICS     │ │ DAST        │  │ RUNTIME     │
  │ (Mike)      │    │ (Rhea)      │ │ (Columbo)   │  │ (Izzy)      │
  │ OWASP/ISO/  │    │ KPI-01..15  │ │ Burp/ZAP/   │  │ audit_logs, │
  │ NIST/GDPR   │    │ TC/AC/SI    │ │ Semgrep/    │  │ rejected_   │
  │ via RAG     │    │ checks      │ │ pytest      │  │ transfers   │
  └──────┬──────┘    └──────┬──────┘ └──────┬──────┘  └──────┬──────┘
         │                  │               │                 │
         └──────────────────┴───────┬───────┴─────────────────┘
                                    ▼
                    ┌──────────────────────────────┐
                    │  JUDGE (Judy)                 │
                    │  Weighted verdict scoring       │
                    │  Compliant / Non-Compliant /    │
                    │  Insufficient Evidence          │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │  Evidence sufficient?          │
                    │  iteration < 3?                │
                    └──────────────┬───────────────┘
                          NO     │     YES
                    ┌────────────┴────────────┐
                    ▼                         ▼
         Re-investigation request      COMPLIANCE REPORT
         back to Orchestrator           + Disclosure Gaps
         (refined queries/tests)        + /admin/compliance
```

### 4.3 Sibyl → ARIA Agent Mapping

| Sibyl agent | ARIA role | Evidence source | Capstone priority |
|---|---|---|---|
| **Menny** (Claims Extractor) | **Control Extractor** | F-01..F-18, Week 5 remediation items, policy docs | P0 — high value |
| **Bron** (Orchestrator) | **Scan Orchestrator** | Routes controls to specialists via shared state | P0 |
| **Mike** (Legal / IFRS) | **Standards Mapper** | OWASP A01–A10, ISO themes, NIST AC/AU/SI, GDPR via RAG | P0 |
| **Rhea** (Data/Metrics) | **KPI & Rule Engine** | SQLite queries, pytest — **no LLM math** | P0 |
| **Columbo** (Geography/satellite) | **Dynamic Test Agent** | Burp replay, ZAP alerts, Nikto, route tests | P0 — adapt, not satellite |
| **Izzy** (News/Media) | **Runtime/Operations Agent** | `audit_logs`, `rejected_transfers`, failed logins | P1 |
| **Newton** (Academic) | **Best-Practices RAG** | OWASP guides, Week 2–5 report chunks | P2 — merge into Mike |
| **Judy** (Judge) | **Compliance Judge** | Weighted verdict + re-investigation if evidence weak | P0 |

**Columbo adaptation:** Sibyl verifies reforestation claims from space. ARIA verifies security controls from **repeatable tests** — the same Burp replays and ZAP scans from Week 4.

### 4.4 Mapping Three-Layer Design to Agents

| Original layer (Section 3) | Sibyl-inspired implementation |
|---|---|
| Layer 1 — Signal Collection | **Control Extractor** + **Runtime Agent (Izzy)** + ingestion pipeline |
| Layer 2 — Rule-Based Checks | **Metrics Agent (Rhea)** + **DAST Agent (Columbo)** — deterministic only |
| Layer 3 — LLM Analysis | **Standards Mapper (Mike)** + **Judge (Judy)** — LLM only after specialists run |

### 4.5 Control Extractor Pattern (Menny)

Do not ask one LLM *"are we compliant?"* Extract verifiable controls first:

```json
{
  "control_id": "F-05",
  "claim": "Customer profile route must not accept role changes",
  "standard_refs": ["OWASP A01", "NIST AC-3"],
  "verification_method": "route_test + code_inspection",
  "priority": "critical",
  "assigned_agent": "dast"
}
```

Controls load from F-01..F-18 JSON and Week 5 remediation plans — not LLM invention.

### 4.6 Orchestrator + Shared State (Bron)

Agents do not communicate peer-to-peer. All read/write the **shared scan state** (same concept as Sibyl's LangGraph message pool):

```json
{
  "scan_id": "2026-07-14T15:00:00Z",
  "controls": [],
  "findings": [],
  "routing_plan": [
    { "control_id": "F-05", "agent": "dast", "checks": ["AC-01"] }
  ],
  "verdicts": [],
  "iteration_count": 0,
  "reinvestigation_requests": []
}
```

Benefits: audit trail, replay capability, clear demo narrative, fault tolerance.

### 4.7 Specialist Responsibilities

| Specialist | Handles | Must be deterministic? |
|---|---|---|
| **Metrics (Rhea)** | KPI-01..15, TC/AC/SI/CF/WC/LM checks | **Yes** — code only |
| **DAST (Columbo)** | Semgrep, ZAP, pytest, Burp notes | **Yes** — tool output |
| **Runtime (Izzy)** | Audit log patterns, rejected transfers | **Mostly yes** — SQL queries |
| **Standards (Mike)** | Map controls to OWASP/ISO/NIST/GDPR text | LLM + RAG, grounded in corpus |
| **Judge (Judy)** | Synthesis + final verdict | LLM, only after specialists complete |

### 4.8 Judge with Re-Investigation Loop (Judy)

No premature verdicts. Adapt Sibyl's weighted scoring:

| Dimension | Weight | ARIA meaning |
|---|---|---|
| **Sufficiency** | 30% | Enough evidence? (test output, log sample, screenshot ref) |
| **Consistency** | 25% | Policy vs practice vs code agree? |
| **Quality** | 25% | Source weight: pytest (0.95) > Semgrep (0.90) > audit log (0.85) > LLM inference (0.50) |
| **Completeness** | 20% | All sub-requirements covered? (e.g. transfer: atomic + idempotency + logging) |

**Verdict taxonomy:**

| Verdict | Meaning |
|---|---|
| **Compliant** | Control verified with sufficient high-quality evidence |
| **Non-Compliant** | Control failed verification |
| **Insufficient Evidence** | Cannot conclude — trigger re-investigation |

If weighted score < 0.7 → Orchestrator receives a re-investigation request:

```json
{
  "control_id": "F-05",
  "gap": "No Burp replay evidence for profile role tamper",
  "refined_query": "Run AC-01 with role=admin in profile POST; capture audit log",
  "requested_agent": "dast"
}
```

**Max 3 iterations** per scan (same as Sibyl), then force verdict with `Insufficient Evidence` flag.

This directly addresses **GAP-05**: logging alone is not proof — the Judge demands multi-source evidence.

### 4.9 Disclosure Gaps Section (Omission Detection)

Sibyl surfaces what reports **never mention**. ARIA equivalent — dedicated report section separate from open findings:

| Missing disclosure | Finding | KPI |
|---|---|---|
| No CSRF on any form | F-08 | KPI-06 |
| No privacy export/deletion/consent/retention | F-17 | KPI-10 |
| No rate limiting on login | F-02 | KPI-04 |
| No rejected-transfer logging (pre-M6) | GAP-05 | F-18 |
| No security headers | F-15 | KPI-11 |

### 4.10 Evidence Chain (Per Verdict)

Every verdict includes a full evidence chain (Sibyl paragraph-level proof):

```
F-18 (Transfer integrity) → PARTIAL
  ├─ Rhea: TC-02 PASS — idempotency test (test_idempotent_replay)
  ├─ Rhea: TC-03 PASS — self-transfer blocked (SELF_TRANSFER logged)
  ├─ Columbo: TC-05 NOT TESTED — parallel race Burp replay pending
  └─ Izzy: rejected_transfers table — 12 rows this week
Verdict: PARTIAL — 2/5 transfer controls verified; race test pending
Judge score: 0.62 → re-investigation requested (iteration 1)
```

### 4.11 Hybrid RAG for Standards (Optional Enhancement)

Embed paragraph-level chunks of:

- OWASP Top 10 descriptions
- Week 2 findings register (F-01..F-18)
- Week 3 KPI definitions
- Week 5 remediation requirements

**Standards Mapper (Mike)** retrieves by control ID + semantic search instead of hallucinating clause numbers.

MVP options: SQLite + keyword search, or pgvector if time permits. Sibyl uses pgvector + ts_vector + reciprocal rank fusion — adopt simplified version for capstone.

### 4.12 Continuous Monitoring with Verdict Expiry

Sibyl: *"Verdicts should have an expiry date, not just an issue date."*

| Event | Monitor action |
|---|---|
| Transfer controls passed July 1 | Re-verify by July 8 (`verdict_expires_at`) |
| New `UNAUTHORIZED_ACCESS_ATTEMPT` in logs | Re-open F-05 / F-07 |
| Semgrep finds new f-string SQL | Regress F-09 to `Non-Compliant` |
| pytest failure after code change | Block Compliant verdict for affected controls |

Store `verdict_expires_at` and `last_verified_at` per control in `compliance_scans`.

### 4.13 Sibyl-Lite MVP (Recommended Implementation)

| Step | Component | LLM required? |
|---|---|---|
| 1 | **Control Extractor** — load F-01..F-18 as JSON | No |
| 2 | **Orchestrator** — assign each control to Metrics / DAST / Runtime / Standards | No |
| 3 | **Specialists run** — pytest, Semgrep, SQL on audit_logs, optional RAG | Mostly no |
| 4 | **Judge** — synthesize specialist outputs; flag insufficient evidence | Yes — one call |
| 5 | **Re-investigation** — if >3 controls lack evidence, run missing tests once more | No |
| 6 | **Report** — verdicts + disclosure gaps + KPI delta + evidence chains | Judge output |
| 7 | **Dashboard** — `/admin/compliance` with last scan, open verdicts, expired checks | No |

### 4.14 What We Adopt vs Skip

**Adopt from Sibyl:**

- Multi-agent specialization (orchestrator routes to domain experts)
- Shared state pool (not peer-to-peer agent chat)
- Extract controls first, then verify (not one giant prompt)
- Judge with re-investigation loop (max 3 cycles)
- Disclosure / omission detection section
- Deterministic tools before LLM (Metrics Agent = no LLM math)
- Evidence chains in every verdict
- Continuous re-verification with verdict expiry

**Skip or simplify for capstone:**

| Sibyl feature | ARIA approach |
|---|---|
| 8 agents + LangGraph | 4–5 logical roles in one Python module |
| Sentinel-2 / NDVI satellite | DAST / live tests (Burp, ZAP, pytest) |
| SSE Detective Dashboard with avatars | `/admin/compliance` scan status UI |
| Multiple LLM providers | GPT-4 Turbo (per project brief) |
| 100–200 page PDF ingestion | Smaller corpus: policies + 5 weekly reports |
| Portfolio-level multi-tenant | Single app: ARIA Bank |

---

## 5. Control Baseline (Imported from Prior Reports)

### 5.1 Findings Register (Week 2 Part 2) — Monitor Targets

The compliance monitor tracks status of each finding:

| ID | Finding | Risk | Monitor check type |
|---|---|---|---|
| F-01 | Weak passwords / plaintext storage | High | Code + DB query |
| F-02 | No MFA / lockout / throttling | High | Route + audit log analysis |
| F-03 | Dashboard IDOR | High | Automated route test |
| F-04 | Transaction history IDOR | High | Automated route test |
| F-05 | Profile role tampering | Critical | Route test + audit log |
| F-06 | Customer → employee portal | High | Role-based access test |
| F-07 | Customer → admin dashboard | High | Role-based access test |
| F-08 | Missing CSRF | Medium | Form inspection / ZAP |
| F-09 | Unsafe SQL — statements | High | Code scan + route test |
| F-10 | Unsafe SQL — transactions | Medium | Code scan + route test |
| F-11 | Unsafe logging of raw input | Medium | Code + log sample review |
| F-12 | Weak document upload | Medium | Route behavior check |
| F-13 | Excessive data exposure | High | Page content check |
| F-14 | Incomplete audit logging | Medium | Log completeness audit |
| F-15 | Missing secure headers | Medium | HTTP header check |
| F-16 | Weak session / secret mgmt | Medium | Config + cookie check |
| F-17 | Missing privacy workflows | High | Route existence check |
| F-18 | Weak transaction design | Medium | Transfer control check |

### 5.2 Gap Analysis IDs (Week 4)

| Gap | Description | Remediation status (M6) | Monitor verifies |
|---|---|---|---|
| GAP-01 | Transfer race condition | **Partially fixed** (`transfer_service.py`) | Idempotency + parallel test |
| GAP-02 | Self-transfer accepted | **Partially fixed** | Self-transfer rejection test |
| GAP-03 | User-controlled role in profile | Planned (Week 5) | Profile POST tamper test |
| GAP-04 | Customer-to-admin escalation | Planned (Week 5) | Admin route 403 test |
| GAP-05 | Passive logging only | **This milestone addresses** | Alert on high-severity events |

### 5.3 KPI Dashboard (Week 3) — Auto-Calculated Each Scan

| KPI | Baseline | Target | Auto-source |
|---|---|---|---|
| KPI-01 Total vulnerabilities | 18 | 0–3 | Findings register count |
| KPI-02 Critical/high findings | 10 | 0 | Risk-rated count |
| KPI-03 Access control violations | 6 | 0 | Route tests |
| KPI-04 Authentication weaknesses | 4 | 0 | Code + behavior checks |
| KPI-05 Injection-prone features | 2 | 0 | Semgrep + route tests |
| KPI-06 Missing CSRF | 8 forms | 0 | Form/token inspection |
| KPI-07 Sensitive data exposure | 6 | 0–1 | Page/route audit |
| KPI-08 Critical action logging | ~60% | ≥95% | Log field completeness |
| KPI-09 Failed login logging | Incomplete | 100% | Audit log query |
| KPI-10 Privacy workflows | 0/4 | 4/4 | Route existence |
| KPI-11 Secure headers | 0/5 | 5/5 | `curl -I` check |
| KPI-12 Session controls | 1/4 | 4/4 | Cookie inspection |
| KPI-13 Mean time to remediate | TBD | ≤7 days | Finding fix dates |
| KPI-14 Retest pass rate | TBD | ≥95% | Test suite results |
| KPI-15 Compliance score | 35–40% | ≥80% | Weighted KPI formula |

---

## 6. Three-Layer Monitoring Design

### Layer 1 — Automated Signal Collection

**Purpose:** Objective, repeatable data — no LLM guessing.

#### 6.1 Database signals (SQLite `aria_bank.db`)

```sql
-- Examples the collector should run each cycle
SELECT COUNT(*) FROM audit_logs WHERE event_type = 'LOGIN_FAILED';
SELECT COUNT(*) FROM audit_logs WHERE event_type = 'UNAUTHORIZED_ACCESS_ATTEMPT';
SELECT COUNT(*) FROM audit_logs WHERE severity = 'High';
SELECT COUNT(*) FROM rejected_transfers GROUP BY reason_code;
SELECT COUNT(*) FROM transactions WHERE flagged = 1;
SELECT COUNT(*) FROM users WHERE password NOT LIKE '$%';  -- plaintext indicator
```

#### 6.2 Application signals

| Signal | Source | Maps to |
|---|---|---|
| Failed logins (7-day window) | `audit_logs` | KPI-09, F-02 |
| Unauthorized access attempts | `audit_logs` | KPI-03, F-05–F-07 |
| Rejected transfers by reason | `rejected_transfers` | GAP-01/02, F-18 |
| Flagged transactions | `transactions` | F-18 |
| High-value transfers | Admin dashboard query | Operational risk |
| Admin actions | `ADMIN_*` event types | KPI-08 |

#### 6.3 External tool signals (from Week 4–5 retesting matrix)

| Tool | Command / action | Frequency | Maps to |
|---|---|---|---|
| Semgrep | `semgrep scan --config p/owasp-top-ten` | Weekly / on-demand | F-09, F-10, F-16 |
| OWASP ZAP | Baseline + active scan | Weekly / on-demand | F-08, F-15 |
| Nikto | `nikto -h http://127.0.0.1:5000` | Weekly / on-demand | F-15 |
| Burp Suite | Manual replay (transfer, profile) | After each remediation | GAP-01–04 |
| pytest | `test_transfer_security.py`, `smoke_tests.py` | Every scan | KPI-14, transfer fixes |

#### 6.4 Structured JSON snapshot (feeds LLM)

Each scan produces one JSON file:

```json
{
  "scan_id": "2026-07-14T15:00:00Z",
  "scan_type": "scheduled",
  "kpis": { "KPI-01": 18, "KPI-03": 6 },
  "audit_summary": { "failed_logins_7d": 12, "unauthorized_7d": 3 },
  "transfer_controls": { "idempotency_present": true, "rejected_transfers_7d": 5 },
  "findings_status": [
    { "id": "F-18", "status": "partial", "evidence": "transfer_service.py implemented" }
  ],
  "tool_results": {
    "semgrep_findings": 3,
    "zap_high_alerts": 4,
    "nikto_items": 4,
    "tests_passed": 2,
    "tests_failed": 0
  },
  "previous_scan_id": "2026-07-07T15:00:00Z"
}
```

---

### Layer 2 — Rule-Based Control Engine

**Purpose:** Deterministic pass/fail before LLM interpretation (Week 2 guardrail: *"Do not let LLM claim compliance without evidence"*).

#### 6.5 Control check catalog

Organized by your Week 5 remediation themes:

**A. Transfer integrity (Week 5 Section 1 — partially implemented)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| TC-01 | Atomic transfer service exists | `transfer_service.py` imported in `app.py` | F-18 |
| TC-02 | Idempotency key enforced | Duplicate POST returns replay message | GAP-01 |
| TC-03 | Self-transfer blocked | `SELF_TRANSFER` in rejected_transfers | GAP-02 |
| TC-04 | Rejected transfers logged | `rejected_transfers` table has rows | GAP-05 |
| TC-05 | Parallel race test | Burp/automated test — no negative balance | GAP-01 |

**B. Access control (Week 5 Section 2 — planned)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| AC-01 | Profile ignores role field | `role=admin` in profile POST → role unchanged | F-05, GAP-03 |
| AC-02 | Admin routes return 403 for customer | `/admin`, `/admin/users` → 403 | F-07, GAP-04 |
| AC-03 | Employee portal blocked for customer | `/employee-portal` → 403 | F-06 |
| AC-04 | IDOR on dashboard | `/dashboard?user_id=2` as user 1 → denied | F-03 |
| AC-05 | Admin-only role management | Role change only via `/admin/users` | F-05 |

**C. SQL injection (Week 5 SQL section — planned)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| SI-01 | No f-string SQL in app.py | Semgrep clean | F-09, F-10 |
| SI-02 | Statements OR 1=1 blocked | Parameterized query / type cast | F-09 |
| SI-03 | Search LIKE parameterized | Safe `?` placeholders | F-10 |

**D. Configuration & deployment (Week 5 Section 3 — planned)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| CF-01 | SECRET_KEY from env | No hardcoded secret in `app.py` | F-16 |
| CF-02 | Debug mode off | `FLASK_DEBUG=False` in prod | F-15 |
| CF-03 | Security headers present | X-Frame-Options, CSP, HSTS, etc. | F-15, KPI-11 |
| CF-04 | Production WSGI | Not `flask run` / Werkzeug in prod | Week 5 §3.1 |

**E. Web controls (Week 5 Section 2 — planned)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| WC-01 | CSRF on state-changing forms | Flask-WTF tokens present | F-08, KPI-06 |
| WC-02 | Rate limiting on /login | Flask-Limiter or equivalent | F-02 |
| WC-03 | CSP header set | Response includes CSP | F-15 |

**F. Logging & monitoring (Week 5 Section 3.2 — this milestone extends)**

| Check ID | Control | Pass condition | Finding |
|---|---|---|---|
| LM-01 | Failed login has IP + severity | Audit log field completeness | F-14, KPI-09 |
| LM-02 | Unauthorized attempts logged | `UNAUTHORIZED_ACCESS_ATTEMPT` events | GAP-05 |
| LM-03 | Structured JSON logs (optional) | SIEM-ready format | Week 5 §3.2 |
| LM-04 | Compliance scan logged | `COMPLIANCE_SCAN_COMPLETED` event | New |

Each check returns:

```json
{
  "check_id": "TC-02",
  "status": "pass|fail|partial|not_tested",
  "finding_ids": ["F-18", "GAP-01"],
  "evidence": "test_idempotent_replay passed 2026-07-14",
  "standards": ["OWASP A04", "ISO secure development", "NIST SI"]
}
```

---

### Layer 3 — LLM Analysis and Reporting

**Purpose:** Interpret signals, detect trends, draft human-readable reports.

#### 6.6 What changes from Week 2 LLM workflow

| Week 2 (one-time) | Milestone 7 (continuous) |
|---|---|
| Manual evidence upload | Automated JSON snapshot |
| "Compare policy to practice" | "Compare **this cycle** to **baseline + previous cycle**" |
| Single findings register | Trend: new / resolved / unchanged / regressed |
| Human writes final report | LLM drafts; team reviews and approves |

#### 6.7 LLM inputs (each scan)

1. **Control baseline** — F-01 to F-18 descriptions from Week 2 Part 2
2. **KPI targets** — from Week 3 dashboard
3. **Current JSON snapshot** — Layer 1 output
4. **Rule check results** — Layer 2 output
5. **Previous report summary** — for trend detection
6. **Remediation status** — Week 5 plans + what's implemented (transfer fix, etc.)
7. **Optional:** Semgrep/ZAP output excerpts (not full dumps)

#### 6.8 LLM outputs (each scan)

1. **Executive summary** (board-ready, similar tone to `TRANSFER_SECURITY_BOARD_REPORT.md`)
2. **KPI delta table** — baseline vs current vs target
3. **Findings register update** — status per F-01..F-18
4. **New or regressed issues** — anything worse than last scan
5. **Resolved issues** — with evidence (e.g., transfer idempotency now passing)
6. **Standards compliance narrative** — OWASP / ISO / NIST / GDPR per area
7. **Recommended next actions** — prioritized by risk
8. **Retest checklist** — items for next Burp/ZAP cycle (from Week 5 §5.1 matrix)

#### 6.9 Prompt template (extends Week 2 Part 2 §14)

```text
You are the continuous compliance monitoring analyst for ARIA Bank.

CONTEXT:
- This is scan {scan_id}. Previous scan: {previous_scan_id}.
- Baseline (Week 2): 18 findings, non-compliant overall.
- KPI baseline (Week 3): OWASP 35%, ISO 40%, NIST 35%, GDPR 30%.
- Transfer remediation (Week 5/M6): partially implemented.

INPUT DATA:
1. KPI snapshot: {kpi_json}
2. Rule check results: {checks_json}
3. Audit log summary: {audit_json}
4. Tool results: {tools_json}

TASKS:
1. Compare current KPIs to Week 3 baseline and targets.
2. For each finding F-01 to F-18, state: open | partial | resolved | regressed.
3. Identify changes since previous scan (if provided).
4. Map top 5 risks to OWASP, ISO 27001, NIST SP 800-53, GDPR.
5. Draft executive summary (150–250 words) for leadership.
6. List recommended next remediation priorities.
7. Flag any claim where evidence is insufficient — say "insufficient evidence".

RULES:
- Do not invent test results.
- Separate facts, inferences, and recommendations.
- Final compliance judgement requires human review.
- Reference check IDs and evidence strings from the JSON.

OUTPUT FORMAT: JSON with sections executive_summary, kpi_delta, findings_update,
risks, recommendations, insufficient_evidence_notes.
Then append a Markdown report suitable for capstone submission.
```

#### 6.10 Guardrails (from Week 2 + Week 5)

- LLM never auto-closes a finding — human sign-off required
- Rule engine must run first; LLM interprets, does not replace checks
- Every status change requires evidence reference (test ID, screenshot, scan output)
- Missing policy docs = governance gap (from Week 2 guide)
- Cache one sample report for demo if API unavailable

---

## 7. Implementation Plan

### Phase 1 — Core monitor + Sibyl-lite agents (MVP for capstone demo)

| # | Task | Owner | Files | Priority |
|---|---|---|---|---|
| 1 | Create `compliance/` module structure | TBD | `compliance/` package | P0 |
| 2 | **Control Extractor** — load F-01..F-18 as JSON controls | TBD | `compliance/control_extractor.py` | P0 |
| 3 | **Orchestrator** — route controls to specialists via shared state | TBD | `compliance/orchestrator.py` | P0 |
| 4 | **Metrics Agent (Rhea)** — KPI-01–15 + TC/AC/SI/CF/WC/LM checks | TBD | `compliance/agents/metrics.py`, `kpi_calculator.py` | P0 |
| 5 | **DAST Agent (Columbo)** — pytest, Semgrep, HTTP header checks | TBD | `compliance/agents/dast.py` | P0 |
| 6 | **Runtime Agent (Izzy)** — audit_logs, rejected_transfers queries | TBD | `compliance/agents/runtime.py`, `collector.py` | P0 |
| 7 | **Standards Mapper (Mike)** — RAG + OWASP/ISO/NIST/GDPR mapping | TBD | `compliance/agents/standards.py` | P1 |
| 8 | **Judge (Judy)** — weighted verdicts + re-investigation loop | TBD | `compliance/agents/judge.py`, `llm_reporter.py` | P0 |
| 9 | Add `compliance_scans` + `compliance_reports` DB tables | TBD | `app.py` init_db | P0 |
| 10 | CLI entry point: `python -m compliance.run_scan` | TBD | `compliance/run_scan.py` | P0 |
| 11 | Store reports in `reports/` as Markdown | TBD | `reports/compliance_YYYY-MM-DD.md` | P1 |

### Phase 2 — Admin dashboard (recommended for demo)

| # | Task | Route | Notes |
|---|---|---|---|
| 12 | Compliance dashboard | `/admin/compliance` | KPI cards, verdict summary, expired checks |
| 13 | Findings status view | `/admin/compliance/findings` | F-01..F-18 with verdict badges |
| 14 | Report history | `/admin/compliance/reports` | List + view Markdown + evidence chains |
| 15 | Run scan button | `POST /admin/compliance/run` | Admin-only trigger |
| 16 | Nav link in admin sidebar | `base.html` | Alongside audit logs |

> Note: `APP_SECURITY_AND_COMPLIANCE_REFERENCE.md` lists `/admin/compliance`, `/admin/findings`, and `/admin/compliance-checklist` as previously removed routes. Milestone 7 is the right time to restore them as the **LLM-powered compliance operations center**.

### Phase 3 — Integration with existing remediation (Week 5 → M6)

| Remediation area | Week 5 plan | Code status | Monitor behavior |
|---|---|---|---|
| Transfer security | Atomic, idempotency, self-transfer, rejected logging | `transfer_service.py` exists; integrate fully in `app.py` | TC-01–TC-05 should show **improvement** in first post-M6 scan |
| Access control | Profile role removal, admin decorators | Partial (`staff_or_admin_required` exists; profile still vulnerable) | AC-* likely still **fail** until M6 complete |
| SQL injection | Parameterized queries | Not yet fixed | SI-* still **fail** |
| Config hardening | Env secrets, headers, Gunicorn/Nginx | Not yet fixed | CF-* still **fail** |
| Web controls | CSRF, CSP, rate limiting | Not yet fixed | WC-* still **fail** |

**Demo narrative:** Run scan **before** and **after** transfer remediation → show KPI-15 score increase and F-18 moving from `open` to `partial`.

### Phase 4 — Scheduling (optional)

| Option | Implementation | Demo need |
|---|---|---|
| Manual | Admin clicks "Run Scan" | Sufficient for capstone |
| CLI cron | Windows Task Scheduler / cron weekly | Nice-to-have |
| Post-deploy hook | Run after `git push` in CI | Future |

---

## 8. Database Schema (New Tables)

```sql
CREATE TABLE compliance_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'manual',  -- manual | scheduled
    triggered_by INTEGER,
    kpi_snapshot TEXT NOT NULL,       -- JSON
    check_results TEXT NOT NULL,      -- JSON
    tool_results TEXT,                -- JSON
    compliance_score_owasp REAL,
    compliance_score_iso REAL,
    compliance_score_nist REAL,
    compliance_score_gdpr REAL,
    findings_open INTEGER,
    findings_resolved INTEGER,
    iteration_count INTEGER DEFAULT 0,
    shared_state TEXT,              -- JSON: full orchestrator state pool
    status TEXT NOT NULL DEFAULT 'completed',
    FOREIGN KEY (triggered_by) REFERENCES users (id)
);

CREATE TABLE compliance_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    report_markdown TEXT NOT NULL,
    verdicts_json TEXT,               -- Judge output: Compliant / Non-Compliant / Insufficient
    disclosure_gaps_json TEXT,        -- Omission detection (Section 4.9)
    llm_model TEXT,
    human_reviewed INTEGER NOT NULL DEFAULT 0,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES compliance_scans (id),
    FOREIGN KEY (reviewed_by) REFERENCES users (id)
);
```

Log each scan to audit_logs:

```
event_type: COMPLIANCE_SCAN_COMPLETED
severity: Low
description: Scan {id} completed. Score OWASP={x}%. {n} checks passed, {m} failed.
```

---

## 9. Retesting Integration (from Week 5 §5.1)

The compliance monitor should **ingest or trigger** the same tests from your Week 5 retesting matrix:

| Vulnerability | Tool | Pass condition | Auto in monitor? |
|---|---|---|---|
| Transfer race | Burp Repeater / pytest | No negative balance | Yes — `test_transfer_security.py` |
| Profile escalation | Burp Suite | Role unchanged | Manual Burp + route test |
| Missing headers | Nikto / ZAP / curl | Headers present | Yes — HTTP check |
| SQL injection | Semgrep + ZAP | No injection alerts | Yes — Semgrep subprocess |
| CSRF | ZAP | 400 on missing token | After WC-01 implemented |
| Idempotency | pytest | Second POST rejected | Yes — existing test |

**Sign-off criteria (Week 5 §5.2)** — monitor tracks progress toward:

1. Zero Critical/High open findings (KPI-02 = 0)
2. ZAP zero high-risk alerts on auth/session/transport/injection
3. Logging detects and reports suspicious behavior (LM-* passing)
4. No successful privilege escalation or unauthorized transfer manipulation

---

## 10. SIEM Vision (Week 5 §3.2 — Future Enhancement)

Week 5 proposed structured JSON logs + SIEM integration. Milestone 7 MVP can include:

```python
# Structured log format for compliance events
logger.info(json.dumps({
    "event": "compliance_check_failed",
    "check_id": "AC-02",
    "finding": "F-07",
    "severity": "high",
    "timestamp": "...",
    "user_id": null
}))
```

Optional Phase 2: export audit_logs + compliance_scans to a SIEM-compatible JSON Lines file.

Active blocking (`log_and_block_threat` from Week 5) remains **out of scope for MVP** but can be noted as a future control linked to LM-03.

---

## 11. Deliverables for Milestone 7 Report

| # | Deliverable | Description |
|---|---|---|
| 1 | Architecture diagram | Three-layer pipeline (Section 3) + agent orchestration flow (Section 4) |
| 2 | `compliance/` multi-agent module | Control Extractor, Orchestrator, specialists, Judge |
| 3 | Admin compliance dashboard | `/admin/compliance` (or CLI + report folder) |
| 4 | Sample compliance report | Judge-generated verdicts, evidence chains, disclosure gaps |
| 5 | KPI trend comparison | Week 3 baseline vs post-transfer-fix scan |
| 6 | Findings status table | F-01..F-18 with Compliant / Non-Compliant / Insufficient Evidence |
| 7 | Demo script | Live scan + Judge verdict walkthrough |
| 8 | LLM prompt documentation | Judge prompt + guardrails (Section 6.9–6.10) |

---

## 12. Demo Script (Capstone Presentation)

1. **Context** — Show Week 2 baseline: 18 findings, non-compliant, KPI dashboard from Week 3.
2. **Gap recap** — Brief Week 4 Burp evidence (GAP-01 race, GAP-04 privilege escalation).
3. **Remediation proof** — Show transfer fix (`transfer_service.py`, rejected transfers, tests passing).
4. **Run compliance scan** — Admin clicks "Run Scan" or CLI command.
5. **Dashboard** — KPI cards update; compliance score improves for transfer-related KPIs.
6. **LLM report + Judge verdicts** — Executive summary, evidence chains, F-18 → Partial, disclosure gaps (missing CSRF, privacy workflows), AC-* still Non-Compliant.
7. **Re-investigation demo** — Show one control with Insufficient Evidence triggering a second test cycle (max 3 iterations).
8. **Continuous value** — "Verdicts expire; this runs weekly; new failed logins or access violations appear automatically."
9. **Human review** — Team marks report as reviewed; final judgement stays with humans (Week 2 principle).

---

## 13. Team Work Split (Suggested)

| Area | Suggested owner | Prior reports used |
|---|---|---|
| Control Extractor + Orchestrator | Member A | F-01..F-18, Section 4 flow |
| Metrics + DAST agents (Rhea, Columbo) | Member B | Week 3 KPIs, Week 4 gaps, Week 5 retest matrix |
| Runtime + Standards agents (Izzy, Mike) | Member C | Audit logs, standards mapping |
| Judge + LLM reporter (Judy) | Member D | Week 2 Part 2 §14, Section 4.8 scoring |
| Admin dashboard UI | Member E | Week 3 dashboard format |
| Testing + demo + report writing | All | Week 5 retest matrix |

---

## 14. Timeline (Suggested)

| Week | Milestone |
|---|---|
| Week 1 | Control Extractor, Orchestrator, Metrics + DAST agents, 10+ rule checks |
| Week 2 | Judge agent, re-investigation loop, DB tables, first sample report |
| Week 3 | Runtime + Standards agents, admin dashboard, before/after demo |
| Week 4 | Disclosure gaps section, human-reviewed output, capstone presentation |

---

## 15. Success Criteria

Milestone 7 is complete when:

- [ ] Compliance scan runs on-demand with orchestrated agent pipeline
- [ ] All 15 KPIs auto-calculate via Metrics Agent (no LLM math)
- [ ] At least 20 rule checks map to F-01..F-18 and GAP-01..05
- [ ] Judge issues Compliant / Non-Compliant / Insufficient Evidence verdicts with evidence chains
- [ ] Re-investigation loop runs up to 3 cycles when evidence is insufficient
- [ ] Disclosure gaps section lists controls expected but not found
- [ ] One before/after comparison shows transfer remediation impact
- [ ] Human review step documented and demonstrated
- [ ] Report maps findings to OWASP, ISO 27001, NIST SP 800-53, GDPR

---

## 16. What We Are NOT Doing (Scope Control)

- Not fixing all 18 findings in Milestone 7 — that was M6
- Not claiming ISO/GDPR certification — continuous *alignment assessment*
- Not replacing Burp/ZAP/Semgrep — DAST Agent integrates their outputs
- Not implementing LangGraph, satellite imagery, or SSE detective dashboard (Section 4.14)
- Not auto-blocking users without human policy (Week 5 SIEM blocking = future phase)
- Not storing OpenAI API keys in git — use environment variables (Week 5 CF-01 pattern)

---

## Appendix A — File Structure

```
ARIA/
├── compliance/
│   ├── __init__.py
│   ├── control_extractor.py   # Menny — load F-01..F-18 controls
│   ├── orchestrator.py        # Bron — route controls to specialists
│   ├── collector.py           # Shared signal collection
│   ├── checks.py              # Rule definitions (TC, AC, SI, CF, WC, LM)
│   ├── kpi_calculator.py      # KPI-01 to KPI-15
│   ├── llm_reporter.py        # Judge report assembly + OpenAI call
│   ├── run_scan.py            # CLI: python -m compliance.run_scan
│   ├── state.py               # Shared scan state schema
│   └── agents/
│       ├── metrics.py         # Rhea — deterministic KPI + rule checks
│       ├── dast.py            # Columbo — pytest, Semgrep, HTTP checks
│       ├── runtime.py         # Izzy — audit_logs, rejected_transfers
│       ├── standards.py       # Mike — RAG standards mapping
│       └── judge.py           # Judy — verdict scoring + re-investigation
├── reports/                   # Generated Markdown reports
├── templates/
│   ├── admin_compliance.html
│   ├── admin_compliance_findings.html
│   └── admin_compliance_reports.html
├── app.py                     # New routes + DB tables
└── MILESTONE_7_LLM_COMPLIANCE_MONITORING_PLAN.md
```

## Appendix B — Dependencies to Add

```
openai>=1.0.0          # LLM API (or use ChatGPT-4 Turbo as per project overview)
python-dotenv>=1.0.0   # API key from env (aligns with Week 5 secret management)
```

Optional: keep `requirements.txt` minimal; document OpenAI as dev/demo dependency.

## Appendix C — Cross-Reference Index

| Document | Reused in this plan |
|---|---|
| Sibyl (reference project) | Multi-agent orchestration, Judge loop, disclosure gaps, proof-not-trust (Section 4) |
| Week 2 Part 2 | F-01..F-18, LLM workflow §14, standards mapping |
| Week 3 | KPI-01..KPI-15, monitoring plan §9, remediation tracking Appendix B |
| Week 4 | GAP-01..05, Burp/Semgrep/Nikto/ZAP/SonarQube methods |
| Week 5 | Transfer, AC, SQL, config, web controls remediation + retest matrix + SIEM |
| INITIAL_COMPLIANCE_ASSESSMENT_GUIDE.md | Prompt patterns, guardrails |
| APP_SECURITY_AND_COMPLIANCE_REFERENCE.md | Route map, removed compliance routes to restore |
| TRANSFER_SECURITY_BOARD_REPORT.md | Report tone for LLM executive summary |
