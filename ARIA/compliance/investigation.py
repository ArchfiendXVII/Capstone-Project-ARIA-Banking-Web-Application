from __future__ import annotations

import json
from typing import Any

from compliance.metadata import control_title, get_check_catalog, get_check_name, get_kpi_list, parse_verdict_evidence
from compliance.scan_progress import AGENT_LABELS, PHASE_LABELS

PIPELINE_AGENTS = [
    {
        "id": "system",
        "label": "Orchestrator",
        "short": "Orchestrator",
        "role": "Coordinates the scan pipeline, loads controls, and routes work to specialist agents.",
        "icon": "git-branch",
        "order": 0,
    },
    {
        "id": "collector",
        "label": "Signal Collector",
        "short": "Collector",
        "role": "Reads audit logs and rejected transfers from SQLite, runs pytest smoke tests, Semgrep, and probes HTTP security headers.",
        "icon": "database",
        "order": 1,
    },
    {
        "id": "metrics",
        "label": "Rhea · Metrics Agent",
        "short": "Rhea",
        "role": "Runs configuration and logging checks (TC/CF/LM). Computes KPI snapshot from audit completeness and tool results.",
        "icon": "bar-chart-2",
        "order": 2,
    },
    {
        "id": "dast",
        "label": "Columbo · DAST Agent",
        "short": "Columbo",
        "role": "Dynamic application security testing — access control, session, web config, and transfer route probes.",
        "icon": "search",
        "order": 3,
    },
    {
        "id": "runtime",
        "label": "Izzy · Runtime Agent",
        "short": "Izzy",
        "role": "Runtime behaviour checks — headers, cookies, error handling, and live response analysis.",
        "icon": "activity",
        "order": 4,
    },
    {
        "id": "standards",
        "label": "Mike · Standards Agent",
        "short": "Mike",
        "role": "Maps check results to OWASP, ISO 27001, NIST, and GDPR control themes.",
        "icon": "book-open",
        "order": 5,
    },
    {
        "id": "judge",
        "label": "Judy · Judge Agent",
        "short": "Judy",
        "role": "Scores each control, builds verdicts with evidence chains, and requests re-investigation when evidence is weak.",
        "icon": "scale",
        "order": 6,
    },
    {
        "id": "disclosure",
        "label": "Disclosure Evaluator",
        "short": "Disclosure",
        "role": "Detects missing privacy policy, CSRF token, and security header disclosures on public routes.",
        "icon": "file-warning",
        "order": 7,
    },
    {
        "id": "reporter",
        "label": "Report Generator",
        "short": "Reporter",
        "role": "Generates the professional gap analysis report using scan state and OpenAI.",
        "icon": "file-text",
        "order": 8,
    },
]

FLOW_EDGES = [
    {"from": "system", "to": "collector", "label": "Scan job + DB path"},
    {"from": "collector", "to": "metrics", "label": "audit_summary · tool_results · headers"},
    {"from": "metrics", "to": "dast", "label": "KPI snapshot · shared check context"},
    {"from": "dast", "to": "runtime", "label": "DAST findings · pytest/semgrep results"},
    {"from": "runtime", "to": "standards", "label": "Runtime check results"},
    {"from": "standards", "to": "judge", "label": "Standards mappings · all check results"},
    {"from": "judge", "to": "dast", "label": "Re-investigation requests (if needed)", "optional": True},
    {"from": "judge", "to": "disclosure", "label": "Verdicts + check results"},
    {"from": "disclosure", "to": "reporter", "label": "Gaps + full scan state"},
    {"from": "reporter", "to": "system", "label": "Report saved to DB + reports/"},
]

AGENT_CHECK_PREFIXES = {
    "metrics": ("TC-", "CF-", "LM-04"),
    "dast": ("AC-", "SI-", "WC-", "TC-"),
    "runtime": ("RT-", "HD-"),
    "standards": ("ST-",),
}


def _agent_for_check(check_id: str, explicit_agent: str | None = None) -> str:
    if explicit_agent and explicit_agent in AGENT_LABELS:
        return explicit_agent
    for agent_id, prefixes in AGENT_CHECK_PREFIXES.items():
        if any(check_id.startswith(p) for p in prefixes):
            return agent_id
    return explicit_agent or "metrics"


def _status_from_checks(checks: list[dict[str, Any]]) -> str:
    if not checks:
        return "idle"
    if any(c.get("status") == "running" for c in checks):
        return "running"
    return "done"


def _agent_participated(
    aid: str,
    *,
    timeline: list[dict[str, Any]],
    agent_checks: list[dict[str, Any]],
    artifacts: dict[str, Any],
    scan_row_id: int | None,
    report_id: int | None,
    verdicts: list,
    standards_mappings: dict,
) -> bool:
    if aid == "system":
        return bool(scan_row_id)
    if aid == "collector":
        return bool(artifacts.get("audit_summary") or any(e.get("agent_id") == aid for e in timeline))
    if aid == "metrics":
        return bool(agent_checks or artifacts.get("kpi_snapshot"))
    if aid == "dast":
        return bool(agent_checks or artifacts.get("dast_summary") or artifacts.get("pytest"))
    if aid == "runtime":
        return bool(agent_checks or timeline)
    if aid == "standards":
        return bool(standards_mappings) or bool(verdicts) or bool(scan_row_id)
    if aid == "judge":
        return bool(verdicts)
    if aid == "disclosure":
        return bool(scan_row_id)
    if aid == "reporter":
        return bool(report_id)
    return bool(any(e.get("agent_id") == aid for e in timeline))


def _resolve_agent_status(
    aid: str,
    *,
    agent_status: dict[str, str],
    timeline: list[dict[str, Any]],
    agent_checks: list[dict[str, Any]],
    artifacts: dict[str, Any],
    scan_row_id: int | None,
    report_id: int | None,
    verdicts: list,
    standards_mappings: dict,
    scan_complete: bool,
) -> str:
    if scan_complete:
        return "done" if _agent_participated(
            aid,
            timeline=timeline,
            agent_checks=agent_checks,
            artifacts=artifacts,
            scan_row_id=scan_row_id,
            report_id=report_id,
            verdicts=verdicts,
            standards_mappings=standards_mappings,
        ) else "idle"

    live = agent_status.get(aid)
    if live == "done":
        return "done"
    if live == "running":
        return "running"
    if agent_checks:
        return "done"
    if aid == "judge" and verdicts:
        return "done"
    if aid == "reporter" and report_id:
        return "done"
    if aid == "disclosure" and scan_row_id and agent_status.get("phase") in ("llm", "saving", "done"):
        return "done"
    if any(e.get("agent_id") == aid for e in timeline):
        return "running"
    return "idle"


def build_investigation_from_state(
    state_dict: dict[str, Any],
    *,
    timeline: list[dict[str, Any]] | None = None,
    agent_status: dict[str, str] | None = None,
    duration_seconds: int | None = None,
    scan_row_id: int | None = None,
    report_id: int | None = None,
    scan_complete: bool | None = None,
) -> dict[str, Any]:
    """Build full investigation trace from completed or in-progress scan state."""
    timeline = timeline or []
    agent_status = agent_status or {}
    check_results = state_dict.get("check_results") or []
    verdicts = state_dict.get("verdicts") or []
    disclosure_gaps = state_dict.get("disclosure_gaps") or []
    kpi = state_dict.get("kpi_snapshot") or {}
    audit = state_dict.get("audit_summary") or {}
    tools = state_dict.get("tool_results") or {}
    reinvest = state_dict.get("reinvestigation_requests") or []
    standards_mappings = state_dict.get("standards_mappings") or {}
    if scan_complete is None:
        scan_complete = bool(scan_row_id and report_id)

    checks_by_agent: dict[str, list[dict[str, Any]]] = {a["id"]: [] for a in PIPELINE_AGENTS}
    for cr in check_results:
        agent = _agent_for_check(cr.get("check_id", ""), cr.get("agent"))
        if agent not in checks_by_agent:
            checks_by_agent[agent] = []
        detail = cr.get("evidence_detail") or {}
        items = detail.get("items") if isinstance(detail, dict) else []
        if not items and isinstance(detail, dict) and detail.get("test_name"):
            items = [detail]
        checks_by_agent.setdefault(agent, []).append(
            {
                "check_id": cr.get("check_id"),
                "name": get_check_name(cr.get("check_id", "")),
                "status": cr.get("status"),
                "evidence": cr.get("evidence"),
                "finding_ids": cr.get("finding_ids") or [],
                "standards": cr.get("standards") or [],
                "evidence_items": items or [],
                "execution_trace": (
                    cr.get("execution_trace")
                    or (detail.get("execution_trace") if isinstance(detail, dict) else None)
                    or []
                ),
                "agent": agent,
            }
        )

    agents_out: dict[str, Any] = {}
    for meta in PIPELINE_AGENTS:
        aid = meta["id"]
        agent_checks = checks_by_agent.get(aid, [])
        agent_timeline = [e for e in timeline if e.get("agent_id") == aid or _timeline_agent_match(e, aid)]

        artifacts: dict[str, Any] = {}
        outputs: list[str] = []
        if aid == "collector":
            artifacts = {"audit_summary": audit, "tool_results": tools, "response_headers": state_dict.get("response_headers")}
            outputs = ["Audit log summary", "Baseline test results", "HTTP security headers"]
        elif aid == "metrics":
            artifacts = {"kpi_snapshot": kpi}
            outputs = ["KPI health snapshot", "Configuration & logging check results"]
        elif aid == "dast":
            artifacts = {"dast_summary": tools.get("dast", {}), "pytest": tools.get("pytest", {}), "semgrep": tools.get("semgrep", {})}
            outputs = ["DAST probe results", "Pytest outcomes", "Semgrep static analysis"]
        elif aid == "runtime":
            artifacts = {"runtime_summary": tools.get("runtime", {})}
            outputs = ["Runtime behaviour check results"]
        elif aid == "standards":
            artifacts = {"standards_mappings": standards_mappings}
            outputs = ["OWASP / ISO / NIST / GDPR control mappings"]
        elif aid == "judge":
            artifacts = {
                "verdicts": verdicts,
                "reinvestigation_requests": reinvest,
                "iteration_count": state_dict.get("iteration_count", 0),
                "judge_score": kpi.get("judge_score"),
            }
            outputs = ["Control verdicts", "Re-investigation requests (if any)"]
        elif aid == "disclosure":
            artifacts = {"disclosure_gaps": disclosure_gaps}
            outputs = ["Public disclosure gap findings"]
        elif aid == "reporter":
            if report_id:
                artifacts = {"report_id": report_id}
            outputs = ["Professional gap analysis report"]

        status = _resolve_agent_status(
            aid,
            agent_status=agent_status,
            timeline=timeline,
            agent_checks=agent_checks,
            artifacts=artifacts,
            scan_row_id=scan_row_id,
            report_id=report_id,
            verdicts=verdicts,
            standards_mappings=standards_mappings,
            scan_complete=scan_complete,
        )

        reasoning_steps = _build_reasoning_steps(
            aid, agent_timeline, agent_checks, artifacts, meta, verdicts, disclosure_gaps, reinvest
        )
        presented = _build_presented_sections(aid, artifacts, agent_checks, kpi, verdicts, disclosure_gaps, report_id)

        agents_out[aid] = {
            **meta,
            "status": status,
            "timeline": agent_timeline,
            "reasoning_steps": reasoning_steps,
            "checks": agent_checks,
            "artifacts": artifacts,
            "presented": presented,
            "outputs": outputs,
            "summary": _agent_summary(aid, agent_checks, artifacts, status),
        }

    evidence_chain = _build_evidence_chain(timeline, check_results, verdicts, disclosure_gaps)

    checks_total = len(check_results)
    checks_pass = sum(1 for c in check_results if c.get("status") == "pass")
    checks_fail = sum(1 for c in check_results if c.get("status") == "fail")

    return {
        "version": 1,
        "scan_row_id": scan_row_id,
        "report_id": report_id,
        "scan_timestamp": state_dict.get("scan_id"),
        "duration_seconds": duration_seconds,
        "pipeline": [{**a, "status": agents_out[a["id"]]["status"]} for a in PIPELINE_AGENTS],
        "flow_edges": FLOW_EDGES,
        "agents": agents_out,
        "evidence_chain": evidence_chain,
        "summary": {
            "checks_total": checks_total,
            "checks_pass": checks_pass,
            "checks_fail": checks_fail,
            "checks_partial": checks_total - checks_pass - checks_fail,
            "verdicts_total": len(verdicts),
            "verdicts_non_compliant": sum(1 for v in verdicts if v.get("verdict") == "Non-Compliant"),
            "disclosure_gaps": len(disclosure_gaps),
            "iteration_count": state_dict.get("iteration_count", 0),
            "judge_score": kpi.get("judge_score"),
        },
        "scan_complete": scan_complete,
    }


def _timeline_agent_match(entry: dict[str, Any], agent_id: str) -> bool:
    agent_field = entry.get("agent", "")
    label = AGENT_LABELS.get(agent_id, agent_id)
    return agent_id in agent_field or label.split("·")[0].strip().lower() in agent_field.lower()


def _agent_summary(aid: str, checks: list, artifacts: dict, status: str) -> str:
    if status == "idle":
        return "Waiting to start"
    if status == "running":
        return "In progress…"
    if aid == "system":
        return "Scan pipeline coordinated and completed"
    if aid == "collector" and artifacts.get("audit_summary"):
        a = artifacts["audit_summary"]
        return f"Collected {a.get('total_events', 0)} audit events · {a.get('failed_login_count', 0)} failed logins"
    if aid == "metrics" and (checks or artifacts.get("kpi_snapshot")):
        return f"Ran {len(checks)} checks · KPI snapshot computed"
    if aid == "dast" and checks:
        passed = sum(1 for c in checks if c.get("status") == "pass")
        return f"Ran {len(checks)} DAST checks · {passed} passed"
    if aid == "runtime" and checks:
        return f"Completed {len(checks)} runtime probes"
    if aid == "standards" and artifacts.get("standards_mappings"):
        return f"Mapped {len(artifacts['standards_mappings'])} controls to framework themes"
    if aid == "judge" and artifacts.get("verdicts"):
        v = artifacts["verdicts"]
        nc = sum(1 for x in v if x.get("verdict") == "Non-Compliant")
        return f"Scored {len(v)} controls · {nc} non-compliant"
    if aid == "disclosure":
        gaps = artifacts.get("disclosure_gaps") or []
        return f"Found {len(gaps)} disclosure gap(s)" if gaps else "No disclosure gaps detected"
    if aid == "reporter" and artifacts.get("report_id"):
        return f"Report #{artifacts['report_id']} saved"
    if checks:
        return f"Completed {len(checks)} step(s)"
    return "Complete"


def _short_check_conclusion(chk: dict[str, Any]) -> str:
    status = chk.get("status", "unknown")
    name = chk.get("name") or get_check_name(chk.get("check_id", ""))
    labels = {
        "pass": f"«{name}» passed — behaviour matches the security claim.",
        "fail": f"«{name}» failed — this weakens related control verdicts.",
        "partial": f"«{name}» returned partial evidence only.",
        "not_tested": f"«{name}» could not be fully executed.",
    }
    return labels.get(status, f"«{name}» recorded as {status}.")


def _execution_hint(check_id: str) -> str:
    hints = {
        "AC-": "Flask test client sends authenticated HTTP requests to protected routes and inspects status codes and response bodies.",
        "SI-": "Combines static source analysis (pattern search in app.py) with live HTTP probes using crafted query parameters.",
        "WC-": "Fetches HTML forms and response headers from live routes to verify tokens, rate limits, and CSP.",
        "TC-": "Exercises money-transfer flows via the test client — including idempotency keys, rejection paths, and DB audit rows.",
        "CF-": "Scans application configuration and startup code for hardcoded secrets, debug flags, and missing security headers.",
        "LM-": "Queries audit_logs and structured compliance logs in SQLite for completeness and required event types.",
    }
    for prefix, hint in hints.items():
        if check_id.startswith(prefix):
            return hint
    cat = get_check_catalog().get(check_id, {}).get("category", "Security")
    return f"Automated {cat} probe against the application under test."


def _location_label(item: dict[str, Any]) -> str:
    if item.get("file"):
        loc = item["file"]
        if item.get("line"):
            loc += f":{item['line']}"
        return loc
    if item.get("route"):
        return f"Route {item['route']}"
    if item.get("database"):
        db = item["database"]
        if item.get("table"):
            db += f" → {item['table']}"
        return f"Database {db}"
    return item.get("location") or "Application"


def _normalize_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "test_name": item.get("test_name") or "Security check",
        "status": item.get("status", "unknown"),
        "method": item.get("method") or "Automated check",
        "where": _location_label(item),
        "observation": item.get("observation") or "—",
        "request_detail": item.get("request_detail"),
        "result_detail": item.get("result_detail"),
        "snippet": item.get("snippet"),
        "tool": item.get("tool"),
        "execution_trace": item.get("execution_trace") or [],
    }


def _parse_formatted_evidence(text: str) -> dict[str, Any] | None:
    """Parse markdown evidence strings from format_evidence_item into structured blocks."""
    import re

    if not text or not text.strip():
        return None
    lines = text.strip().splitlines()
    first = lines[0] if lines else ""
    name_m = re.match(r"\*\*(.+?)\*\*\s*—\s*(\w+)", first)
    item: dict[str, Any] = {
        "test_name": name_m.group(1) if name_m else "Evidence",
        "status": name_m.group(2).lower() if name_m else "unknown",
    }
    for line in lines[1:]:
        line = line.lstrip("- ").strip()
        if line.startswith("**How tested:**"):
            item["method"] = line.split("**How tested:**", 1)[1].strip()
        elif line.startswith("**Where:**"):
            item["where"] = line.split("**Where:**", 1)[1].strip()
        elif line.startswith("**What we found:**"):
            item["observation"] = line.split("**What we found:**", 1)[1].strip()
        elif line.startswith("**Request / action:**"):
            item["request_detail"] = line.split("**Request / action:**", 1)[1].strip()
        elif line.startswith("**Result:**"):
            item["result_detail"] = line.split("**Result:**", 1)[1].strip()
        elif line.startswith("**Source excerpt"):
            continue
    snippet_m = re.search(r"```\n([\s\S]*?)\n```", text)
    if snippet_m:
        item["snippet"] = snippet_m.group(1).strip()
    if item.get("method") or item.get("observation"):
        return _normalize_evidence_item(item)
    return None


def _execution_from_check(chk: dict[str, Any] | None) -> dict[str, Any] | None:
    if not chk:
        return None
    cid = chk.get("check_id", "")
    catalog = get_check_catalog().get(cid, {})
    items = list(chk.get("evidence_items") or [])
    detail = chk.get("evidence_detail") or {}
    if not items and isinstance(detail, dict) and detail.get("method"):
        items = [_normalize_evidence_item({**detail, "status": chk.get("status")})]
    if not items:
        items = [
            {
                "test_name": chk.get("name") or get_check_name(cid),
                "status": chk.get("status"),
                "method": _execution_hint(cid),
                "where": "See check output below",
                "observation": chk.get("evidence") or "Probe executed.",
            }
        ]
    else:
        items = [_normalize_evidence_item(it) for it in items]
    trace = list(chk.get("execution_trace") or (detail.get("execution_trace") if isinstance(detail, dict) else None) or [])
    if trace and items and not items[0].get("execution_trace"):
        items[0]["execution_trace"] = trace
    return {
        "check_id": cid,
        "category": catalog.get("category", "Security"),
        "status": chk.get("status"),
        "technique": _execution_hint(cid),
        "summary": chk.get("evidence"),
        "finding_ids": chk.get("finding_ids") or [],
        "standards": chk.get("standards") or [],
        "evidence_items": items,
    }


def _finalize_reasoning_steps(steps: list[dict[str, Any]], checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name = {c.get("name"): c for c in checks if c.get("name")}
    by_id = {c.get("check_id"): c for c in checks if c.get("check_id")}
    result_titles = {s.get("title") for s in steps if s.get("step_type") == "check_result"}

    final: list[dict[str, Any]] = []
    n = 1
    for step in steps:
        stype = step.get("step_type")
        if stype == "check_running" and step.get("title") in result_titles:
            continue

        chk = by_name.get(step.get("title")) or by_id.get(step.get("check_id"))
        if stype in ("check_running", "check_result") and chk:
            step["execution"] = _execution_from_check(chk)
            step["has_details"] = True
            step["status"] = chk.get("status") or step.get("status")
            if stype == "check_result" or chk.get("status"):
                step["conclusion"] = _short_check_conclusion(chk)

        if stype == "verdict" and step.get("evidence_blocks"):
            step["has_details"] = True

        if stype == "disclosure_gap" and step.get("conclusion"):
            step["has_details"] = True
            step["execution"] = {"summary": step.get("conclusion"), "evidence_items": []}

        step["step"] = n
        n += 1
        final.append(step)
    return final


def _check_reasoning(chk: dict[str, Any]) -> dict[str, str]:
    catalog = get_check_catalog()
    cid = chk.get("check_id", "")
    meta = catalog.get(cid, {})
    category = meta.get("category", "Security")
    name = chk.get("name") or get_check_name(cid)
    status = chk.get("status", "unknown")
    reasoning = (
        f"I need to verify «{name}» because it falls under {category} — "
        f"this directly affects whether mapped security controls can be considered met."
    )
    action = chk.get("evidence") or "Executed the automated probe and captured the application response."
    conclusions = {
        "pass": "The application behaved as expected. This check supports compliant control verdicts.",
        "fail": "The application did not meet the expected security behaviour. This will pull related controls toward non-compliant.",
        "partial": "Evidence was inconclusive or only partially satisfied. Judy may mark related controls as insufficient evidence.",
        "not_tested": "This check could not be fully executed. Manual follow-up or re-investigation may be required.",
    }
    return {
        "reasoning": reasoning,
        "action": action,
        "conclusion": conclusions.get(status, "Recorded check outcome for the judge."),
    }


def _timeline_step_reasoning(entry: dict[str, Any], agent_meta: dict[str, Any]) -> dict[str, str]:
    step_type = entry.get("step_type", "activity")
    message = entry.get("message") or ""
    detail = entry.get("detail") or ""
    if step_type == "agent_start":
        return {
            "reasoning": f"{agent_meta.get('label', 'This agent')} is activated because prior agents have supplied the inputs listed in the pipeline.",
            "action": message,
            "conclusion": "Work phase started — downstream agents will wait for my outputs.",
        }
    if step_type == "agent_done":
        return {
            "reasoning": "My assigned checks and analysis for this pass are finished.",
            "action": message,
            "conclusion": "Outputs are forwarded to the next agent in the pipeline.",
        }
    if step_type == "check_running":
        return {
            "reasoning": "Running the next security check in my queue to gather evidence for control scoring.",
            "action": f"Executing: {message}" + (f" ({detail})" if detail else ""),
            "conclusion": "Running automated probe — expand below for execution details.",
        }
    if step_type == "check_result":
        status = entry.get("status", "unknown")
        return {
            "reasoning": "Recording the outcome of an automated security check so Judy can score controls.",
            "action": message,
            "conclusion": f"Check recorded as {status}.",
        }
    if step_type == "complete":
        return {
            "reasoning": "All agents have finished and results are persisted.",
            "action": message,
            "conclusion": "Investigation trace is complete.",
        }
    return {
        "reasoning": agent_meta.get("role", "Pipeline activity."),
        "action": message,
        "conclusion": detail or "Step recorded.",
    }


def _build_reasoning_steps(
    aid: str,
    timeline: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    artifacts: dict[str, Any],
    meta: dict[str, Any],
    verdicts: list[dict[str, Any]],
    disclosure_gaps: list[dict[str, Any]],
    reinvest: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    n = 1

    for entry in timeline:
        r = _timeline_step_reasoning(entry, meta)
        steps.append(
            {
                "step": n,
                "time": entry.get("time"),
                "title": entry.get("message") or entry.get("check_name") or "Pipeline step",
                "step_type": entry.get("step_type", "activity"),
                "check_id": entry.get("check_id"),
                "status": entry.get("status"),
                **r,
            }
        )
        n += 1

    seen_checks = {s.get("title") for s in steps}
    for chk in checks:
        title = chk.get("name") or chk.get("check_id")
        if title in seen_checks:
            continue
        r = _check_reasoning(chk)
        steps.append(
            {
                "step": n,
                "title": title,
                "step_type": "check_result",
                "status": chk.get("status"),
                "check_id": chk.get("check_id"),
                **r,
            }
        )
        n += 1

    if aid == "standards" and artifacts.get("standards_mappings"):
        mapped = len(artifacts["standards_mappings"])
        steps.append(
            {
                "step": n,
                "title": "Framework alignment mapping",
                "step_type": "analysis",
                "reasoning": "Mike cross-references each control's claims against OWASP, ISO 27001, NIST, and GDPR corpus excerpts so reports speak the language auditors expect.",
                "action": f"Matched {mapped} controls to relevant standard themes and stored excerpt citations.",
                "conclusion": "Standards mappings are ready for Judy to contextualize verdicts.",
            }
        )
        n += 1

    if aid == "judge":
        for v in verdicts:
            cid = v.get("control_id", "")
            verdict = v.get("verdict", "")
            score = v.get("score")
            evidence_items = list(v.get("evidence_items") or [])
            if not evidence_items:
                for line in v.get("evidence_chain") or []:
                    parsed = _parse_formatted_evidence(line)
                    if parsed:
                        evidence_items.append(parsed)
            evidence_blocks = [_normalize_evidence_item(it) for it in evidence_items]
            steps.append(
                {
                    "step": n,
                    "title": f"Verdict: {control_title(cid)}",
                    "step_type": "verdict",
                    "status": verdict,
                    "control_id": cid,
                    "reasoning": (
                        f"I weigh all check evidence linked to {cid}. "
                        f"A score of {score} and verdict «{verdict}» means the control "
                        + (
                            "is satisfied by automated evidence."
                            if verdict == "Compliant"
                            else "is not met and requires remediation."
                            if verdict == "Non-Compliant"
                            else "needs more evidence before we can claim compliance."
                        )
                    ),
                    "action": "Synthesized check outcomes and standards references into a control-level verdict.",
                    "conclusion": f"Scored {score} — {verdict}. See supporting evidence below.",
                    "evidence_blocks": evidence_blocks,
                    "has_details": bool(evidence_blocks),
                }
            )
            n += 1
        for req in reinvest:
            steps.append(
                {
                    "step": n,
                    "title": f"Re-investigation: {req.get('control_id')}",
                    "step_type": "reinvestigation",
                    "reasoning": req.get("gap") or "Evidence was weak — requesting a deeper pass from a specialist agent.",
                    "action": req.get("refined_query") or "Re-run targeted checks.",
                    "conclusion": f"Delegated to {AGENT_LABELS.get(req.get('requested_agent', ''), req.get('requested_agent'))}.",
                }
            )
            n += 1

    if aid == "disclosure":
        if not disclosure_gaps:
            steps.append(
                {
                    "step": n,
                    "title": "Disclosure review",
                    "step_type": "analysis",
                    "reasoning": "Public routes must disclose privacy practices, CSRF protection, and security headers where required.",
                    "action": "Compared live routes and related check results against disclosure rules.",
                    "conclusion": "No open disclosure gaps detected.",
                }
            )
        else:
            for gap in disclosure_gaps:
                steps.append(
                    {
                        "step": n,
                        "title": gap.get("title") or gap.get("id") or "Disclosure gap",
                        "step_type": "disclosure_gap",
                        "status": "open",
                        "reasoning": "Users and auditors expect certain security/privacy disclosures to be visible on public pages.",
                        "action": "Checked required routes and linked automated check outcomes.",
                        "conclusion": gap.get("detail") or gap.get("description") or "Gap is open.",
                    }
                )
                n += 1

    if aid == "reporter" and artifacts.get("report_id"):
        steps.append(
            {
                "step": n,
                "title": "Gap analysis report",
                "step_type": "report",
                "reasoning": "Admins need a readable narrative tying KPIs, verdicts, and disclosure gaps into actionable remediation guidance.",
                "action": "Generated markdown + HTML report from full scan state using OpenAI.",
                "conclusion": f"Report #{artifacts['report_id']} saved to the local database and reports/ folder.",
            }
        )

    if aid == "system" and not steps:
        steps.append(
            {
                "step": 1,
                "title": "Orchestration",
                "step_type": "orchestration",
                "reasoning": "I load the control catalog, assign checks to specialist agents in order, and ensure each agent receives the prior agent's outputs.",
                "action": "Initialized scan job and routed work through the compliance pipeline.",
                "conclusion": meta.get("role", ""),
            }
        )

    return _finalize_reasoning_steps(steps, checks)


def _build_presented_sections(
    aid: str,
    artifacts: dict[str, Any],
    checks: list[dict[str, Any]],
    kpi: dict[str, Any],
    verdicts: list[dict[str, Any]],
    disclosure_gaps: list[dict[str, Any]],
    report_id: int | None,
) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []

    if aid == "collector":
        audit = artifacts.get("audit_summary") or {}
        if audit:
            sections.append(
                {
                    "type": "stats",
                    "title": "Audit log signals (last 7 days)",
                    "items": [
                        {"label": "Total events", "value": audit.get("total_events", 0)},
                        {"label": "Failed logins", "value": audit.get("failed_login_count", 0)},
                        {"label": "Unauthorized attempts (all time)", "value": audit.get("unauthorized_attempts", 0)},
                        {"label": "Failed-login log completeness", "value": f"{audit.get('failed_login_completeness_pct', 0)}%"},
                        {"label": "Critical action log completeness", "value": f"{audit.get('critical_action_completeness_pct', 0)}%"},
                    ],
                }
            )
        pytest = (artifacts.get("tool_results") or {}).get("pytest") or {}
        tests = pytest.get("tests") or {}
        if tests:
            rows = [
                {"name": name, "status": "Pass" if t.get("passed") else "Fail", "detail": f"exit code {t.get('returncode', '?')}"}
                for name, t in tests.items()
            ]
            sections.append({"type": "table", "title": "Baseline automated tests", "columns": ["Test suite", "Result", "Detail"], "rows": rows})
        headers = artifacts.get("response_headers") or {}
        if headers:
            sections.append(
                {
                    "type": "list",
                    "title": "HTTP security headers observed",
                    "items": [f"{k}: {v or '(missing)'}" for k, v in headers.items()],
                }
            )

    elif aid == "metrics" and kpi:
        metrics = get_kpi_list(kpi)[:8]
        sections.append(
            {
                "type": "cards",
                "title": "Key performance indicators",
                "cards": [
                    {"label": m["label"], "value": m["value"], "hint": m.get("description", "")[:120]}
                    for m in metrics
                    if m.get("value") is not None
                ],
            }
        )

    elif aid == "dast":
        dast = artifacts.get("dast_summary") or {}
        if dast:
            sections.append(
                {
                    "type": "stats",
                    "title": "DAST summary",
                    "items": [{"label": "Checks executed this pass", "value": dast.get("checks_run", len(checks))}],
                }
            )

    elif aid == "runtime":
        rt = artifacts.get("runtime_summary") or {}
        if rt:
            sections.append(
                {
                    "type": "stats",
                    "title": "Runtime observations",
                    "items": [
                        {"label": "Rejected transfers logged", "value": rt.get("rejected_transfers", 0)},
                        {"label": "Audit events (7d)", "value": rt.get("audit_events_7d", 0)},
                    ],
                }
            )

    elif aid == "standards":
        mappings = artifacts.get("standards_mappings") or {}
        if mappings:
            rows = []
            for cid, excerpts in list(mappings.items())[:12]:
                preview = excerpts[0][:100] + "…" if excerpts and len(excerpts[0]) > 100 else (excerpts[0] if excerpts else "—")
                rows.append({"control": control_title(cid), "framework_refs": preview})
            sections.append(
                {
                    "type": "table",
                    "title": "Control → standards mapping (sample)",
                    "columns": ["Control", "Framework excerpt"],
                    "rows": rows,
                }
            )

    elif aid == "judge":
        if artifacts.get("judge_score") is not None:
            sections.append(
                {
                    "type": "stats",
                    "title": "Judge scoring",
                    "items": [
                        {"label": "Overall judge score", "value": artifacts.get("judge_score")},
                        {"label": "Iterations", "value": artifacts.get("iteration_count", 0)},
                    ],
                }
            )
        if verdicts:
            rows = [
                {
                    "control": control_title(v.get("control_id", "")),
                    "verdict": v.get("verdict"),
                    "score": v.get("score"),
                }
                for v in verdicts
            ]
            sections.append(
                {"type": "table", "title": "Control verdicts", "columns": ["Control", "Verdict", "Score"], "rows": rows}
            )
        reinvest = artifacts.get("reinvestigation_requests") or []
        if reinvest:
            sections.append(
                {
                    "type": "list",
                    "title": "Re-investigation requests",
                    "items": [f"{r.get('control_id')}: {r.get('gap')}" for r in reinvest],
                }
            )

    elif aid == "disclosure":
        if disclosure_gaps:
            sections.append(
                {
                    "type": "cards",
                    "title": "Open disclosure gaps",
                    "cards": [
                        {"label": g.get("title") or g.get("id"), "value": g.get("severity", "medium"), "hint": g.get("detail", "")}
                        for g in disclosure_gaps
                    ],
                }
            )
        else:
            sections.append(
                {
                    "type": "list",
                    "title": "Disclosure review",
                    "items": ["All configured disclosure rules passed — no missing public routes or linked check failures."],
                }
            )

    elif aid == "reporter" and report_id:
        sections.append(
            {
                "type": "link",
                "title": "Generated report",
                "label": f"Open gap analysis report #{report_id}",
                "report_id": report_id,
                "hint": "Full narrative with executive summary, risk analysis, and remediation priorities.",
            }
        )

    elif aid == "system":
        sections.append(
            {
                "type": "list",
                "title": "Orchestrator responsibilities",
                "items": [
                    "Load security control catalog and build agent routing plan",
                    "Run collector → specialist agents → judge → disclosure → reporter in order",
                    "Persist scan, verdicts, investigation trace, and report to SQLite",
                ],
            }
        )

    return sections


def _build_evidence_chain(
    timeline: list[dict[str, Any]],
    check_results: list[dict[str, Any]],
    verdicts: list[dict[str, Any]],
    disclosure_gaps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    seq = 1
    for entry in timeline:
        chain.append(
            {
                "seq": seq,
                "type": entry.get("step_type", "activity"),
                "time": entry.get("time"),
                "agent_id": entry.get("agent_id"),
                "agent": entry.get("agent") or AGENT_LABELS.get(entry.get("agent_id", ""), ""),
                "action": entry.get("message") or entry.get("action", ""),
                "detail": entry.get("detail"),
                "check_id": entry.get("check_id"),
                "check_name": entry.get("check_name"),
                "status": entry.get("status"),
            }
        )
        seq += 1

    for cr in check_results:
        cid = cr.get("check_id")
        detail = cr.get("evidence_detail") or {}
        items = detail.get("items") if isinstance(detail, dict) else []
        if not items and isinstance(detail, dict) and detail.get("test_name"):
            items = [detail]
        chain.append(
            {
                "seq": seq,
                "type": "check_result",
                "agent_id": _agent_for_check(cid or "", cr.get("agent")),
                "agent": AGENT_LABELS.get(_agent_for_check(cid or "", cr.get("agent")), ""),
                "action": f"Check result: {get_check_name(cid or '')}",
                "check_id": cid,
                "check_name": get_check_name(cid or ""),
                "status": cr.get("status"),
                "evidence": cr.get("evidence"),
                "evidence_items": items,
                "standards": cr.get("standards") or [],
            }
        )
        seq += 1

    for v in verdicts:
        evidence_items = v.get("evidence_items") or []
        if not evidence_items:
            raw = v.get("evidence_json")
            if isinstance(raw, str):
                parsed = parse_verdict_evidence(raw)
                evidence_items = parsed.get("evidence_items") or []
            elif isinstance(raw, dict):
                evidence_items = raw.get("evidence_items") or []
        chain.append(
            {
                "seq": seq,
                "type": "verdict",
                "agent_id": "judge",
                "agent": AGENT_LABELS["judge"],
                "action": f"Control verdict: {v.get('control_id')}",
                "control_id": v.get("control_id"),
                "status": v.get("verdict"),
                "score": v.get("score"),
                "evidence_chain": v.get("evidence_chain") or [],
                "evidence_items": evidence_items,
            }
        )
        seq += 1

    for gap in disclosure_gaps:
        chain.append(
            {
                "seq": seq,
                "type": "disclosure_gap",
                "agent_id": "disclosure",
                "agent": "Disclosure Evaluator",
                "action": gap.get("title") or gap.get("gap_id") or "Disclosure gap",
                "detail": gap.get("description") or gap.get("detail"),
                "status": "gap",
            }
        )
        seq += 1

    return chain


def rebuild_investigation_from_scan_row(scan_row: dict[str, Any], report_id: int | None = None) -> dict[str, Any]:
    """Rebuild investigation view from persisted scan row (legacy scans without investigation_json)."""
    shared = scan_row.get("shared_state")
    state_dict = json.loads(shared) if shared else {}
    if not state_dict.get("check_results") and scan_row.get("check_results"):
        state_dict["check_results"] = json.loads(scan_row["check_results"])
    if not state_dict.get("kpi_snapshot") and scan_row.get("kpi_snapshot"):
        state_dict["kpi_snapshot"] = json.loads(scan_row["kpi_snapshot"])
    if not state_dict.get("tool_results") and scan_row.get("tool_results"):
        state_dict["tool_results"] = json.loads(scan_row["tool_results"])

    rid = report_id
    return build_investigation_from_state(
        state_dict,
        scan_row_id=scan_row.get("id"),
        report_id=rid,
        scan_complete=True,
        timeline=_timeline_from_saved(scan_row),
    )


def _timeline_from_saved(scan_row: dict[str, Any]) -> list[dict[str, Any]]:
    if not scan_row.get("investigation_json"):
        return []
    try:
        saved = json.loads(scan_row["investigation_json"])
        merged: list[dict[str, Any]] = []
        for agent in (saved.get("agents") or {}).values():
            merged.extend(agent.get("timeline") or [])
        if merged:
            return sorted(merged, key=lambda e: e.get("time") or "")
        chain = saved.get("evidence_chain") or []
        return [
            {
                "time": c.get("time"),
                "agent_id": c.get("agent_id"),
                "agent": c.get("agent"),
                "message": c.get("action"),
                "step_type": c.get("type"),
                "detail": c.get("detail") or c.get("evidence"),
            }
            for c in chain
            if c.get("type") in ("activity", "agent_start", "agent_done", "check_running", "check_result", "complete")
        ]
    except json.JSONDecodeError:
        return []


def investigation_for_live_job(progress_dict: dict[str, Any], partial_state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge live progress with partial scan state for investigation UI polling."""
    state = partial_state or progress_dict.get("partial_state") or {}
    return build_investigation_from_state(
        state,
        timeline=progress_dict.get("full_timeline") or [],
        agent_status=progress_dict.get("agent_status") or {},
        duration_seconds=progress_dict.get("elapsed_seconds"),
        scan_complete=progress_dict.get("status") == "completed",
        scan_row_id=(progress_dict.get("result") or {}).get("scan_id"),
        report_id=(progress_dict.get("result") or {}).get("report_id"),
    )
