from __future__ import annotations

from compliance.agents.dast import dast_agent
from compliance.agents.judge import judge_agent
from compliance.agents.metrics import metrics_agent
from compliance.agents.runtime import runtime_agent
from compliance.agents.standards import standards_agent
from compliance.checks import run_checks
from compliance.config import MAX_ITERATIONS
from compliance.control_extractor import build_routing_plan, load_controls
from compliance.state import ScanState, new_scan_id


from compliance.metadata import get_check_name

AGENTS = {
    "metrics": metrics_agent,
    "dast": dast_agent,
    "runtime": runtime_agent,
    "standards": standards_agent,
}

# (start_percent, span_percent) for each agent's check work
AGENT_PROGRESS = {
    "metrics": (30, 10),
    "dast": (40, 18),
    "runtime": (58, 6),
    "standards": (64, 4),
}


def run_orchestration(
    ctx: dict,
    *,
    scan_type: str = "manual",
    previous_scan_id: str | None = None,
    progress=None,
) -> ScanState:
    state = ScanState(
        scan_id=new_scan_id(),
        scan_type=scan_type,
        controls=load_controls(),
        previous_scan_id=previous_scan_id,
    )
    state.routing_plan = build_routing_plan(state.controls)

    agent_names = ("metrics", "dast", "runtime", "standards")

    while state.iteration_count < MAX_ITERATIONS:
        if state.iteration_count == 0:
            for agent_name in agent_names:
                base, span = AGENT_PROGRESS.get(agent_name, (30, 10))
                if progress:
                    progress.agent_start(
                        agent_name,
                        f"Starting {agent_name} agent — running security checks",
                        base,
                    )
                ctx["_current_agent"] = agent_name
                ctx["_progress"] = progress
                ctx["_progress_base"] = base
                ctx["_progress_span"] = span
                AGENTS[agent_name].run(state, ctx)
                if progress:
                    progress.agent_done(agent_name, f"{agent_name} agent finished", base + span)
        else:
            if progress:
                progress.advance(
                    66,
                    f"Re-investigation pass {state.iteration_count + 1} — deepening evidence",
                    agent="system",
                    phase="orchestrating",
                )
            for req in state.reinvestigation_requests:
                if req.check_ids:
                    ctx["_current_agent"] = req.requested_agent
                    ctx["_progress"] = progress
                    ctx["_progress_base"] = 66
                    ctx["_progress_span"] = 4
                    new_results = run_checks(ctx, req.check_ids)
                    by_id = {c.check_id: c for c in state.check_results}
                    for result in new_results:
                        by_id[result.check_id] = result
                    state.check_results = list(by_id.values())
                agent = AGENTS.get(req.requested_agent)
                if agent:
                    agent.run(state, ctx)

        if progress:
            progress.advance(68, "Judy (Judge) — scoring controls and building verdicts", agent="judge", phase="orchestrating")
        state.iteration_count += 1
        judge_agent.run(state, ctx)
        overall = state.kpi_snapshot.get("judge_score", 1.0)
        if progress:
            progress.advance(70, f"Judge complete — iteration {state.iteration_count}", agent="judge")
        if overall >= 0.7 or not state.reinvestigation_requests:
            break
        if state.iteration_count >= MAX_ITERATIONS:
            break

    return state
