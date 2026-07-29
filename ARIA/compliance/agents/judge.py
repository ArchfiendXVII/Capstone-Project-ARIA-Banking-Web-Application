from __future__ import annotations

from compliance.scoring import build_verdicts, score_state
from compliance.state import ReinvestigationRequest, ScanState


class JudgeAgent:
    name = "judge"

    def run(self, state: ScanState, ctx: dict) -> ScanState:
        scores = score_state(state)
        state.verdicts = build_verdicts(state, scores)
        state.reinvestigation_requests = _reinvestigation_requests(state)
        state.kpi_snapshot.setdefault("judge_score", scores.get("overall", 0))
        state.findings = [
            {
                "control_id": v.control_id,
                "verdict": v.verdict,
                "score": v.score,
                "evidence_chain": v.evidence_chain,
            }
            for v in state.verdicts
        ]
        return state


def _reinvestigation_requests(state: ScanState) -> list[ReinvestigationRequest]:
    requests: list[ReinvestigationRequest] = []
    check_map = {c.check_id: c for c in state.check_results}
    for verdict in state.verdicts:
        if verdict.verdict != "Insufficient Evidence":
            continue
        control = next((c for c in state.controls if c.id == verdict.control_id), None)
        if not control:
            continue
        weak_checks = [cid for cid in control.check_ids if check_map.get(cid, None) and check_map[cid].status == "not_tested"]
        if weak_checks:
            requests.append(
                ReinvestigationRequest(
                    control_id=control.id,
                    gap="Insufficient automated evidence",
                    refined_query=f"Re-run checks {', '.join(weak_checks)}",
                    requested_agent=control.assigned_agents[0] if control.assigned_agents else "dast",
                    check_ids=weak_checks,
                )
            )
    low_score = state.kpi_snapshot.get("judge_score", 1.0)
    if isinstance(low_score, (int, float)) and low_score < 0.7:
        for control in state.controls:
            if control.priority in ("critical", "high"):
                related = [c for c in state.check_results if control.id in c.finding_ids and c.status == "partial"]
                if related:
                    requests.append(
                        ReinvestigationRequest(
                            control_id=control.id,
                            gap="Partial evidence on high priority control",
                            refined_query=f"Deepen evidence for {control.id}",
                            requested_agent=control.assigned_agents[0],
                            check_ids=[c.check_id for c in related],
                        )
                    )
    return requests[:5]


judge_agent = JudgeAgent()
