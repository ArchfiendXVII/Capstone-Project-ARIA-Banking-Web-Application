from __future__ import annotations

from compliance.checks import CHECK_REGISTRY, run_checks
from compliance.kpi_calculator import calculate_kpis
from compliance.state import CheckResult, ScanState


class MetricsAgent:
    name = "metrics"

    def run(self, state: ScanState, ctx: dict) -> ScanState:
        ids = [cid for cid in CHECK_REGISTRY if cid.startswith(("TC-", "CF-")) or cid == "LM-04"]
        existing = {c.check_id for c in state.check_results}
        new_checks = run_checks(ctx, [i for i in ids if i not in existing])
        state.check_results.extend(new_checks)
        state.kpi_snapshot = calculate_kpis(
            controls=state.controls,
            checks=state.check_results,
            audit_summary=ctx.get("audit_summary", {}),
            tool_results=ctx.get("tool_results", {}),
            response_headers=ctx.get("response_headers", {}),
        )
        state.tool_results.setdefault("metrics", {})["kpi_count"] = len(state.kpi_snapshot)
        return state


metrics_agent = MetricsAgent()
