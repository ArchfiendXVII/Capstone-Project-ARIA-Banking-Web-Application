from __future__ import annotations

from compliance.checks import run_checks
from compliance.collector import collect_signals
from compliance.control_extractor import load_controls
from compliance.kpi_calculator import calculate_kpis


def test_kpi_snapshot_keys():
    ctx = collect_signals()
    checks = run_checks(ctx)
    controls = load_controls()
    kpis = calculate_kpis(
        controls=controls,
        checks=checks,
        audit_summary=ctx["audit_summary"],
        tool_results=ctx["tool_results"],
        response_headers=ctx.get("response_headers", {}),
    )
    for key in [f"KPI-{i:02d}" for i in range(1, 16)]:
        assert key in kpis
    assert "framework_scores" in kpis
