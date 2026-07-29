from __future__ import annotations

import sqlite3

from compliance.checks import run_checks
from compliance.state import ScanState


class RuntimeAgent:
    name = "runtime"

    def run(self, state: ScanState, ctx: dict) -> ScanState:
        ids = ["TC-04", "LM-01", "LM-02", "LM-03", "LM-04"]
        existing = {c.check_id for c in state.check_results}
        new_checks = run_checks(ctx, [i for i in ids if i not in existing])
        state.check_results.extend(new_checks)
        state.audit_summary = ctx.get("audit_summary", {})
        db_path = ctx.get("db_path")
        if db_path:
            conn = sqlite3.connect(db_path)
            try:
                rejected = conn.execute("SELECT COUNT(*) FROM rejected_transfers").fetchone()[0]
                state.tool_results["runtime"] = {
                    "rejected_transfers": rejected,
                    "audit_events_7d": state.audit_summary.get("total_events", 0),
                }
            finally:
                conn.close()
        return state


runtime_agent = RuntimeAgent()
