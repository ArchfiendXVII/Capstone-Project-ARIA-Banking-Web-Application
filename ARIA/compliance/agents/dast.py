from __future__ import annotations

import threading

from compliance.checks import CHECK_REGISTRY, run_checks
from compliance.flask_adapter import get_test_client
from compliance.state import ScanState


class DASTAgent:
    name = "dast"

    def run(self, state: ScanState, ctx: dict) -> ScanState:
        ids = [cid for cid in CHECK_REGISTRY if cid.startswith(("AC-", "SI-", "WC-", "TC-"))]
        existing = {c.check_id for c in state.check_results}
        new_checks = run_checks(ctx, [i for i in ids if i not in existing])
        state.check_results.extend(new_checks)
        state.tool_results["pytest"] = ctx.get("tool_results", {}).get("pytest", {})
        state.tool_results["semgrep"] = ctx.get("tool_results", {}).get("semgrep", {})
        state.tool_results["dast"] = {"checks_run": len(new_checks)}
        return state


def run_concurrent_transfer_test() -> dict:
    """Optional TC-05 probe; may be flaky under test client."""
    results: list[str] = []

    def worker():
        client = get_test_client()
        client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
        page = client.get("/transfer")
        key = "race-test-key"
        if b'idempotency_key' in page.data:
            import re

            m = re.search(rb'name="idempotency_key" value="([^"]+)"', page.data)
            if m:
                key = m.group(1).decode()
        client.post(
            "/transfer",
            data={"recipient": "sara@aria.local", "amount": "1", "description": "race", "idempotency_key": key},
            follow_redirects=True,
        )
        results.append("ok")

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return {"threads_completed": len(results), "flaky": len(results) != 3}


dast_agent = DASTAgent()
