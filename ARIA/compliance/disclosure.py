from __future__ import annotations

import json

from compliance.config import DATA_DIR, PRIVACY_ROUTES
from compliance.flask_adapter import get_test_client
from compliance.state import CheckResult, ScanState


def evaluate_disclosure_gaps(state: ScanState) -> list[dict]:
    path = DATA_DIR / "disclosure_rules.json"
    rules = json.loads(path.read_text(encoding="utf-8"))
    check_map: dict[str, CheckResult] = {c.check_id: c for c in state.check_results}
    gaps: list[dict] = []
    client = get_test_client()

    for rule in rules:
        gap = {
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule.get("severity", "medium"),
            "status": "closed",
            "detail": "",
        }
        check_id = rule.get("check_id")
        if check_id and check_id in check_map:
            result = check_map[check_id]
            if result.status in ("fail", "partial", "not_tested"):
                gap["status"] = "open"
                gap["detail"] = result.evidence
        routes = rule.get("routes", [])
        if routes:
            missing = []
            for route in routes:
                resp = client.get(route, follow_redirects=False)
                if resp.status_code == 404:
                    missing.append(route)
            if missing:
                gap["status"] = "open"
                gap["detail"] = f"Missing routes: {', '.join(missing)}"
        if gap["status"] == "open":
            gaps.append(gap)
    state.disclosure_gaps = gaps
    return gaps
