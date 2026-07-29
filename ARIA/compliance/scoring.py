from __future__ import annotations

from compliance.config import VERDICT_TTL_DAYS
from compliance.evidence import format_evidence_item
from compliance.metadata import get_check_name, control_title
from compliance.state import ScanState, Verdict, expiry_from_now


SOURCE_WEIGHTS = {
    "pytest": 0.95,
    "semgrep": 0.90,
    "audit": 0.85,
    "static": 0.80,
    "llm": 0.50,
}

DIMENSION_WEIGHTS = {
    "sufficiency": 0.30,
    "consistency": 0.25,
    "quality": 0.25,
    "completeness": 0.20,
}


def _check_score(status: str, weight: float) -> float:
    if status == "pass":
        return weight
    if status == "partial":
        return weight * 0.5
    if status == "not_tested":
        return weight * 0.25
    return 0.0


def score_control(control_id: str, state: ScanState) -> dict[str, float]:
    related = [c for c in state.check_results if control_id in c.finding_ids]
    if not related:
        return {"overall": 0.25, "sufficiency": 0.2, "consistency": 0.2, "quality": 0.2, "completeness": 0.2}

    sufficiency = sum(_check_score(c.status, c.source_weight) for c in related) / len(related)
    statuses = [c.status for c in related]
    consistency = 1.0 if len(set(statuses)) == 1 else 0.5 if "pass" in statuses else 0.3
    quality = sum(c.source_weight for c in related) / len(related)
    completeness = sum(1 for c in related if c.status != "not_tested") / len(related)
    overall = (
        sufficiency * DIMENSION_WEIGHTS["sufficiency"]
        + consistency * DIMENSION_WEIGHTS["consistency"]
        + quality * DIMENSION_WEIGHTS["quality"]
        + completeness * DIMENSION_WEIGHTS["completeness"]
    )
    return {
        "overall": round(overall, 3),
        "sufficiency": round(sufficiency, 3),
        "consistency": round(consistency, 3),
        "quality": round(quality, 3),
        "completeness": round(completeness, 3),
    }


def score_state(state: ScanState) -> dict[str, float]:
    if not state.controls:
        return {"overall": 0.0}
    scores = [score_control(c.id, state)["overall"] for c in state.controls]
    return {"overall": round(sum(scores) / len(scores), 3)}


def verdict_from_score(score: float, has_not_tested: bool) -> str:
    if has_not_tested and score < 0.6:
        return "Insufficient Evidence"
    if score >= 0.7:
        return "Compliant"
    if score >= 0.4:
        return "Insufficient Evidence"
    return "Non-Compliant"


def build_verdicts(state: ScanState, scores: dict[str, float]) -> list[Verdict]:
    now = expiry_from_now(0)
    expires = expiry_from_now(VERDICT_TTL_DAYS)
    verdicts: list[Verdict] = []
    for control in state.controls:
        control_scores = score_control(control.id, state)
        related = [c for c in state.check_results if control.id in c.finding_ids]
        has_not_tested = any(c.status == "not_tested" for c in related)
        verdict_label = verdict_from_score(control_scores["overall"], has_not_tested)
        if any(c.status == "fail" for c in related):
            verdict_label = "Non-Compliant"
        elif all(c.status == "pass" for c in related) and related:
            verdict_label = "Compliant"
        evidence_items: list[dict] = []
        for c in related:
            detail = dict(c.evidence_detail or {})
            detail.setdefault("test_name", get_check_name(c.check_id))
            detail["status"] = c.status
            detail["check_id"] = c.check_id  # internal only
            evidence_items.append(detail)
        evidence = [format_evidence_item(item) for item in evidence_items]
        standards = state.standards_mappings.get(control.id, control.standard_refs)
        verdicts.append(
            Verdict(
                control_id=control.id,
                verdict=verdict_label,
                score=control_scores["overall"],
                evidence_chain=evidence,
                evidence_items=evidence_items,
                standards=standards,
                last_verified_at=now,
                verdict_expires_at=expires,
            )
        )
    return verdicts
