from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class ControlDefinition:
    id: str
    title: str
    risk: str
    claim: str
    standard_refs: list[str]
    gap_ids: list[str] = field(default_factory=list)
    check_ids: list[str] = field(default_factory=list)
    assigned_agents: list[str] = field(default_factory=list)
    priority: str = "medium"


@dataclass
class CheckResult:
    check_id: str
    status: str  # pass | fail | partial | not_tested
    evidence: str
    finding_ids: list[str] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)
    source_weight: float = 0.8
    agent: str = "metrics"
    evidence_detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReinvestigationRequest:
    control_id: str
    gap: str
    refined_query: str
    requested_agent: str
    check_ids: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    control_id: str
    verdict: str  # Compliant | Non-Compliant | Insufficient Evidence
    score: float
    evidence_chain: list[str]
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)
    last_verified_at: str = ""
    verdict_expires_at: str = ""


@dataclass
class ScanState:
    scan_id: str
    scan_type: str = "manual"
    controls: list[ControlDefinition] = field(default_factory=list)
    routing_plan: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    check_results: list[CheckResult] = field(default_factory=list)
    kpi_snapshot: dict[str, Any] = field(default_factory=dict)
    audit_summary: dict[str, Any] = field(default_factory=dict)
    tool_results: dict[str, Any] = field(default_factory=dict)
    standards_mappings: dict[str, list[str]] = field(default_factory=dict)
    verdicts: list[Verdict] = field(default_factory=list)
    reinvestigation_requests: list[ReinvestigationRequest] = field(default_factory=list)
    disclosure_gaps: list[dict[str, Any]] = field(default_factory=list)
    iteration_count: int = 0
    previous_scan_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "controls": [asdict(c) for c in self.controls],
            "routing_plan": self.routing_plan,
            "findings": self.findings,
            "check_results": [asdict(c) for c in self.check_results],
            "kpi_snapshot": self.kpi_snapshot,
            "audit_summary": self.audit_summary,
            "tool_results": self.tool_results,
            "standards_mappings": self.standards_mappings,
            "verdicts": [asdict(v) for v in self.verdicts],
            "reinvestigation_requests": [asdict(r) for r in self.reinvestigation_requests],
            "disclosure_gaps": self.disclosure_gaps,
            "iteration_count": self.iteration_count,
            "previous_scan_id": self.previous_scan_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def new_scan_id() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def expiry_from_now(days: int) -> str:
    return (datetime.utcnow() + timedelta(days=days)).isoformat(timespec="seconds")
