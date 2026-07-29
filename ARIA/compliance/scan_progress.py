from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

DEFAULT_ESTIMATED_SECONDS = 50

AGENT_LABELS = {
    "system": "Orchestrator",
    "metrics": "Rhea · Metrics Agent",
    "dast": "Columbo · DAST Agent",
    "runtime": "Izzy · Runtime Agent",
    "standards": "Mike · Standards Agent",
    "judge": "Judy · Judge Agent",
    "collector": "Signal Collector",
    "disclosure": "Disclosure Evaluator",
    "reporter": "Report Generator",
}

PHASE_LABELS = {
    "starting": "Initializing scan",
    "collecting": "Collecting signals & running baseline tests",
    "orchestrating": "Multi-agent security analysis",
    "disclosure": "Evaluating disclosure gaps",
    "llm": "Generating gap analysis report",
    "saving": "Saving to local database",
    "done": "Scan complete",
}

_registry: dict[str, ScanProgressTracker] = {}
_registry_lock = threading.Lock()


@dataclass
class ScanProgressTracker:
    job_id: str
    status: str = "running"
    phase: str = "starting"
    percent: int = 1
    message: str = "Starting compliance scan…"
    current_agent: str = "system"
    activity_log: list[dict[str, str]] = field(default_factory=list)
    full_timeline: list[dict[str, Any]] = field(default_factory=list)
    agent_status: dict[str, str] = field(default_factory=dict)
    partial_state: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    result: dict[str, Any] | None = None
    started_at: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def advance(
        self,
        percent: int,
        message: str,
        *,
        agent: str | None = None,
        phase: str | None = None,
        step_type: str = "activity",
        detail: str | None = None,
    ) -> None:
        with self._lock:
            self.percent = min(99, max(self.percent, percent))
            self.message = message
            if phase:
                self.phase = phase
                self.agent_status["phase"] = phase
            agent_id = agent or self.current_agent
            if agent:
                self.current_agent = agent
                if self.agent_status.get(agent) != "done":
                    self.agent_status[agent] = "running"
            self._push_event(message, agent_id, step_type=step_type, detail=detail)

    def set_phase(self, phase: str, message: str = "", *, percent: int | None = None) -> None:
        self.advance(
            percent if percent is not None else self.percent,
            message or PHASE_LABELS.get(phase, phase),
            phase=phase,
        )

    def agent_start(self, agent: str, message: str, percent: int) -> None:
        with self._lock:
            self.agent_status[agent] = "running"
        self.advance(percent, message, agent=agent, phase="orchestrating", step_type="agent_start")

    def agent_done(self, agent: str, message: str, percent: int) -> None:
        with self._lock:
            self.agent_status[agent] = "done"
        self.advance(percent, message, agent=agent, step_type="agent_done")

    def check_progress(self, agent: str, check_name: str, index: int, total: int, base: int, span: int) -> None:
        if total <= 0:
            return
        pct = base + int(span * (index + 1) / total)
        self.advance(
            pct,
            f"{check_name}",
            agent=agent,
            phase="orchestrating",
            step_type="check_running",
            detail=f"Check {index + 1} of {total}",
        )

    def record_check(self, check_dict: dict[str, Any]) -> None:
        with self._lock:
            checks = self.partial_state.setdefault("check_results", [])
            by_id = {c.get("check_id"): i for i, c in enumerate(checks)}
            cid = check_dict.get("check_id")
            if cid in by_id:
                checks[by_id[cid]] = check_dict
            else:
                checks.append(check_dict)
            agent = check_dict.get("agent", "metrics")
            self._push_event(
                f"Completed: {check_dict.get('name') or cid}",
                agent,
                step_type="check_result",
                check_id=cid,
                check_name=check_dict.get("name"),
                status=check_dict.get("status"),
                detail=check_dict.get("evidence"),
            )

    def merge_state(self, state_dict: dict[str, Any]) -> None:
        with self._lock:
            for key, value in state_dict.items():
                if value is not None:
                    self.partial_state[key] = value

    def complete(self, result: dict[str, Any]) -> None:
        with self._lock:
            self.status = "completed"
            self.phase = "done"
            self.percent = 100
            self.message = "Scan finished — results saved to database"
            self.current_agent = "system"
            for agent_id in AGENT_LABELS:
                if self.agent_status.get(agent_id) != "idle":
                    self.agent_status[agent_id] = "done"
            self.agent_status["system"] = "done"
            self.agent_status["phase"] = "done"
            self.result = result
            self._push_event("Scan completed successfully", "system", step_type="complete")

    def fail(self, error: str) -> None:
        with self._lock:
            self.status = "failed"
            self.error = error
            self.message = error
            self._push_event(f"Failed: {error}", "system", step_type="error")

    def _push_event(
        self,
        message: str,
        agent_id: str,
        *,
        step_type: str = "activity",
        detail: str | None = None,
        check_id: str | None = None,
        check_name: str | None = None,
        status: str | None = None,
    ) -> None:
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "agent_id": agent_id,
            "agent": AGENT_LABELS.get(agent_id, agent_id),
            "message": message,
            "step_type": step_type,
            "detail": detail,
            "check_id": check_id,
            "check_name": check_name,
            "status": status,
        }
        self.full_timeline.append(entry)
        self.activity_log.append(
            {"time": entry["time"], "agent": entry["agent"], "message": message}
        )
        if len(self.activity_log) > 12:
            self.activity_log = self.activity_log[-12:]

    def eta_seconds(self) -> int:
        with self._lock:
            if self.status != "running":
                return 0
            elapsed = time.time() - self.started_at
            pct = max(self.percent, 1)
            estimated_total = elapsed / (pct / 100.0)
            remaining = max(0, int(estimated_total - elapsed))
            return min(remaining, 300)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            elapsed = int(time.time() - self.started_at)
            pct = self.percent
            if self.status == "running" and pct >= 1:
                eta = max(0, int(elapsed / (pct / 100.0) - elapsed))
                eta = min(eta, 300)
            elif self.status == "running":
                eta = DEFAULT_ESTIMATED_SECONDS
            else:
                eta = 0
            base = {
                "job_id": self.job_id,
                "status": self.status,
                "phase": self.phase,
                "phase_label": PHASE_LABELS.get(self.phase, self.phase),
                "percent": pct,
                "message": self.message,
                "current_agent": self.current_agent,
                "current_agent_label": AGENT_LABELS.get(self.current_agent, self.current_agent),
                "activity_log": list(self.activity_log),
                "full_timeline": list(self.full_timeline),
                "agent_status": dict(self.agent_status),
                "partial_state": dict(self.partial_state),
                "error": self.error,
                "result": self.result,
                "eta_seconds": eta,
                "elapsed_seconds": elapsed,
            }
            return base


def create_job() -> ScanProgressTracker:
    job = ScanProgressTracker(job_id=uuid.uuid4().hex[:12])
    job.advance(1, "Scan job queued", agent="system", phase="starting")
    with _registry_lock:
        _cleanup_old_jobs()
        _registry[job.job_id] = job
    return job


def get_job(job_id: str) -> ScanProgressTracker | None:
    with _registry_lock:
        return _registry.get(job_id)


def _cleanup_old_jobs(max_age_seconds: int = 3600) -> None:
    now = time.time()
    stale = [jid for jid, job in _registry.items() if now - job.started_at > max_age_seconds]
    for jid in stale:
        _registry.pop(jid, None)
