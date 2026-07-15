from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from compliance.config import LOGS_DIR


def _log_path() -> Path:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR / "compliance_events.jsonl"


def log_event(event_type: str, payload: dict[str, Any]) -> None:
    record = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event_type": event_type,
        "payload": payload,
    }
    with _log_path().open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def log_check_failure(check_id: str, status: str, evidence: str, finding_ids: list[str]) -> None:
    log_event(
        "COMPLIANCE_CHECK_FAILURE",
        {
            "check_id": check_id,
            "status": status,
            "evidence": evidence[:500],
            "finding_ids": finding_ids,
        },
    )
