#!/usr/bin/env python3
"""Export audit and compliance logs to JSON Lines for SIEM ingestion."""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE_DIR / "aria_bank.db"
COMPLIANCE_LOG = BASE_DIR / "logs" / "compliance_events.jsonl"


def export_logs(db_path: Path, output: Path) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    count = 0
    with output.open("w", encoding="utf-8") as out:
        for row in conn.execute("SELECT * FROM audit_logs ORDER BY id"):
            record = {"source": "audit_logs", **dict(row)}
            out.write(json.dumps(record, default=str) + "\n")
            count += 1
        for row in conn.execute("SELECT * FROM compliance_scans ORDER BY id"):
            record = {"source": "compliance_scans", **dict(row)}
            out.write(json.dumps(record, default=str) + "\n")
            count += 1
        if COMPLIANCE_LOG.exists():
            for line in COMPLIANCE_LOG.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.write(line.strip() + "\n")
                    count += 1
    conn.close()
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ARIA SIEM logs")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--output", default=str(BASE_DIR / "reports" / f"siem_export_{datetime.utcnow():%Y%m%d_%H%M%S}.jsonl"))
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    n = export_logs(Path(args.db), output)
    print(f"Exported {n} records to {output}")


if __name__ == "__main__":
    main()
