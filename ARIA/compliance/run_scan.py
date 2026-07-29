from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from compliance.config import DEFAULT_DB_PATH
from compliance.llm_reporter import MissingAPIKeyError
from compliance.scan_service import run_scan


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run ARIA Bank compliance scan")
    parser.add_argument("--type", choices=["manual", "scheduled"], default="manual")
    parser.add_argument("--json", action="store_true", help="Print result JSON to stdout")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    args = parser.parse_args(argv)

    try:
        result = run_scan(db_path=Path(args.db), scan_type=args.type)
    except MissingAPIKeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": result.scan_id,
                    "report_id": result.report_id,
                    "markdown_path": str(result.markdown_path),
                    "partial_checks": result.partial_checks,
                    "iteration_count": result.state.iteration_count,
                },
                indent=2,
            )
        )
    else:
        print(f"Compliance scan completed. scan_id={result.scan_id} report_id={result.report_id}")
        print(f"Report written to {result.markdown_path}")

    return 3 if result.partial_checks else 0


if __name__ == "__main__":
    raise SystemExit(main())
