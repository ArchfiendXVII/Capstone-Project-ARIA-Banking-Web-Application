from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def find_line_number(source: str, pattern: str) -> int | None:
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(pattern, line):
            return i
    return None


def snippet_at_line(source: str, line_no: int | None, context: int = 0) -> str | None:
    if not line_no:
        return None
    lines = source.splitlines()
    idx = line_no - 1
    if idx < 0 or idx >= len(lines):
        return None
    start = max(0, idx - context)
    end = min(len(lines), idx + context + 1)
    return "\n".join(lines[start:end])


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def build_evidence(
    *,
    test_name: str,
    method: str,
    observation: str,
    location: str,
    file: str | None = None,
    line: int | None = None,
    route: str | None = None,
    database: str | None = None,
    table: str | None = None,
    snippet: str | None = None,
    tool: str | None = None,
    request_detail: str | None = None,
    result_detail: str | None = None,
    execution_trace: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "test_name": test_name,
        "method": method,
        "observation": observation,
        "location": location,
        "file": file,
        "line": line,
        "route": route,
        "database": database,
        "table": table,
        "snippet": snippet,
        "tool": tool,
        "request_detail": request_detail,
        "result_detail": result_detail,
    }
    if execution_trace:
        out["execution_trace"] = execution_trace
    return out


def format_evidence_item(item: dict[str, Any]) -> str:
    """Single human-readable block for reports."""
    lines = [
        f"**{item.get('test_name', 'Security check')}** — {item.get('status', 'unknown').upper()}",
        f"- **How tested:** {item.get('method', '—')}",
        f"- **Where:** {_where_string(item)}",
        f"- **What we found:** {item.get('observation', '—')}",
    ]
    if item.get("request_detail"):
        lines.append(f"- **Request / action:** {item['request_detail']}")
    if item.get("result_detail"):
        lines.append(f"- **Result:** {item['result_detail']}")
    if item.get("snippet"):
        lines.append(f"- **Source excerpt (`{item.get('file', 'file')}`):**\n```\n{item['snippet']}\n```")
    return "\n".join(lines)


def _where_string(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("file"):
        loc = item["file"]
        if item.get("line"):
            loc += f":{item['line']}"
        parts.append(loc)
    if item.get("route"):
        parts.append(f"HTTP route {item['route']}")
    if item.get("database"):
        db = item["database"]
        if item.get("table"):
            db += f" → table `{item['table']}`"
        parts.append(f"Database {db}")
    if item.get("location") and not parts:
        parts.append(item["location"])
    if item.get("tool"):
        parts.append(f"via {item['tool']}")
    return " · ".join(parts) if parts else item.get("location", "Application")
