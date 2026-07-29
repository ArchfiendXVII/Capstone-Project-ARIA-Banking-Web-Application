from __future__ import annotations

import json

from compliance.config import DATA_DIR
from compliance.state import ControlDefinition, ScanState


def _load_corpus() -> list[dict]:
    path = DATA_DIR / "standards_corpus.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _keywords_for_control(control: ControlDefinition) -> set[str]:
    words = set(control.title.lower().split())
    words.update(control.claim.lower().split())
    for ref in control.standard_refs:
        words.update(ref.lower().split())
    return words


class StandardsAgent:
    name = "standards"

    def run(self, state: ScanState, ctx: dict) -> ScanState:
        corpus = _load_corpus()
        mappings: dict[str, list[str]] = {}
        for control in state.controls:
            keywords = _keywords_for_control(control)
            excerpts: list[str] = []
            for chunk in corpus:
                if control.id in chunk.get("finding_ids", []):
                    excerpts.append(f"{chunk['framework']} {chunk['topic']}: {chunk['text']}")
                    continue
                hay = " ".join(chunk.get("keywords", [])).lower()
                if any(k in hay for k in keywords if len(k) > 3):
                    excerpts.append(f"{chunk['framework']} {chunk['topic']}: {chunk['text']}")
            mappings[control.id] = excerpts[:3]
        state.standards_mappings = mappings
        state.tool_results["standards"] = {"controls_mapped": len(mappings)}
        return state


standards_agent = StandardsAgent()
