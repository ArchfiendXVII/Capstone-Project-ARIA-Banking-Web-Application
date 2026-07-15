from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from compliance.config import OPENAI_API_KEY, OPENAI_MODEL
from compliance.report_builder import build_professional_report, build_report_sections


class MissingAPIKeyError(RuntimeError):
    pass


@dataclass
class LLMReport:
    markdown: str
    sections: dict[str, Any]
    model: str
    html: str = ""
    executive_summary: str = ""


def _require_api_key() -> str:
    if not OPENAI_API_KEY:
        raise MissingAPIKeyError(
            "OPENAI_API_KEY is required to generate compliance reports. "
            "Set it in your environment or .env file."
        )
    return OPENAI_API_KEY


def _build_prompt(state_json: str) -> str:
    return f"""You are Judy, a senior security consultant writing a professional gap analysis for ARIA Bank.

Produce a JSON object with these keys:
- executive_summary: 2-3 paragraphs in plain English for bank leadership (risk, business impact, top 3 priorities)
- risk_narrative: 1 paragraph explaining overall posture
- top_recommendations: array of 5 specific, actionable remediation items ordered by priority
- finding_impacts: object mapping control_id (F-01..F-18) to 2-3 sentence business/technical impact paragraph
- markdown_addendum: optional markdown section "## Consultant Notes" with additional context (or empty string)

Rules:
- Do NOT contradict deterministic verdicts or check statuses in the input
- Write like a bug bounty or Big-4 gap analysis report — clear, professional, no jargon without explanation
- Reference specific control IDs (F-xx) and check IDs (AC-xx, TC-xx) where relevant
- Note F-18 transfer improvements where checks pass, and remaining gaps where they fail

Input scan state:
{state_json[:14000]}
"""


def generate_report(
    state_dict: dict[str, Any],
    *,
    client: Any | None = None,
    scan_id: int | None = None,
    report_id: int | None = None,
) -> LLMReport:
    base_markdown = build_professional_report(state_dict, scan_id=scan_id, report_id=report_id)
    sections = build_report_sections(state_dict)
    prompt = _build_prompt(json.dumps(state_dict, indent=2))

    llm_sections: dict[str, Any] = {}
    model = OPENAI_MODEL

    if client is not None:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior banking security and compliance consultant producing executive-ready gap analysis narratives.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        model = getattr(response, "model", OPENAI_MODEL)
        llm_sections = json.loads(content)
    else:
        api_key = _require_api_key()
        from openai import OpenAI

        openai_client = OpenAI(api_key=api_key)
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior banking security and compliance consultant producing executive-ready gap analysis narratives.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        model = response.model
        llm_sections = json.loads(content)

    markdown = _merge_report(base_markdown, llm_sections, state_dict)
    executive = llm_sections.get("executive_summary", "")
    if isinstance(executive, list):
        executive = "\n\n".join(executive)
    sections.update(llm_sections)

    import markdown as md_lib

    html = md_lib.markdown(markdown, extensions=["tables", "fenced_code", "nl2br"])

    return LLMReport(
        markdown=markdown,
        sections=sections,
        model=model,
        html=html,
        executive_summary=str(executive),
    )


def _merge_report(base: str, llm: dict[str, Any], state_dict: dict[str, Any]) -> str:
    """Insert LLM narrative into the structured report."""
    exec_text = llm.get("executive_summary", "")
    if isinstance(exec_text, list):
        exec_text = "\n\n".join(exec_text)

    parts = [base]

    if exec_text:
        insert = (
            "\n\n### 1.2 Consultant executive narrative\n\n"
            + exec_text
            + "\n"
        )
        parts[0] = base.replace(
            "### 1.1 Business impact (plain language)",
            insert + "### 1.1 Business impact (plain language)",
            1,
        )

    risk = llm.get("risk_narrative")
    if risk:
        parts[0] = parts[0].replace(
            "---\n\n## 2. Key Performance Indicators",
            f"### 1.3 Overall risk narrative\n\n{risk}\n\n---\n\n## 2. Key Performance Indicators",
            1,
        )

    impacts = llm.get("finding_impacts") or {}
    if impacts:
        extra = ["\n\n## 4.1 Business impact by finding (consultant analysis)\n"]
        for cid in sorted(impacts.keys()):
            extra.append(f"**{cid}:** {impacts[cid]}\n")
        marker = "## 5. Disclosure Gaps"
        parts[0] = parts[0].replace(marker, "\n".join(extra) + "\n" + marker, 1)

    recs = llm.get("top_recommendations")
    if recs:
        rec_block = "\n\n## 8. Prioritized Remediation Roadmap\n\n"
        for i, rec in enumerate(recs, 1):
            rec_block += f"{i}. {rec}\n"
        addendum = llm.get("markdown_addendum", "")
        if addendum:
            rec_block += f"\n{addendum}\n"
        parts[0] = parts[0].replace(
            "*End of report — generated by ARIA Bank Compliance Monitor (Milestone 7).*",
            rec_block + "\n*End of report — generated by ARIA Bank Compliance Monitor (Milestone 7).*",
        )

    return parts[0]
