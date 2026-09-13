from __future__ import annotations

from guardrails.response_guard import (
    ResponseGuardResult,
)


SECTION_TITLES = {
    "fact": "已确认事实",
    "hypothesis": "推断",
    "recommendation": "建议",
    "unknown": "待确认",
}


def render_guarded_response(
    guard_result: ResponseGuardResult,
) -> str:
    grouped: dict[str, list[str]] = {
        "fact": [],
        "hypothesis": [],
        "recommendation": [],
        "unknown": [],
    }

    for item in guard_result.claims:
        if item.decision != "accepted":
            continue

        claim_type = item.claim.type
        text = item.claim.text.strip()

        if not text:
            continue

        if text not in grouped[claim_type]:
            grouped[claim_type].append(text)

    sections: list[str] = []

    for claim_type in (
        "fact",
        "hypothesis",
        "recommendation",
        "unknown",
    ):
        items = grouped[claim_type]
        if not items:
            continue

        lines = [
            f"### {SECTION_TITLES[claim_type]}"
        ]
        lines.extend(
            f"- {text}"
            for text in items
        )
        sections.append("\n".join(lines))

    if not sections:
        return (
            "当前证据不足，暂时无法给出"
            "经过验证的确定结论。"
        )

    return "\n\n".join(sections)
