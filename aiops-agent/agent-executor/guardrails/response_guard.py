from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from guardrails.claim_compiler import (
    build_evidence_catalog,
)
from guardrails.models import (
    Claim,
    ClaimEnvelope,
    EvidenceRecord,
    utc_now,
)


GuardDecision = Literal[
    "accepted",
    "rejected",
]


class GuardedClaim(BaseModel):
    claim: Claim
    decision: GuardDecision
    valid_evidence_ids: list[str] = Field(
        default_factory=list
    )
    violations: list[str] = Field(
        default_factory=list
    )


class ResponseGuardResult(BaseModel):
    claims: list[GuardedClaim] = Field(
        default_factory=list
    )
    accepted_count: int = 0
    rejected_count: int = 0


def resolve_field_path(
    data: Any,
    field_path: str,
) -> Any:
    normalized_path = field_path.strip()

    if normalized_path.startswith("data."):
        normalized_path = normalized_path[5:]



    normalized_path = re.sub(
        r"\[(\d+)\]",
        r".\1",
        normalized_path,
    ).strip(".")

    if not normalized_path:
        return data

    current = data

    for part in normalized_path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise KeyError(field_path)
            current = current[part]
            continue

        if isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index]
            continue

        raise KeyError(field_path)

    return current


def values_match(
    actual: Any,
    expected: Any,
) -> bool:
    numeric_types = (int, float)

    if (
        isinstance(actual, numeric_types)
        and not isinstance(actual, bool)
        and isinstance(expected, numeric_types)
        and not isinstance(expected, bool)
    ):
        return math.isclose(
            float(actual),
            float(expected),
            rel_tol=1e-6,
            abs_tol=1e-9,
        )

    return actual == expected


def claim_contains_number(text: str) -> bool:
    return bool(
        re.search(
            r"(?<![\w.])-?\d+(?:\.\d+)?",
            text,
        )
    )


def build_evidence_ledger(
    tool_results: list[dict[str, Any]],
) -> dict[str, EvidenceRecord]:
    ledger: dict[str, EvidenceRecord] = {}

    for item in build_evidence_catalog(tool_results):
        try:
            evidence = EvidenceRecord.model_validate(
                item
            )
        except Exception:
            continue

        ledger[evidence.evidence_id] = evidence

    return ledger


def validate_claims(
    envelope: ClaimEnvelope,
    tool_results: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> ResponseGuardResult:
    current_time = now or utc_now()
    ledger = build_evidence_ledger(tool_results)
    guarded_claims: list[GuardedClaim] = []

    for claim in envelope.claims:
        violations: list[str] = []
        valid_evidence_ids: list[str] = []

        if claim.type == "fact" and not claim.evidence_refs:
            violations.append(
                "fact_missing_evidence"
            )

        for evidence_ref in claim.evidence_refs:
            evidence = ledger.get(
                evidence_ref.evidence_id
            )

            if evidence is None:
                violations.append(
                    "evidence_not_found:"
                    f"{evidence_ref.evidence_id}"
                )
                continue

            requires_success = claim.type in {
                "fact",
                "hypothesis",
            }

            if (
                requires_success
                and evidence.status != "success"
            ):
                violations.append(
                    "evidence_not_success:"
                    f"{evidence_ref.evidence_id}"
                )
                continue

            if (
                requires_success
                and not evidence.is_fresh(current_time)
            ):
                violations.append(
                    "evidence_expired:"
                    f"{evidence_ref.evidence_id}"
                )
                continue

            if evidence_ref.field_path:
                try:
                    actual_value = resolve_field_path(
                        evidence.data,
                        evidence_ref.field_path,
                    )
                except (KeyError, IndexError):
                    violations.append(
                        "field_not_found:"
                        f"{evidence_ref.field_path}"
                    )
                    continue

                if (
                    evidence_ref.expected_value is not None
                    and not values_match(
                        actual_value,
                        evidence_ref.expected_value,
                    )
                ):
                    violations.append(
                        "value_mismatch:"
                        f"{evidence_ref.field_path}"
                    )
                    continue

            elif (
                claim.type == "fact"
                and evidence_ref.expected_value is not None
            ):
                violations.append(
                    "numeric_reference_missing_field"
                )
                continue

            valid_evidence_ids.append(
                evidence.evidence_id
            )

        if (
            claim.type == "fact"
            and claim_contains_number(claim.text)
            and not any(
                ref.expected_value is not None
                for ref in claim.evidence_refs
            )
        ):
            violations.append(
                "numeric_claim_missing_value_reference"
            )

        decision: GuardDecision = "accepted"


        if claim.type == "fact" and violations:
            decision = "rejected"

        guarded_claims.append(
            GuardedClaim(
                claim=claim,
                decision=decision,
                valid_evidence_ids=(
                    valid_evidence_ids
                ),
                violations=violations,
            )
        )

    return ResponseGuardResult(
        claims=guarded_claims,
        accepted_count=sum(
            item.decision == "accepted"
            for item in guarded_claims
        ),
        rejected_count=sum(
            item.decision == "rejected"
            for item in guarded_claims
        ),
    )
