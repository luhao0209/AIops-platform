from __future__ import annotations

import os
from typing import Any

from alerting.capacity_skill_contract import (
    ACTIVATE_CAPACITY_SKILL_TOOL,
    CAPACITY_SCALING_SKILL,
    CAPACITY_SKILL_INSTRUCTIONS,
    REQUEST_SCALE_APPROVAL_TOOL,
)
from alerting.release_skill_contract import (
    ACTIVATE_RELEASE_SKILL_TOOL,
    RELEASE_REGRESSION_SKILL,
    RELEASE_SKILL_INSTRUCTIONS,
    REQUEST_ROLLBACK_APPROVAL_TOOL,
)


def _successful_tool_events(events: list[Any], tool_names: set[str]) -> list[Any]:
    matched: list[Any] = []
    for event in events:
        if getattr(event, "event_type", "") != "tool_result":
            continue
        if getattr(event, "tool_name", "") not in tool_names:
            continue
        evidence = getattr(event, "evidence", {})
        if not isinstance(evidence, dict) or evidence.get("status") != "success":
            continue
        if evidence.get("query_outcome") in {"failed", "timeout", "no_match", "no_data"}:
            continue
        matched.append(event)
    return matched


def _change_items(event: Any) -> list[dict[str, Any]]:
    evidence = getattr(event, "evidence", {})
    compact = evidence.get("compact_result") if isinstance(evidence, dict) else {}
    if not isinstance(compact, dict):
        return []
    return [item for item in compact.get("items", []) if isinstance(item, dict)]


def _release_change_matches(event: Any, namespace: str, target_name: str) -> bool:
    for item in _change_items(event):
        item_namespace = str(item.get("namespace") or "").strip()
        item_target = str(item.get("resource_name") or "").strip()
        event_type = str(item.get("event_type") or "").lower()
        summary = str(item.get("summary") or "").lower()
        if item_namespace and item_namespace != namespace:
            continue
        if item_target and item_target != target_name:
            continue
        if event_type == "image" or "镜像" in summary or "image" in summary:
            return True
    return False


def _active_skill_event(events: list[Any]) -> Any | None:
    for event in reversed(events):
        if getattr(event, "event_type", "") != "skill_selected":
            continue
        evidence = getattr(event, "evidence", {})
        if isinstance(evidence, dict) and evidence.get("skill_name") == RELEASE_REGRESSION_SKILL:
            return event
    return None


def _active_capacity_skill_event(events: list[Any]) -> Any | None:
    for event in reversed(events):
        if getattr(event, "event_type", "") != "skill_selected":
            continue
        evidence = getattr(event, "evidence", {})
        if (
            isinstance(evidence, dict)
            and evidence.get("skill_name") == CAPACITY_SCALING_SKILL
        ):
            return event
    return None


def _latest_observed_replicas(
    events: list[Any],
    *,
    namespace: str,
    target_name: str,
) -> int | None:
    for event in reversed(events):
        if getattr(event, "tool_name", "") != "get_deployment_status":
            continue
        evidence = getattr(event, "evidence", {})
        compact = evidence.get("compact_result") if isinstance(evidence, dict) else {}
        if not isinstance(compact, dict):
            continue
        if str(compact.get("namespace") or "").strip() != namespace:
            continue
        if str(compact.get("deployment_name") or "").strip() != target_name:
            continue
        value = compact.get("desired_replicas")
        if isinstance(value, (int, float)):
            return int(value)
    return None


def _latest_safe_node_headroom_event(
    events: list[Any],
    *,
    scheduled_nodes: list[str],
) -> tuple[Any | None, str]:
    """Find fresh node evidence that shows room for one additional replica."""
    normalized_nodes = {
        str(item or "").strip() for item in scheduled_nodes if str(item or "").strip()
    }
    if not normalized_nodes:
        return None, "deployment_scheduled_nodes"

    observed_node_evidence = False
    for event in reversed(events):
        if getattr(event, "tool_name", "") != "get_infrastructure_saturation":
            continue
        evidence = getattr(event, "evidence", {})
        if not isinstance(evidence, dict) or evidence.get("status") != "success":
            continue
        compact = evidence.get("compact_result") or {}
        if not isinstance(compact, dict) or compact.get("component_type") != "node":
            continue
        target_name = str(compact.get("target_name") or "").strip()
        if target_name and target_name not in normalized_nodes:
            continue
        items = compact.get("items") or []
        matched_items = [
            item
            for item in items
            if isinstance(item, dict)
            and (
                (target_name and target_name in str(item.get("instance") or ""))
                or (
                    not target_name
                    and any(
                        node in str(item.get("instance") or "")
                        for node in normalized_nodes
                    )
                )
            )
        ]
        if not matched_items:
            continue
        observed_node_evidence = True
        for item in matched_items:
            cpu = item.get("cpu_usage_percent")
            memory = item.get("memory_used_percent")
            disk = item.get("disk_used_percent")
            if not all(isinstance(value, (int, float)) for value in (cpu, memory, disk)):
                return None, "node_resource_headroom_incomplete"
            if float(cpu) >= 80 or float(memory) >= 85 or float(disk) >= 90:
                return None, "node_resource_headroom_insufficient"
        return event, ""

    return (
        None,
        "node_resource_headroom_unavailable"
        if observed_node_evidence
        else "node_resource_headroom",
    )


def activate_release_regression_skill(
    incident_id: str,
    reason: str,
) -> dict[str, Any]:
    """Activate a trusted workflow after the model finds release evidence."""
    from memory import IncidentAnalysisStore, IncidentMemoryStore

    incident_store = IncidentMemoryStore()
    analysis_store = IncidentAnalysisStore()
    incident = incident_store.get((incident_id or "").strip())
    if incident is None:
        return {"error": "incident not found"}
    if incident.status != "firing":
        return {"error": "resolved incidents cannot activate a skill"}

    run = analysis_store.get_run_by_incident(incident.incident_id)
    if run is None:
        return {"error": "incident analysis has not started"}
    events = analysis_store.list_events(run.analysis_id, limit=1000)
    existing = _active_skill_event(events)
    if existing is not None:
        return {
            "status": "active",
            "created": False,
            "skill_name": RELEASE_REGRESSION_SKILL,
            "instructions": RELEASE_SKILL_INSTRUCTIONS,
        }

    change_events = _successful_tool_events(events, {"search_change_events"})
    supporting = [
        event
        for event in change_events
        if _release_change_matches(
            event,
            incident.namespace,
            incident.target,
        )
    ]
    if not supporting:
        return {
            "error": "release evidence is incomplete",
            "missing_evidence": ["matching_image_change"],
        }

    normalized_reason = " ".join((reason or "").split())[:500]
    if len(normalized_reason) < 20:
        return {"error": "skill activation reason must be specific"}

    event = analysis_store.append_event(
        run.analysis_id,
        "skill_selected",
        "启用发版回归分析 Skill",
        content_md=(
            "初步证据指向近期发布，已进入 `release_regression` Skill 继续核对。"
            f"当前理由：{normalized_reason}"
        ),
        round_index=run.current_round,
        evidence={
            "skill_name": RELEASE_REGRESSION_SKILL,
            "status": "active",
            "reason": normalized_reason,
            "evidence_refs": [item.event_id for item in supporting],
        },
    )
    return {
        "status": "active",
        "created": True,
        "skill_name": RELEASE_REGRESSION_SKILL,
        "skill_event_id": event.event_id,
        "instructions": RELEASE_SKILL_INSTRUCTIONS,
    }


def activate_capacity_scaling_skill(
    incident_id: str,
    reason: str,
) -> dict[str, Any]:
    """Activate the capacity workflow after general investigation."""
    from memory import IncidentAnalysisStore, IncidentMemoryStore

    incident_store = IncidentMemoryStore()
    analysis_store = IncidentAnalysisStore()
    incident = incident_store.get((incident_id or "").strip())
    if incident is None:
        return {"error": "incident not found"}
    if incident.status != "firing":
        return {"error": "resolved incidents cannot activate a skill"}

    run = analysis_store.get_run_by_incident(incident.incident_id)
    if run is None:
        return {"error": "incident analysis has not started"}
    events = analysis_store.list_events(run.analysis_id, limit=1000)
    existing = _active_capacity_skill_event(events)
    if existing is not None:
        return {
            "status": "active",
            "created": False,
            "skill_name": CAPACITY_SCALING_SKILL,
            "instructions": CAPACITY_SKILL_INSTRUCTIONS,
        }

    impact_events = _successful_tool_events(
        events,
        {"get_metric_trend", "get_service_golden_signals"},
    )
    deployment_events = _successful_tool_events(
        events,
        {"get_deployment_status"},
    )
    business_events = _successful_tool_events(
        events,
        {"get_business_overview"},
    )
    missing: list[str] = []
    if not impact_events:
        missing.append("traffic_or_latency_evidence")
    if not deployment_events:
        missing.append("deployment_replica_state")
    if (
        incident.alert_name == "GatewayCapacitySaturation"
        and not any(
            float(
                (
                    getattr(event, "evidence", {}).get(
                        "compact_result", {}
                    )
                    or {}
                ).get("raw_total_count")
                or 0
            )
            > 0
            for event in business_events
        )
    ):
        missing.append("real_order_business_traffic")
    if missing:
        return {
            "error": "capacity evidence is incomplete",
            "missing_evidence": missing,
        }

    normalized_reason = " ".join((reason or "").split())[:500]
    if len(normalized_reason) < 20:
        return {"error": "skill activation reason must be specific"}

    supporting = [
        *impact_events[-2:],
        *business_events[-1:],
        *deployment_events[-1:],
    ]
    event = analysis_store.append_event(
        run.analysis_id,
        "skill_selected",
        "启用容量扩展分析 Skill",
        content_md=(
            "初步证据指向网关实例容量不足，已进入 `capacity_scaling` Skill继续核对。"
            f"当前理由：{normalized_reason}"
        ),
        round_index=run.current_round,
        evidence={
            "skill_name": CAPACITY_SCALING_SKILL,
            "status": "active",
            "reason": normalized_reason,
            "evidence_refs": [item.event_id for item in supporting],
        },
    )
    return {
        "status": "active",
        "created": True,
        "skill_name": CAPACITY_SCALING_SKILL,
        "skill_event_id": event.event_id,
        "instructions": CAPACITY_SKILL_INSTRUCTIONS,
    }


def _pair_supported_by_change(
    events: list[Any],
    *,
    namespace: str,
    target_name: str,
    current_image: str,
    target_image: str,
) -> bool:
    for event in events:
        if getattr(event, "tool_name", "") != "search_change_events":
            continue
        for item in _change_items(event):
            if str(item.get("namespace") or "").strip() not in {"", namespace}:
                continue
            if str(item.get("resource_name") or "").strip() not in {"", target_name}:
                continue
            before_value = str(item.get("before_value") or "")
            after_value = str(item.get("after_value") or "")
            summary = str(item.get("summary") or "")
            if (
                target_image in before_value
                and current_image in after_value
            ) or (
                target_image in summary
                and current_image in summary
            ):
                return True
    return False


def request_rollback_approval(
    incident_id: str,
    namespace: str,
    deployment_name: str,
    container_name: str,
    current_image: str,
    target_image: str,
    reason: str,
    risk: str,
    expected_outcome: str,
    verification: list[str],
) -> dict[str, Any]:
    """Create an approval request; this function never mutates Kubernetes."""
    from memory import IncidentAnalysisStore, IncidentMemoryStore, RemediationStore

    incident_store = IncidentMemoryStore()
    analysis_store = IncidentAnalysisStore()
    remediation_store = RemediationStore()
    incident = incident_store.get((incident_id or "").strip())
    if incident is None:
        return {"error": "incident not found"}
    if incident.status != "firing":
        return {"error": "resolved incidents cannot request remediation"}

    run = analysis_store.get_run_by_incident(incident.incident_id)
    if run is None:
        return {"error": "incident analysis has not started"}
    events = analysis_store.list_events(run.analysis_id, limit=1000)
    if _active_skill_event(events) is None:
        return {"error": "release_regression skill is not active"}

    normalized_namespace = (namespace or "").strip()
    normalized_target = (deployment_name or "").strip()
    if normalized_namespace != incident.namespace or normalized_target != incident.target:
        return {"error": "rollback target does not match the Incident target"}

    impact_events = _successful_tool_events(
        events,
        {"get_metric_trend", "get_business_overview"},
    )
    log_events = _successful_tool_events(events, {"search_logs"})
    change_events = _successful_tool_events(events, {"search_change_events"})
    missing: list[str] = []
    if not impact_events:
        missing.append("impact_metric")
    if not any(
        (getattr(event, "evidence", {}).get("compact_result") or {}).get("samples")
        for event in log_events
    ):
        missing.append("error_logs")
    if not any(
        _release_change_matches(event, normalized_namespace, normalized_target)
        for event in change_events
    ):
        missing.append("image_change")
    if missing:
        return {"error": "required evidence is incomplete", "missing_evidence": missing}

    normalized_current_image = (current_image or "").strip()
    normalized_target_image = (target_image or "").strip()
    if not normalized_current_image or not normalized_target_image:
        return {"error": "current_image and target_image are required"}
    if normalized_current_image == normalized_target_image:
        return {"error": "rollback images must be different"}
    if not _pair_supported_by_change(
        change_events,
        namespace=normalized_namespace,
        target_name=normalized_target,
        current_image=normalized_current_image,
        target_image=normalized_target_image,
    ):
        return {"error": "the proposed rollback pair is not supported by change evidence"}

    normalized_reason = " ".join((reason or "").split())[:500]
    normalized_risk = " ".join((risk or "").split())[:300]
    normalized_outcome = " ".join((expected_outcome or "").split())[:300]
    checks = [" ".join(str(item).split())[:160] for item in verification if str(item).strip()][:6]
    if len(normalized_reason) < 20 or len(normalized_risk) < 5 or len(normalized_outcome) < 10:
        return {"error": "reason, risk and expected_outcome must be specific"}
    if not checks:
        return {"error": "at least one verification item is required"}

    evidence_refs = list(
        dict.fromkeys(
            [
                *(event.event_id for event in impact_events[-2:]),
                *(event.event_id for event in log_events[-2:]),
                *(event.event_id for event in change_events[-2:]),
            ]
        )
    )
    action, created = remediation_store.create_request(
        incident_id=incident.incident_id,
        analysis_id=run.analysis_id,
        skill_name=RELEASE_REGRESSION_SKILL,
        namespace=normalized_namespace,
        target_name=normalized_target,
        container_name=(container_name or "").strip(),
        current_image=normalized_current_image,
        target_image=normalized_target_image,
        reason=normalized_reason,
        risk=normalized_risk,
        expected_outcome=normalized_outcome,
        verification=checks,
        evidence_refs=evidence_refs,
    )
    return {
        "status": action.status,
        "created": created,
        "action": action.model_dump(mode="json"),
    }


def request_scale_approval(
    incident_id: str,
    namespace: str,
    deployment_name: str,
    current_replicas: int,
    target_replicas: int,
    reason: str,
    risk: str,
    expected_outcome: str,
    verification: list[str],
) -> dict[str, Any]:
    """Create a one-replica scale-out approval; never mutate Kubernetes."""
    from memory import IncidentAnalysisStore, IncidentMemoryStore, RemediationStore

    incident_store = IncidentMemoryStore()
    analysis_store = IncidentAnalysisStore()
    remediation_store = RemediationStore()
    incident = incident_store.get((incident_id or "").strip())
    if incident is None:
        return {"error": "incident not found"}
    if incident.status != "firing":
        return {"error": "resolved incidents cannot request remediation"}

    run = analysis_store.get_run_by_incident(incident.incident_id)
    if run is None:
        return {"error": "incident analysis has not started"}
    events = analysis_store.list_events(run.analysis_id, limit=1000)
    if _active_capacity_skill_event(events) is None:
        return {"error": "capacity_scaling skill is not active"}

    normalized_namespace = (namespace or "").strip()
    normalized_target = (deployment_name or "").strip()
    if (
        normalized_namespace != incident.namespace
        or normalized_target != incident.target
    ):
        return {"error": "scale target does not match the Incident target"}

    trend_events = _successful_tool_events(events, {"get_metric_trend"})
    signal_events = _successful_tool_events(
        events,
        {"get_service_golden_signals"},
    )
    deployment_events = _successful_tool_events(
        events,
        {"get_deployment_status"},
    )
    business_events = _successful_tool_events(
        events,
        {"get_business_overview"},
    )
    missing: list[str] = []
    if not trend_events:
        missing.append("sustained_metric_impact")
    if not signal_events:
        missing.append("traffic_and_service_signals")
    if not deployment_events:
        missing.append("deployment_replica_state")
    if (
        incident.alert_name == "GatewayCapacitySaturation"
        and not any(
            float(
                (
                    getattr(event, "evidence", {}).get(
                        "compact_result", {}
                    )
                    or {}
                ).get("raw_total_count")
                or 0
            )
            > 0
            for event in business_events
        )
    ):
        missing.append("real_order_business_traffic")
    signal_compacts = [
        getattr(event, "evidence", {}).get("compact_result", {})
        for event in signal_events
    ]
    if signal_events and not any(
        isinstance(item, dict)
        and item.get("latency_available") is True
        and float(item.get("total_requests") or 0) > 0
        for item in signal_compacts
    ):
        missing.append("measured_traffic_and_p95_latency")
    deployment_compact = (
        getattr(deployment_events[-1], "evidence", {}).get("compact_result", {})
        if deployment_events
        else {}
    )
    if deployment_events and (
        not isinstance(deployment_compact, dict)
        or not deployment_compact.get("rollout_complete")
        or int(deployment_compact.get("ready_replicas") or 0)
        != int(deployment_compact.get("desired_replicas") or 0)
    ):
        missing.append("all_current_replicas_ready")
    scheduled_nodes = (
        deployment_compact.get("scheduled_nodes")
        if isinstance(deployment_compact, dict)
        and isinstance(deployment_compact.get("scheduled_nodes"), list)
        else []
    )
    node_headroom_event, node_headroom_error = _latest_safe_node_headroom_event(
        events,
        scheduled_nodes=scheduled_nodes,
    )
    if node_headroom_event is None:
        missing.append(node_headroom_error)
    if missing:
        return {
            "error": "required capacity evidence is incomplete",
            "missing_evidence": missing,
        }

    observed_replicas = _latest_observed_replicas(
        events,
        namespace=normalized_namespace,
        target_name=normalized_target,
    )
    requested_current = int(current_replicas)
    requested_target = int(target_replicas)
    if observed_replicas is None:
        return {"error": "current replica evidence is unavailable"}
    if requested_current != observed_replicas:
        return {
            "error": "current replicas do not match the latest evidence",
            "observed_replicas": observed_replicas,
        }
    if requested_target != requested_current + 1:
        return {"error": "scale approval must add exactly one replica"}
    max_replicas = max(1, int(os.getenv("AIOPS_SCALE_MAX_REPLICAS", "3")))
    if requested_target > max_replicas:
        return {"error": "target replicas exceed the safety limit"}

    normalized_reason = " ".join((reason or "").split())[:500]
    normalized_risk = " ".join((risk or "").split())[:300]
    normalized_outcome = " ".join((expected_outcome or "").split())[:300]
    checks = [
        " ".join(str(item).split())[:160]
        for item in verification
        if str(item).strip()
    ][:6]
    if (
        len(normalized_reason) < 20
        or len(normalized_risk) < 5
        or len(normalized_outcome) < 10
    ):
        return {"error": "reason, risk and expected_outcome must be specific"}
    if not checks:
        return {"error": "at least one verification item is required"}

    evidence_refs = list(
        dict.fromkeys(
            [
                *(event.event_id for event in trend_events[-2:]),
                *(event.event_id for event in signal_events[-2:]),
                *(event.event_id for event in business_events[-1:]),
                *(event.event_id for event in deployment_events[-1:]),
                *([node_headroom_event.event_id] if node_headroom_event is not None else []),
            ]
        )
    )
    action, created = remediation_store.create_scale_request(
        incident_id=incident.incident_id,
        analysis_id=run.analysis_id,
        skill_name=CAPACITY_SCALING_SKILL,
        namespace=normalized_namespace,
        target_name=normalized_target,
        current_replicas=requested_current,
        target_replicas=requested_target,
        reason=normalized_reason,
        risk=normalized_risk,
        expected_outcome=normalized_outcome,
        verification=checks,
        evidence_refs=evidence_refs,
    )
    return {
        "status": action.status,
        "created": created,
        "action": action.model_dump(mode="json"),
    }


INCIDENT_SKILL_TOOLS: list[dict[str, Any]] = [
    {
        "name": ACTIVATE_CAPACITY_SKILL_TOOL,
        "label": "启用容量扩展分析 Skill",
        "spec": {
            "type": "function",
            "function": {
                "name": ACTIVATE_CAPACITY_SKILL_TOOL,
                "description": (
                    "仅当通用调查已发现持续高并发或延迟/处理中请求堆积，并取得当前 Deployment "
                    "副本状态时，激活 capacity_scaling Skill。该工具只切换调查流程，不执行扩容。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "incident_id": {"type": "string"},
                        "reason": {
                            "type": "string",
                            "minLength": 20,
                            "maxLength": 500,
                        },
                    },
                    "required": ["incident_id", "reason"],
                },
            },
        },
        "handler": activate_capacity_scaling_skill,
    },
    {
        "name": REQUEST_SCALE_APPROVAL_TOOL,
        "label": "申请 Deployment 扩容审批",
        "spec": {
            "type": "function",
            "function": {
                "name": REQUEST_SCALE_APPROVAL_TOOL,
                "description": (
                    "capacity_scaling Skill 已激活，且持续影响、流量与服务黄金信号、当前副本状态"
                    "以及目标节点资源余量证据完整时，创建一次仅增加一个副本的人工审批。"
                    "节点 CPU、内存或磁盘接近饱和时会拒绝申请。该工具绝不修改 Kubernetes。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "incident_id": {"type": "string"},
                        "namespace": {"type": "string"},
                        "deployment_name": {"type": "string"},
                        "current_replicas": {"type": "integer", "minimum": 1},
                        "target_replicas": {
                            "type": "integer",
                            "minimum": 2,
                            "maximum": 3,
                        },
                        "reason": {
                            "type": "string",
                            "minLength": 20,
                            "maxLength": 500,
                        },
                        "risk": {
                            "type": "string",
                            "minLength": 5,
                            "maxLength": 300,
                        },
                        "expected_outcome": {
                            "type": "string",
                            "minLength": 10,
                            "maxLength": 300,
                        },
                        "verification": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "maxItems": 6,
                        },
                    },
                    "required": [
                        "incident_id",
                        "namespace",
                        "deployment_name",
                        "current_replicas",
                        "target_replicas",
                        "reason",
                        "risk",
                        "expected_outcome",
                        "verification",
                    ],
                },
            },
        },
        "handler": request_scale_approval,
    },
    {
        "name": ACTIVATE_RELEASE_SKILL_TOOL,
        "label": "启用发版回归分析 Skill",
        "spec": {
            "type": "function",
            "function": {
                "name": ACTIVATE_RELEASE_SKILL_TOOL,
                "description": (
                    "仅当通用调查已经发现与当前对象匹配的镜像变更，并初步判断故障可能与发布相关时，"
                    "激活 release_regression Skill。该工具只切换调查流程，不执行任何生产操作。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "incident_id": {"type": "string"},
                        "reason": {"type": "string", "minLength": 20, "maxLength": 500},
                    },
                    "required": ["incident_id", "reason"],
                },
            },
        },
        "handler": activate_release_regression_skill,
    },
    {
        "name": REQUEST_ROLLBACK_APPROVAL_TOOL,
        "label": "申请 Deployment 回滚审批",
        "spec": {
            "type": "function",
            "function": {
                "name": REQUEST_ROLLBACK_APPROVAL_TOOL,
                "description": (
                    "release_regression Skill 已激活，且指标、错误日志、镜像变更和上一稳定版本证据完整时，"
                    "创建一次 Deployment 回滚人工审批。该工具绝不修改 Kubernetes；审批通过后才由后端执行器处理。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "incident_id": {"type": "string"},
                        "namespace": {"type": "string"},
                        "deployment_name": {"type": "string"},
                        "container_name": {"type": "string"},
                        "current_image": {"type": "string"},
                        "target_image": {"type": "string"},
                        "reason": {"type": "string", "minLength": 20, "maxLength": 500},
                        "risk": {"type": "string", "minLength": 5, "maxLength": 300},
                        "expected_outcome": {"type": "string", "minLength": 10, "maxLength": 300},
                        "verification": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "maxItems": 6,
                        },
                    },
                    "required": [
                        "incident_id", "namespace", "deployment_name", "container_name",
                        "current_image", "target_image", "reason", "risk",
                        "expected_outcome", "verification"
                    ],
                },
            },
        },
        "handler": request_rollback_approval,
    },
]
