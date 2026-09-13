from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable
from zoneinfo import ZoneInfo

from alerting.classifier import classify_alert_labels
from alerting.profiles import get_alert_recovery_gate
from memory.incident_analysis_store import IncidentAnalysisStore
from memory.incident_memory_store import IncidentMemoryStore
from memory.models import format_utc_datetime, parse_utc_datetime, utc_now

if TYPE_CHECKING:
    from alerting.analysis_agent import IncidentAnalysisAgent

_ACTIVE_STATUSES = {
    "running",
    "waiting_approval",
    "waiting_recheck",
    "monitoring",
    "completed",
}

_RESOLVABLE_STATUSES = {
    "waiting_recheck",
    "monitoring",
    "failed",
    "waiting_approval",
}

_BEIJING_TZ = ZoneInfo("Asia/Shanghai")


def _format_beijing(value: datetime | None) -> str:
    if value is None:
        return "--"
    return value.astimezone(_BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def _alert_direction(expression: str) -> str | None:
    match = re.search(r"(<=|>=|<|>)\s*-?\d+(?:\.\d+)?", expression or "")
    if not match:
        return None
    return "below" if match.group(1) in {"<", "<="} else "above"


def _report_text(value: Any, *, limit: int = 1800) -> str:
    """Flatten tool summaries so embedded Markdown cannot break the report."""
    text = " ".join(str(value or "").replace("\r", " ").split())
    text = text.strip(" |").replace("|", r"\|")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _completed_assessment(event: Any) -> bool:
    """Only the final assessment of a completed round has these snapshots."""
    if event.event_type != "assessment" or not event.content_md:
        return False
    evidence = event.evidence if isinstance(event.evidence, dict) else {}
    return bool(
        isinstance(evidence.get("evidence_progress"), dict)
        or isinstance(evidence.get("reasoning_state"), dict)
    )


def _evidence_priority(
    tool_name: str,
    evidence: dict[str, Any],
    compact: dict[str, Any],
) -> int:
    """Rank direct diagnostic observations ahead of generic/empty results."""
    outcome = str(evidence.get("query_outcome") or "").strip().lower()
    if outcome in {"failed", "timeout"}:
        return 0

    if tool_name == "search_logs":
        if compact.get("samples"):
            return 100
        if int(compact.get("total_matches") or 0) > 0:
            return 82
        return 15
    if tool_name == "search_change_events":
        if compact.get("items"):
            return 95
        if int(compact.get("total") or 0) > 0:
            return 78
        return 15
    if tool_name in {"get_metric_trend", "get_pod_resource_trend"}:
        return 90 if int(compact.get("sample_count") or 0) > 0 else 20
    if tool_name == "get_business_overview":
        return 85
    if tool_name in {
        "get_kubernetes_events",
        "get_pod_status",
        "get_workload_status",
    }:
        return 75 if outcome not in {"no_match", "no_data"} else 20
    if tool_name == "get_seckill_reliability":
        return 65
    if tool_name == "get_prometheus_alert_rule":
        return 45
    if outcome in {"no_match", "no_data"}:
        return 15
    return 55


def _build_resolved_conclusion(incident: Any, run: Any, events: list[Any]) -> str:
    evidence_candidates: list[tuple[int, int, str]] = []
    trend_facts: list[str] = []
    seen_evidence_keys: set[str] = set()
    seen_summaries: set[str] = set()
    latest_assessment = ""
    recovery_verification = None
    has_direct_diagnostic_evidence = False

    for event in reversed(events):
        if _completed_assessment(event):
            candidate = _report_text(event.content_md, limit=5000)
            if candidate:
                latest_assessment = candidate
                break

    for event in reversed(events):
        if event.event_type != "recovery_check":
            continue
        evidence = event.evidence if isinstance(event.evidence, dict) else {}
        if evidence.get("verification_status"):
            recovery_verification = evidence
            break



    for event_index in range(len(events) - 1, -1, -1):
        event = events[event_index]
        if event.event_type != "tool_result":
            continue
        evidence = event.evidence if isinstance(event.evidence, dict) else {}
        if evidence.get("status") != "success":
            continue
        evidence_key = str(evidence.get("evidence_key") or event.event_id)
        if evidence_key in seen_evidence_keys:
            continue
        seen_evidence_keys.add(evidence_key)
        summary = _report_text(
            evidence.get("summary") or event.content_md or ""
        )
        if summary.startswith("查询失败："):
            continue
        compact = evidence.get("compact_result")
        if not isinstance(compact, dict):
            compact = {}
        if isinstance(compact, dict) and compact.get("sample_count"):
            window_text = ""
            if compact.get("start_at") and compact.get("end_at"):
                window_text = (
                    f"在 {compact.get('start_at')} 至 {compact.get('end_at')} "
                )
            fact = (
                f"{compact.get('metric_label') or '历史指标'}{window_text}共取得 "
                f"{compact.get('sample_count')} 个样本，最小值 "
                f"{compact.get('min', '--')}，峰值 {compact.get('peak', '--')}，"
                f"最新值 {compact.get('latest', '--')}。"
            )
            if compact.get("unit"):
                fact = fact[:-1] + f"，单位 {compact.get('unit')}。"
            if compact.get("node_capacity_cores"):
                fact += (
                    f"节点 {compact.get('node_name') or '--'} 容量为 "
                    f"{compact.get('node_capacity_cores')} cores，"
                    f"该 Pod 峰值约占节点容量的 "
                    f"{compact.get('peak_node_capacity_percent', '--')}%。"
                )
            threshold = compact.get("threshold")
            if isinstance(threshold, (int, float)):
                direction = str(compact.get("threshold_direction") or "above")
                direction_text = "低于" if direction == "below" else "高于"
                breached_count = compact.get(
                    "breached_sample_count",
                    compact.get("above_threshold_sample_count", 0),
                )
                if compact.get("condition_promql"):
                    fact += (
                        f"规则阈值为 {threshold}，观察到 {breached_count} 个"
                        "完整告警条件成立的样本，覆盖时长只能按采样粒度估算，"
                        "不能视为精确连续告警时长。"
                    )
                else:
                    fact += (
                        f"规则阈值为 {threshold}，观察到 "
                        f"{breached_count} 个{direction_text}阈值样本，"
                        "覆盖时长只能按采样粒度估算，不能视为精确连续超阈时长。"
                    )
            trend_facts.append(fact)
            continue

        if summary and summary not in seen_summaries:
            seen_summaries.add(summary)
            observed_at = getattr(event, "created_at", None)
            observed_text = _format_beijing(observed_at)
            scoped_summary = f"{observed_text} 查询时：{summary}"
            priority = _evidence_priority(
                str(event.tool_name or ""),
                evidence,
                compact,
            )
            evidence_candidates.append(
                (priority, event_index, scoped_summary)
            )
            if (
                (
                    event.tool_name == "search_logs"
                    and bool(compact.get("samples"))
                )
                or (
                    event.tool_name == "search_change_events"
                    and bool(compact.get("items"))
                )
            ):
                has_direct_diagnostic_evidence = True

    trend_facts.reverse()


    evidence_lines = [
        item[2]
        for item in sorted(
            sorted(
                evidence_candidates,
                key=lambda item: (item[0], item[1]),
                reverse=True,
            )[:6],
            key=lambda item: item[1],
        )
    ]

    event_time = _format_beijing(incident.resolved_at)
    received_time = _format_beijing(incident.last_received_at)
    delay_text = ""
    if incident.resolved_at and incident.last_received_at:
        delay = max(
            0,
            int((incident.last_received_at - incident.resolved_at).total_seconds()),
        )
        delay_text = f"，系统在 {received_time} 收到恢复通知，传递延迟约 {delay} 秒"

    confirmed = [
        f"Alertmanager resolved 时间为 {event_time}（北京时间）{delay_text}。",
        f"本次共收到 {incident.notification_count} 次通知，接收器为 "
        f"{incident.receiver or '--'}。",
    ]
    confirmed.extend(trend_facts[-3:])
    if recovery_verification:
        verification_summary = str(
            recovery_verification.get("summary") or ""
        ).strip()
        if verification_summary:
            confirmed.append(verification_summary)
    for line in evidence_lines:
        if line not in confirmed and len(confirmed) < 10:
            confirmed.append(line)

    confirmed_text = "\n".join(
        f"{index}. {item}"
        for index, item in enumerate(confirmed, start=1)
    )
    independently_verified = bool(
        recovery_verification
        and recovery_verification.get("verification_status") == "confirmed"
    )
    condition_cleared = bool(
        recovery_verification
        and recovery_verification.get("verification_status")
        == "condition_cleared"
    )
    insufficient_traffic = bool(
        recovery_verification
        and recovery_verification.get("verification_status")
        == "insufficient_traffic"
    )
    if independently_verified:
        recovery_status_text = "并已通过目标指标完成独立恢复验证。"
    elif condition_cleared:
        recovery_status_text = (
            "独立复查仅确认完整告警条件已解除，主指标尚未确认恢复。"
        )
    elif insufficient_traffic:
        recovery_status_text = (
            "完整告警条件已经解除，但有效流量不足，业务恢复仍待验证。"
        )
    else:
        recovery_status_text = "该通知本身不等同于独立的指标恢复验证。"
    sections = [
        (
            "Incident 告警已解除，业务恢复待验证"
            if insufficient_traffic
            else "Incident 已恢复"
        ),
        (
            "恢复状态：Alertmanager 已发送 resolved 通知，生命周期已经闭环；"
            f"{recovery_status_text}"
        ),
        f"已确认事实：\n{confirmed_text}",
    ]

    classification = getattr(run, "classification", "unknown")
    if classification != "unknown":
        sections.append(f"分类：{classification}")
    if latest_assessment:
        sections.append(
            "恢复前最后分析判断：\n"
            f"{latest_assessment}\n\n"
            "这是一条带采集时点的阶段性判断，不因告警恢复自动升级为已确认根因。"
        )
    else:
        sections.append("根因判断：现有证据不足以确认具体根因。")

    sections.append(
        "判断边界：规则被触发只说明监控条件曾满足，不等同于资源饱和，"
        "也不自动等同于生产故障。历史趋势证据存在时，以趋势窗口为准；"
        "即时值只表示查询时点的状态。"
    )
    if has_direct_diagnostic_evidence:
        sections.append(
            "根因边界：已观察到具体日志或变更证据，但时间相关性不自动等同于"
            "因果性；最深层原因仍以已采集证据能够直接支持的范围为准。"
        )
    else:
        sections.append(
            "如果现有证据没有定位到具体进程、工作负载、变更或日志异常，"
            "则本次只能确认告警生命周期已经闭环，不能虚构具体根因。"
        )
    return "\n\n".join(sections)


class IncidentAnalysisRunner:
    """Create and advance Incident analysis runs."""

    def __init__(
        self,
        incident_store: IncidentMemoryStore,
        analysis_store: IncidentAnalysisStore,
        *,
        max_automatic_rounds: int = 6,
        recovery_verifier: Callable[[str, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.incident_store = incident_store
        self.analysis_store = analysis_store
        self.max_automatic_rounds = max(1, int(max_automatic_rounds))
        self.recovery_verifier = recovery_verifier

    def _verify_metric_recovery(
        self,
        incident: Any,
        events: list[Any],
    ) -> tuple[str, dict[str, Any]]:
        resolved_at = incident.resolved_at
        if self.recovery_verifier is None or resolved_at is None:
            return (
                f"恢复时间：{_format_beijing(resolved_at)}（北京时间）",
                {"verification_status": "unavailable"},
            )

        source_arguments: dict[str, Any] | None = None
        for event in reversed(events):
            if event.event_type != "tool_result" or event.tool_name != "get_metric_trend":
                continue
            evidence = event.evidence if isinstance(event.evidence, dict) else {}
            arguments = evidence.get("arguments")
            if (
                evidence.get("status") == "success"
                and isinstance(arguments, dict)
                and isinstance(arguments.get("threshold"), (int, float))
            ):
                source_arguments = dict(arguments)
                break

        if not source_arguments:
            return (
                f"恢复时间：{_format_beijing(resolved_at)}（北京时间）",
                {
                    "verification_status": "unavailable",
                    "summary": "缺少可复用的目标指标查询，未执行独立恢复验证。",
                },
            )




        alert_expression = str(
            source_arguments.get("condition_promql") or ""
        ).strip()
        if not alert_expression:
            for event in reversed(events):
                if (
                    event.event_type != "tool_result"
                    or event.tool_name != "get_prometheus_alert_rule"
                ):
                    continue
                evidence = event.evidence if isinstance(event.evidence, dict) else {}
                compact = evidence.get("compact_result")
                if not isinstance(compact, dict):
                    continue
                alert_expression = str(compact.get("expression") or "").strip()
                if alert_expression:
                    break

        deterministic_direction = _alert_direction(alert_expression)
        if deterministic_direction:
            source_arguments["threshold_direction"] = deterministic_direction
            source_arguments["condition_promql"] = alert_expression

        end_at = incident.last_received_at or resolved_at
        start_at = end_at - timedelta(minutes=2)
        verification_arguments = {
            **source_arguments,
            "start_at": format_utc_datetime(start_at),
            "end_at": format_utc_datetime(end_at),
            "metric_label": (
                f"{source_arguments.get('metric_label') or '告警指标'}恢复复查"
            ),
        }
        verification_arguments.pop("window", None)

        try:
            result = self.recovery_verifier(
                "get_metric_trend",
                verification_arguments,
            )
        except Exception as exc:
            return (
                f"恢复时间：{_format_beijing(resolved_at)}（北京时间）",
                {
                    "verification_status": "failed",
                    "summary": f"独立指标恢复验证执行失败：{exc}",
                    "arguments": verification_arguments,
                },
            )

        if not isinstance(result, dict) or result.get("error"):
            error = (
                result.get("error")
                if isinstance(result, dict)
                else "invalid recovery verifier result"
            )
            return (
                f"恢复时间：{_format_beijing(resolved_at)}（北京时间）",
                {
                    "verification_status": "failed",
                    "summary": f"独立指标恢复验证失败：{error}",
                    "arguments": verification_arguments,
                },
            )

        latest = result.get("latest")
        threshold = result.get("threshold")
        threshold_direction = str(
            result.get("threshold_direction")
            or source_arguments.get("threshold_direction")
            or "above"
        ).lower()
        metric_recovered = (
            isinstance(latest, (int, float))
            and isinstance(threshold, (int, float))
            and (
                latest >= threshold
                if threshold_direction == "below"
                else latest <= threshold
            )
        )

        recovery_gate = get_alert_recovery_gate(
            str(getattr(incident, "alert_name", "") or "")
        )
        gate_result: dict[str, Any] = {}
        gate_status = "not_required"
        if recovery_gate:
            gate_tool_name = str(recovery_gate.get("tool_name") or "").strip()
            gate_arguments = recovery_gate.get("arguments")
            if gate_tool_name and isinstance(gate_arguments, dict):
                try:
                    candidate = self.recovery_verifier(
                        gate_tool_name,
                        dict(gate_arguments),
                    )
                    if isinstance(candidate, dict):
                        gate_result = candidate
                except Exception as exc:
                    gate_result = {"error": str(exc)}

            if not gate_result or gate_result.get("error"):
                gate_status = "unavailable"
            else:
                total_count = int(gate_result.get("total_count") or 0)
                success_count = int(gate_result.get("success_count") or 0)
                minimum_total = int(
                    recovery_gate.get("minimum_total_count_exclusive") or 0
                )
                minimum_success = int(
                    recovery_gate.get("minimum_success_count") or 0
                )
                if total_count <= minimum_total:
                    gate_status = "insufficient_traffic"
                elif success_count < minimum_success:
                    gate_status = "no_success"
                else:
                    gate_status = "passed"

        confirmed = metric_recovered and gate_status in {"not_required", "passed"}
        condition_promql = str(
            result.get("condition_promql")
            or source_arguments.get("condition_promql")
            or ""
        ).strip()
        condition_active_latest = result.get("condition_active_latest")
        condition_cleared = bool(
            condition_promql
            and condition_active_latest is False
            and not confirmed
        )
        comparison = "已回到" if confirmed else "尚未确认回到"
        direction_text = "低于阈值触发" if threshold_direction == "below" else "高于阈值触发"
        if gate_status == "insufficient_traffic":
            total_count = int(gate_result.get("total_count") or 0)
            minimum_total = int(
                recovery_gate.get("minimum_total_count_exclusive") or 0
            )
            summary = (
                "独立恢复复查：Alertmanager 完整告警条件已经解除，但近 5 分钟"
                f"有效请求量仅 {total_count}，未达到大于 {minimum_total} 的恢复验证门槛。"
                f"当前计算得到的 {result.get('metric_label') or '告警指标'}="
                f"{latest if latest is not None else '--'} 不能代表业务已恢复，"
                "本次状态为恢复待验证。"
            )
        elif gate_status == "no_success":
            summary = (
                "独立恢复复查：有效流量已经恢复，但没有观察到成功请求；"
                "业务恢复尚未确认。"
            )
        elif gate_status == "unavailable":
            summary = (
                "独立恢复复查：目标指标已经复查，但流量恢复门禁查询失败或返回无效结果；"
                "业务恢复尚未确认。"
            )
        elif condition_cleared:
            summary = (
                "独立指标恢复复查：完整告警条件已经解除，但"
                f"{result.get('metric_label') or '告警指标'}最新值 "
                f"{latest if latest is not None else '--'}，阈值 "
                f"{threshold if threshold is not None else '--'}（{direction_text}），"
                "主指标尚未确认恢复；只能确认附加门槛不再满足。"
            )
        else:
            summary = (
                f"独立指标恢复复查：{result.get('metric_label') or '告警指标'}"
                f"最新值 {latest if latest is not None else '--'}，阈值 "
                f"{threshold if threshold is not None else '--'}（{direction_text}），"
                f"{comparison}阈值范围。"
            )
        return (
            f"恢复时间：{_format_beijing(resolved_at)}（北京时间）\n\n{summary}",
            {
                "verification_status": (
                    "confirmed"
                    if confirmed
                    else "insufficient_traffic"
                    if gate_status == "insufficient_traffic"
                    else "condition_cleared"
                    if condition_cleared
                    else "not_confirmed"
                ),
                "summary": summary,
                "arguments": verification_arguments,
                "recovery_gate": {
                    "status": gate_status,
                    "configuration": recovery_gate,
                    "result": {
                        key: gate_result.get(key)
                        for key in (
                            "metric_name",
                            "namespace",
                            "window",
                            "total_count",
                            "raw_total_count",
                            "success_count",
                            "success_rate",
                            "summary",
                            "error",
                        )
                        if gate_result.get(key) is not None
                    },
                },
                "result": {
                    key: result.get(key)
                    for key in (
                        "metric_label",
                        "start_at",
                        "end_at",
                        "sample_count",
                        "min",
                        "peak",
                        "latest",
                        "threshold",
                        "threshold_direction",
                        "series_match",
                        "series_metric",
                        "condition_promql",
                        "condition_active_sample_count",
                        "condition_active_latest",
                    )
                    if result.get(key) is not None
                },
            },
        )

    def ensure_started(self, incident_id: str) -> dict[str, Any]:
        normalized_id = (incident_id or "").strip()
        if not normalized_id:
            return {
                "error": "incident_id is required",
                "summary": "缺少 Incident ID。",
                "started": False,
            }

        incident = self.incident_store.get(normalized_id)
        if incident is None:
            return {
                "error": "incident not found",
                "incident_id": normalized_id,
                "summary": f"未找到 Incident {normalized_id}。",
                "started": False,
            }

        run = self.analysis_store.get_or_create_run(normalized_id)

        if run.status in _ACTIVE_STATUSES:
            return {
                "incident_id": normalized_id,
                "analysis_id": run.analysis_id,
                "status": run.status,
                "started": False,
                "summary": (
                    f"分析任务 {run.analysis_id} 当前状态为 {run.status}，"
                    "未重复启动。"
                ),
            }

        namespace = incident.namespace or "--"
        target = incident.target or "--"

        if incident.status == "resolved":
            updated = self.analysis_store.update_run(
                run.analysis_id,
                status="completed",
                phase="closed",
                current_round=max(1, run.current_round),
            )
            self.analysis_store.append_event(
                run.analysis_id,
                "conclusion",
                "告警已恢复",
                content_md=(
                    f"已接收 {incident.alert_name}，目标为 "
                    f"{namespace}/{target}。告警当前已恢复，"
                    "本次不继续自动采集证据。"
                ),
                round_index=updated.current_round,
            )
            return {
                "incident_id": normalized_id,
                "analysis_id": updated.analysis_id,
                "status": updated.status,
                "started": True,
                "summary": (
                    f"Incident {normalized_id} 已恢复，"
                    "分析任务已直接标记为 completed。"
                ),
            }

        classification = classify_alert_labels(
            incident.labels
        )

        if classification.deterministic:
            updated = self.analysis_store.update_run(
                run.analysis_id,
                status="monitoring",
                phase="monitoring",
                classification=(
                    classification.classification
                ),
                classification_confidence=(
                    classification.confidence
                ),
                classification_reason=(
                    classification.reason
                ),
                classified_at=utc_now(),
                current_round=1,
                clear_next_recheck_at=True,
            )

            self.analysis_store.append_event(
                run.analysis_id,
                "classification",
                "识别为测试告警",
                content_md=(
                    f"{classification.reason}"
                    "本次只验证告警接收、去重和恢复闭环，"
                    "不进入真实故障根因分析。"
                ),
                round_index=1,
                evidence={
                    "classification": (
                        classification.classification
                    ),
                    "confidence": (
                        classification.confidence
                    ),
                    "deterministic": True,
                },
            )

            return {
                "incident_id": normalized_id,
                "analysis_id": updated.analysis_id,
                "status": updated.status,
                "phase": updated.phase,
                "classification": (
                    updated.classification
                ),
                "started": True,
                "summary": (
                    "已根据结构化标签识别为测试告警，"
                    "进入 monitoring。"
                ),
            }

        updated = self.analysis_store.update_run(
            run.analysis_id,
            status="running",
            phase="collecting_evidence",
            current_round=1,
        )
        self.analysis_store.append_event(
            run.analysis_id,
            "analysis_started",
            "开始分析告警",
            content_md=(
                f"已接收 {incident.alert_name}，目标为 "
                f"{namespace}/{target}，准备采集证据。"
            ),
            round_index=1,
        )

        return {
            "incident_id": normalized_id,
            "analysis_id": updated.analysis_id,
            "status": updated.status,
            "started": True,
            "summary": (
                f"已启动 Incident {normalized_id} 的分析任务 "
                f"{updated.analysis_id}。"
            ),
        }

    def complete_if_resolved(self, incident_id: str) -> dict[str, Any]:
        normalized_id = (incident_id or "").strip()
        if not normalized_id:
            return {
                "completed": False,
                "reason": "incident_id_required",
            }

        incident = self.incident_store.get(normalized_id)
        if incident is None:
            return {
                "completed": False,
                "incident_id": normalized_id,
                "reason": "incident_not_found",
            }

        if incident.status != "resolved":
            return {
                "completed": False,
                "incident_id": normalized_id,
                "reason": "not_resolved",
                "incident_status": incident.status,
            }

        run = self.analysis_store.get_run_by_incident(normalized_id)
        if run is None:
            return {
                "completed": False,
                "incident_id": normalized_id,
                "reason": "no_analysis",
            }

        if run.status == "completed":
            return {
                "completed": True,
                "idempotent": True,
                "incident_id": normalized_id,
                "analysis_id": run.analysis_id,
                "status": run.status,
            }

        if run.status == "running":
            return {
                "completed": False,
                "deferred": True,
                "incident_id": normalized_id,
                "analysis_id": run.analysis_id,
                "status": run.status,
                "summary": (
                    "分析仍在运行，暂不强制改为 completed，"
                    "避免当前轮结束后覆盖状态。"
                ),
            }

        if run.status not in _RESOLVABLE_STATUSES:
            return {
                "completed": False,
                "incident_id": normalized_id,
                "analysis_id": run.analysis_id,
                "status": run.status,
                "reason": f"unsupported_status:{run.status}",
            }

        events = self.analysis_store.list_events(run.analysis_id)
        recovery_content, recovery_evidence = self._verify_metric_recovery(
            incident,
            events,
        )

        self.analysis_store.append_event(
            run.analysis_id,
            "recovery_check",
            (
                "告警已解除，恢复待验证"
                if recovery_evidence.get("verification_status")
                == "insufficient_traffic"
                else "告警已恢复"
            ),
            content_md=recovery_content,
            round_index=run.current_round,
            evidence=recovery_evidence,
        )
        events = self.analysis_store.list_events(run.analysis_id)
        content_md = _build_resolved_conclusion(
            incident,
            run,
            events,
        )
        self.analysis_store.append_event(
            run.analysis_id,
            "conclusion",
            "分析结束",
            content_md=content_md,
            round_index=run.current_round,
        )
        completed = self.analysis_store.update_run(
            run.analysis_id,
            status="completed",
            phase="closed",
            clear_next_recheck_at=True,
        )
        return {
            "completed": True,
            "incident_id": normalized_id,
            "analysis_id": completed.analysis_id,
            "status": completed.status,
            "summary": (
                "告警已解除，但流量不足，业务恢复待验证。"
                if recovery_evidence.get("verification_status")
                == "insufficient_traffic"
                else "告警已恢复，分析任务已结束。"
            ),
        }

    def recover_stale_running(
        self,
        analysis_id: str,
        *,
        now: Any = None,
        stale_after_seconds: int = 180,
    ) -> dict[str, Any]:
        """Recover a running lease left behind by a terminated worker."""
        normalized_id = (analysis_id or "").strip()
        run = self.analysis_store.get_run(normalized_id)
        if run is None:
            return {
                "recovered": False,
                "analysis_id": normalized_id,
                "reason": "not_found",
            }
        if run.status != "running":
            return {
                "recovered": False,
                "analysis_id": normalized_id,
                "status": run.status,
                "reason": "not_running",
            }

        current_time = parse_utc_datetime(now) or utc_now()
        age_seconds = max(
            0.0,
            (current_time - run.updated_at).total_seconds(),
        )
        if age_seconds < max(60, int(stale_after_seconds)):
            return {
                "recovered": False,
                "analysis_id": normalized_id,
                "status": run.status,
                "reason": "not_stale",
            }

        incident = self.incident_store.get(run.incident_id)
        if incident is None:
            failed = self.analysis_store.update_run(
                run.analysis_id,
                status="failed",
            )
            return {
                "recovered": True,
                "analysis_id": failed.analysis_id,
                "status": failed.status,
                "reason": "incident_not_found",
            }

        self.analysis_store.append_event(
            run.analysis_id,
            "error",
            "分析任务中断恢复",
            content_md=(
                "检测到分析任务长时间停留在运行状态，"
                "推定原执行进程已退出。系统已回收该运行状态，"
                "已保存的工具证据不会丢失。"
            ),
            round_index=run.current_round,
            evidence={
                "stale_running_recovered": True,
                "stale_age_seconds": round(age_seconds, 3),
            },
        )

        if incident.status == "resolved":
            self.analysis_store.update_run(
                run.analysis_id,
                status="monitoring",
                phase="monitoring",
                clear_next_recheck_at=True,
            )
            completed = self.complete_if_resolved(run.incident_id)
            return {
                "recovered": True,
                "incident_id": run.incident_id,
                "analysis_id": run.analysis_id,
                "status": completed.get("status", "completed"),
                "resolved": True,
            }

        requeued = self.analysis_store.update_run(
            run.analysis_id,
            status="waiting_recheck",
            next_recheck_at=current_time,
        )
        return {
            "recovered": True,
            "incident_id": run.incident_id,
            "analysis_id": requeued.analysis_id,
            "status": requeued.status,
            "resolved": False,
        }

    def run_first_round(
        self,
        incident_id: str,
        analysis_agent: IncidentAnalysisAgent,
    ) -> dict[str, Any]:
        started = self.ensure_started(incident_id)
        if started.get("error"):
            return {
                **started,
                "executed": False,
            }

        normalized_id = str(started.get("incident_id") or incident_id).strip()
        analysis_id = str(started.get("analysis_id") or "").strip()
        incident = self.incident_store.get(normalized_id)
        run = self.analysis_store.get_run(analysis_id)

        if incident is None or run is None:
            return {
                "error": "incident or analysis run missing after ensure_started",
                "incident_id": normalized_id,
                "analysis_id": analysis_id,
                "executed": False,
                "summary": "分析任务状态异常，无法执行第一轮。",
            }

        if run.status != "running" or run.current_round != 1:
            return {
                "incident_id": normalized_id,
                "analysis_id": run.analysis_id,
                "status": run.status,
                "current_round": run.current_round,
                "executed": False,
                "summary": (
                    f"当前状态为 {run.status}/round={run.current_round}，"
                    "不重复执行第一轮分析。"
                ),
            }

        try:
            result = analysis_agent.run_round(
                incident=incident,
                analysis_run=run,
                analysis_store=self.analysis_store,
                round_index=1,
            )
            return {
                "incident_id": normalized_id,
                "executed": True,
                **result,
            }
        except Exception as exc:
            self.analysis_store.append_event(
                run.analysis_id,
                "error",
                "第一轮分析失败",
                content_md=str(exc),
                round_index=1,
            )
            failed = self.analysis_store.update_run(
                run.analysis_id,
                status="failed",
            )
            return {
                "error": str(exc),
                "incident_id": normalized_id,
                "analysis_id": failed.analysis_id,
                "status": failed.status,
                "executed": False,
                "summary": f"第一轮分析失败：{exc}",
            }

    def run_recheck(
        self,
        analysis_id: str,
        analysis_agent: IncidentAnalysisAgent,
        *,
        now: Any = None,
    ) -> dict[str, Any]:
        normalized_analysis_id = (analysis_id or "").strip()
        existing = self.analysis_store.get_run(normalized_analysis_id)
        if existing is None:
            return {
                "executed": False,
                "reason": "not_found",
                "analysis_id": normalized_analysis_id,
            }

        if (
            existing.status == "waiting_recheck"
            and existing.current_round >= self.max_automatic_rounds
        ):
            self.analysis_store.append_event(
                existing.analysis_id,
                "conclusion",
                "达到自动分析轮次上限",
                content_md=(
                    f"已完成 {existing.current_round} 轮自动分析"
                    f"（上限 {self.max_automatic_rounds}）。"
                    "告警仍可能处于 firing，自动分析暂停，等待 SRE 接管。"
                ),
                round_index=existing.current_round,
            )
            paused = self.analysis_store.update_run(
                existing.analysis_id,
                status="monitoring",
                phase="monitoring",
                clear_next_recheck_at=True,
            )
            return {
                "executed": True,
                "paused": True,
                "incident_id": paused.incident_id,
                "analysis_id": paused.analysis_id,
                "status": paused.status,
                "current_round": paused.current_round,
                "summary": (
                    f"已达自动轮次上限 {self.max_automatic_rounds}，"
                    "进入 monitoring，等待告警恢复或 SRE 主动接管。"
                ),
            }

        run = self.analysis_store.claim_recheck(
            normalized_analysis_id,
            now=now,
        )
        if run is None:
            return {
                "executed": False,
                "reason": "not_due_or_claimed",
                "analysis_id": normalized_analysis_id,
            }

        incident = self.incident_store.get(run.incident_id)
        if incident is None:
            failed = self.analysis_store.update_run(
                run.analysis_id,
                status="failed",
            )
            return {
                "executed": False,
                "error": "incident not found",
                "analysis_id": failed.analysis_id,
                "status": failed.status,
            }

        if incident.status == "resolved":
            events = self.analysis_store.list_events(run.analysis_id)
            self.analysis_store.append_event(
                run.analysis_id,
                "recovery_check",
                "告警已恢复",
                content_md=(
                    f"恢复时间：{_format_beijing(incident.resolved_at)}"
                    "（北京时间）"
                ),
                round_index=run.current_round,
            )
            self.analysis_store.append_event(
                run.analysis_id,
                "conclusion",
                "分析结束",
                content_md=_build_resolved_conclusion(
                    incident,
                    run,
                    events,
                ),
                round_index=run.current_round,
            )
            completed = self.analysis_store.update_run(
                run.analysis_id,
                status="completed",
                phase="closed",
                clear_next_recheck_at=True,
            )
            return {
                "executed": True,
                "incident_id": run.incident_id,
                "analysis_id": completed.analysis_id,
                "status": completed.status,
                "current_round": completed.current_round,
                "summary": "告警已恢复，复查后结束分析。",
            }

        self.analysis_store.append_event(
            run.analysis_id,
            "recovery_check",
            "告警仍在发生",
            content_md="到达复查时间，Incident 当前仍为 firing。",
            round_index=run.current_round,
        )

        try:
            result = analysis_agent.run_round(
                incident=incident,
                analysis_run=run,
                analysis_store=self.analysis_store,
                round_index=run.current_round,
            )
            return {
                "executed": True,
                "incident_id": run.incident_id,
                **result,
            }
        except Exception as exc:
            self.analysis_store.append_event(
                run.analysis_id,
                "error",
                f"第{_round_label(run.current_round)}轮复查失败",
                content_md=str(exc),
                round_index=run.current_round,
            )
            failed = self.analysis_store.update_run(
                run.analysis_id,
                status="failed",
            )
            return {
                "error": str(exc),
                "incident_id": run.incident_id,
                "analysis_id": failed.analysis_id,
                "status": failed.status,
                "executed": False,
                "summary": f"复查分析失败：{exc}",
            }


def _round_label(round_index: int) -> str:
    mapping = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五"}
    return mapping.get(round_index, str(round_index))
