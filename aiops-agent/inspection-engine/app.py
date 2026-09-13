from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime
from threading import Lock, Thread
from typing import Any

from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel
from urllib.parse import quote
from urllib.request import urlopen
from zoneinfo import ZoneInfo


app = FastAPI(title="AIOps Inspection Engine")

PROMETHEUS_BASE = os.getenv(
    "PROMETHEUS_BASE",
    "http://prometheus.monitoring.svc.cluster.local:9090",
)
CHANGE_EVENTS_PATH = os.getenv("CHANGE_EVENTS_PATH", "/app/data/change_events.json")
TARGET_NAMESPACES = os.getenv(
    "TARGET_NAMESPACES",
    "aiops,data-services,monitoring",
).split(",")

SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
inspection_jobs: dict[str, dict[str, Any]] = {}
inspection_lock = Lock()
kube_loaded = False


class StopInspectionRequest(BaseModel):
    inspection_id: str


def now_str() -> str:
    return datetime.now(SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def http_get_json(url: str, timeout: int = 8) -> dict[str, Any]:
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def query_prometheus(expr: str) -> list[dict[str, Any]]:
    url = f"{PROMETHEUS_BASE}/api/v1/query?query={quote(expr)}"
    data = http_get_json(url)
    if data.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {expr}")
    return data.get("data", {}).get("result", [])


def get_firing_alert_count() -> int:
    data = http_get_json(f"{PROMETHEUS_BASE}/api/v1/alerts")
    alerts = data.get("data", {}).get("alerts", [])
    return sum(1 for alert in alerts if alert.get("state") == "firing")


def get_success_rate_data() -> dict[str, Any]:
    results = query_prometheus("seckill_order_total")
    if not results:
        return {
            "success_rate": 0.0,
            "success_count": 0,
            "total_count": 0,
            "by_result": {},
        }

    by_result: dict[str, int] = {}
    total_count = 0
    success_count = 0

    for item in results:
        metric = item.get("metric", {})
        result_name = metric.get("result", "unknown")
        value = int(float(item.get("value", [0, "0"])[1]))
        by_result[result_name] = by_result.get(result_name, 0) + value
        total_count += value
        if result_name == "success":
            success_count += value

    success_rate = (success_count / total_count * 100) if total_count else 0.0
    return {
        "success_rate": success_rate,
        "success_count": success_count,
        "total_count": total_count,
        "by_result": by_result,
    }


def load_change_events(limit: int = 5) -> list[dict[str, Any]]:
    if not os.path.exists(CHANGE_EVENTS_PATH):
        return []

    try:
        with open(CHANGE_EVENTS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        return data[-limit:]
    except Exception as exc:
        return [
            {
                "event_id": "chg-read-error",
                "event_time": now_str(),
                "event_type": "system",
                "namespace": "aiops",
                "resource_kind": "File",
                "resource_name": "change_events.json",
                "before_value": "",
                "after_value": "",
                "summary": f"变更归档读取失败: {exc}",
                "operator": "system",
                "source": "inspection-engine",
                "during_incident": False,
            }
        ]


def load_kube_config_once() -> None:
    global kube_loaded
    if kube_loaded:
        return

    try:
        config.load_incluster_config()
        print("[inspection-engine] using in-cluster config")
    except Exception:
        config.load_kube_config()
        print("[inspection-engine] using local kubeconfig")

    kube_loaded = True


def collect_cluster_summary() -> dict[str, Any]:
    load_kube_config_once()

    core = client.CoreV1Api()
    apps = client.AppsV1Api()

    pod_summary: list[dict[str, Any]] = []
    deploy_summary: list[dict[str, Any]] = []

    for namespace in TARGET_NAMESPACES:
        namespace = namespace.strip()
        if not namespace:
            continue

        try:
            pods = core.list_namespaced_pod(namespace=namespace).items
            running = sum(1 for pod in pods if pod.status.phase == "Running")
            pending = sum(1 for pod in pods if pod.status.phase == "Pending")
            failed = sum(1 for pod in pods if pod.status.phase == "Failed")
            pod_summary.append(
                {
                    "namespace": namespace,
                    "total": len(pods),
                    "running": running,
                    "pending": pending,
                    "failed": failed,
                }
            )
        except Exception as exc:
            pod_summary.append(
                {
                    "namespace": namespace,
                    "total": 0,
                    "running": 0,
                    "pending": 0,
                    "failed": 0,
                    "error": str(exc),
                }
            )

        try:
            deps = apps.list_namespaced_deployment(namespace=namespace).items
            deployment_items = []
            for dep in deps:
                containers = dep.spec.template.spec.containers or []
                deployment_items.append(
                    {
                        "name": dep.metadata.name or "",
                        "desired": dep.spec.replicas or 0,
                        "ready": dep.status.ready_replicas or 0,
                        "available": dep.status.available_replicas or 0,
                        "images": [container.image or "" for container in containers],
                    }
                )
            deploy_summary.append(
                {
                    "namespace": namespace,
                    "total": len(deps),
                    "available": sum(
                        1
                        for dep in deps
                        if (dep.status.available_replicas or 0) > 0
                    ),
                    "items": deployment_items,
                }
            )
        except Exception as exc:
            deploy_summary.append(
                {
                    "namespace": namespace,
                    "total": 0,
                    "available": 0,
                    "items": [],
                    "error": str(exc),
                }
            )

    nodes = core.list_node().items
    ready_nodes = 0
    for node in nodes:
        for condition in node.status.conditions or []:
            if condition.type == "Ready" and condition.status == "True":
                ready_nodes += 1
                break

    return {
        "pods": pod_summary,
        "deployments": deploy_summary,
        "nodes": {
            "total": len(nodes),
            "ready": ready_nodes,
            "not_ready": len(nodes) - ready_nodes,
        },
    }


def append_inspection_step(
    inspection_id: str,
    title: str,
    detail: str,
    status: str,
) -> None:
    with inspection_lock:
        job = inspection_jobs.get(inspection_id)
        if not job:
            return

        job["steps"].append(
            {
                "title": title,
                "detail": detail,
                "status": status,
                "timestamp": now_str(),
            }
        )
        job["updated_at"] = now_str()


def build_inspection_text(steps: list[dict[str, Any]]) -> str:
    icon_map = {
        "success": "✓",
        "warn": "!",
        "error": "✗",
    }
    lines: list[str] = []

    for index, step in enumerate(steps, start=1):
        icon = icon_map.get(step.get("status"), "•")
        title = step.get("title", "未命名检查项")
        detail = step.get("detail", "")
        lines.append(f"{icon} {index}. {title}")
        lines.append(f"   {detail}")

    return "\n".join(lines)


def should_stop(inspection_id: str) -> bool:
    with inspection_lock:
        job = inspection_jobs.get(inspection_id)
        return bool(job and job.get("stop_requested"))


def finish_job(
    inspection_id: str,
    status: str,
    summary: str,
    level: str,
    cluster_summary: dict[str, Any] | None = None,
    related_changes: list[dict[str, Any]] | None = None,
) -> None:
    with inspection_lock:
        job = inspection_jobs.get(inspection_id)
        if not job:
            return

        steps = job.get("steps", [])
        job["status"] = status
        job["updated_at"] = now_str()
        job["result"] = {
            "summary": summary,
            "level": level,
            "analysis_input": build_inspection_text(steps),
            "cluster_summary": cluster_summary or {},
            "related_changes": related_changes or [],
        }


def run_inspection_job(inspection_id: str) -> None:
    try:
        time.sleep(0.5)

        if should_stop(inspection_id):
            finish_job(inspection_id, "stopped", "巡检已手动终止。", "info")
            return

        query_prometheus("up")
        append_inspection_step(
            inspection_id,
            "检查 Prometheus 连通性",
            "Prometheus 连通正常，查询接口可访问。",
            "success",
        )

        time.sleep(0.8)
        if should_stop(inspection_id):
            finish_job(inspection_id, "stopped", "巡检已手动终止。", "info")
            return

        firing_count = get_firing_alert_count()
        alert_status = "success" if firing_count == 0 else "warn"
        append_inspection_step(
            inspection_id,
            "检查活跃告警",
            f"当前 firing 告警数量：{firing_count}。",
            alert_status,
        )

        time.sleep(0.8)
        if should_stop(inspection_id):
            finish_job(inspection_id, "stopped", "巡检已手动终止。", "info")
            return

        success_data = get_success_rate_data()
        success_rate = success_data["success_rate"]
        success_count = success_data["success_count"]
        total_count = success_data["total_count"]
        by_result = success_data["by_result"]

        result_parts = [f"{k}={v}" for k, v in sorted(by_result.items())]
        result_text = "，结果分布：" + " / ".join(result_parts) if result_parts else ""

        if success_rate >= 95:
            rate_status = "success"
            rate_detail = (
                f"当前成功率 {success_rate:.2f}% ，整体正常，"
                f"成功 {success_count} 单，总请求 {total_count}。{result_text}"
            )
            final_level = "good"
        elif success_rate >= 80:
            rate_status = "warn"
            rate_detail = (
                f"当前成功率 {success_rate:.2f}% ，略低，"
                f"成功 {success_count} 单，总请求 {total_count}。{result_text}"
            )
            final_level = "warn"
        else:
            rate_status = "error"
            rate_detail = (
                f"当前成功率 {success_rate:.2f}% ，明显偏低，"
                f"成功 {success_count} 单，总请求 {total_count}。{result_text}"
            )
            final_level = "warn"

        append_inspection_step(
            inspection_id,
            "检查业务成功率",
            rate_detail,
            rate_status,
        )

        time.sleep(0.8)
        if should_stop(inspection_id):
            finish_job(inspection_id, "stopped", "巡检已手动终止。", "info")
            return

        cluster_summary = collect_cluster_summary()
        pod_text = "；".join(
            [
                f"{item['namespace']} Pod {item['running']}/{item['total']} Running"
                for item in cluster_summary["pods"]
            ]
        )
        deploy_text = "；".join(
            [
                f"{item['namespace']} Deployment {item['available']}/{item['total']} Available"
                for item in cluster_summary["deployments"]
            ]
        )
        node_text = (
            f"节点 Ready {cluster_summary['nodes']['ready']}/"
            f"{cluster_summary['nodes']['total']}"
        )

        append_inspection_step(
            inspection_id,
            "检查集群工作负载",
            f"{pod_text}。{deploy_text}。{node_text}。",
            "success",
        )

        time.sleep(0.8)
        if should_stop(inspection_id):
            finish_job(inspection_id, "stopped", "巡检已手动终止。", "info")
            return

        recent_changes = load_change_events(limit=5)
        if recent_changes:
            latest = recent_changes[-1]
            change_detail = (
                f"最近 5 条关键变更已纳入分析，最新一条：{latest.get('summary', '无摘要')}。"
            )
        else:
            change_detail = "最近没有读取到关键变更记录。"

        append_inspection_step(
            inspection_id,
            "检查近期关键变更",
            change_detail,
            "success",
        )

        finish_job(
            inspection_id=inspection_id,
            status="completed",
            summary=rate_detail,
            level=final_level,
            cluster_summary=cluster_summary,
            related_changes=recent_changes,
        )
    except Exception as exc:
        append_inspection_step(
            inspection_id,
            "巡检执行异常",
            f"巡检过程中发生异常：{exc}",
            "error",
        )
        finish_job(
            inspection_id,
            "completed",
            f"巡检异常结束：{exc}",
            "error",
        )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/inspection/start")
def start_inspection() -> dict[str, Any]:
    inspection_id = f"inspect-{uuid.uuid4().hex[:8]}"
    created_at = now_str()

    with inspection_lock:
        inspection_jobs[inspection_id] = {
            "inspection_id": inspection_id,
            "status": "queued",
            "created_at": created_at,
            "updated_at": created_at,
            "stop_requested": False,
            "steps": [],
            "result": {
                "summary": "",
                "level": "info",
                "analysis_input": "",
                "cluster_summary": {},
                "related_changes": [],
            },
        }

    def runner() -> None:
        with inspection_lock:
            if inspection_id in inspection_jobs:
                inspection_jobs[inspection_id]["status"] = "running"
                inspection_jobs[inspection_id]["updated_at"] = now_str()
        run_inspection_job(inspection_id)

    Thread(target=runner, daemon=True).start()

    return {
        "inspection_id": inspection_id,
        "status": "queued",
        "message": "巡检任务已启动。",
    }


@app.get("/api/inspection/{inspection_id}")
def get_inspection(inspection_id: str) -> dict[str, Any]:
    with inspection_lock:
        job = inspection_jobs.get(inspection_id)
        if not job:
            raise HTTPException(status_code=404, detail="inspection not found")
        return job


@app.post("/api/inspection/stop")
def stop_inspection(payload: StopInspectionRequest) -> dict[str, Any]:
    with inspection_lock:
        job = inspection_jobs.get(payload.inspection_id)
        if not job:
            raise HTTPException(status_code=404, detail="inspection not found")
        job["stop_requested"] = True
        job["updated_at"] = now_str()

    return {
        "inspection_id": payload.inspection_id,
        "status": "stopping",
        "message": "已请求停止巡检。",
    }
