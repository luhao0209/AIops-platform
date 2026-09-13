import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
CHANGE_EVENTS_FILE = DATA_DIR / "change_events.json"
SNAPSHOT_FILE = DATA_DIR / "cluster_snapshot.json"
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "300"))
TARGET_NAMESPACES = [ns.strip() for ns in os.getenv("WATCH_NAMESPACES", "aiops,data-services,monitoring").split(",") if ns.strip()]


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def load_json_file(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(path: Path, data) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def append_events(new_events: list[dict]) -> None:
    if not new_events:
        return

    existing = load_json_file(CHANGE_EVENTS_FILE, [])
    if not isinstance(existing, list):
        existing = []

    existing.extend(new_events)
    existing = existing[-MAX_EVENTS:]
    save_json_file(CHANGE_EVENTS_FILE, existing)


def infer_role(namespace: str, name: str, kind: str) -> str:
    text = f"{namespace}/{kind}/{name}".lower()
    if "gateway" in text:
        return "网关流量入口"
    if "prometheus" in text:
        return "监控指标采集与查询"
    if "grafana" in text:
        return "可视化看板"
    if "loki" in text or "promtail" in text:
        return "日志采集与检索"
    if "mysql" in text:
        return "数据库服务"
    if "redis" in text:
        return "缓存服务"
    if "agent" in text:
        return "AIOps 智能运维"
    return "集群工作负载"


def load_kube_config() -> None:
    try:
        config.load_incluster_config()
        print("[watcher] using in-cluster config")
    except ConfigException:
        config.load_kube_config()
        print("[watcher] using local kubeconfig")


def build_snapshot() -> dict:
    apps = client.AppsV1Api()
    core = client.CoreV1Api()

    snapshot = {
        "generated_at": now_str(),
        "deployments": {},
        "pods": {},
        "configmaps": {},
        "nodes": {},
    }

    for namespace in TARGET_NAMESPACES:
        for dep in apps.list_namespaced_deployment(namespace=namespace).items:
            key = f"{namespace}/{dep.metadata.name}"
            images = [c.image for c in dep.spec.template.spec.containers]
            snapshot["deployments"][key] = {
                "namespace": namespace,
                "name": dep.metadata.name,
                "replicas": dep.spec.replicas or 0,
                "available_replicas": dep.status.available_replicas or 0,
                "images": images,
                "labels": dep.metadata.labels or {},
            }

        for pod in core.list_namespaced_pod(namespace=namespace).items:
            key = f"{namespace}/{pod.metadata.name}"
            owner = pod.metadata.owner_references[0].kind + "/" + pod.metadata.owner_references[0].name if pod.metadata.owner_references else "Unknown"
            images = [c.image for c in pod.spec.containers]
            snapshot["pods"][key] = {
                "namespace": namespace,
                "name": pod.metadata.name,
                "phase": pod.status.phase,
                "node": pod.spec.node_name or "",
                "owner": owner,
                "images": images,
                "pod_ip": pod.status.pod_ip or "",
            }

        for cm in core.list_namespaced_config_map(namespace=namespace).items:
            if cm.metadata.name.startswith("kube-root-ca"):
                continue
            key = f"{namespace}/{cm.metadata.name}"
            content = json.dumps(cm.data or {}, ensure_ascii=False, sort_keys=True)
            snapshot["configmaps"][key] = {
                "namespace": namespace,
                "name": cm.metadata.name,
                "hash": sha_text(content),
            }

    for node in core.list_node().items:
        name = node.metadata.name
        labels = node.metadata.labels or {}
        node_role = "worker"
        if "node-role.kubernetes.io/control-plane" in labels:
            node_role = "control-plane"
        snapshot["nodes"][name] = {
            "name": name,
            "role": node_role,
            "schedulable": not bool(node.spec.unschedulable),
            "internal_ip": next((a.address for a in (node.status.addresses or []) if a.type == "InternalIP"), ""),
        }

    return snapshot


def new_event(event_type: str, namespace: str, resource_kind: str, resource_name: str, before_value: str, after_value: str, summary: str, operator: str = "change-watcher", source: str = "cluster") -> dict:
    raw = f"{event_type}|{namespace}|{resource_kind}|{resource_name}|{before_value}|{after_value}|{summary}|{time.time()}"
    return {
        "event_id": f"chg-{sha_text(raw)}",
        "event_time": now_str(),
        "event_type": event_type,
        "namespace": namespace,
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "before_value": before_value,
        "after_value": after_value,
        "summary": summary,
        "operator": operator,
        "source": source,
        "during_incident": False,
    }


def diff_deployments(old: dict, new: dict) -> list[dict]:
    events = []
    old_keys = set(old)
    new_keys = set(new)

    for key in sorted(new_keys - old_keys):
        item = new[key]
        role = infer_role(item["namespace"], item["name"], "Deployment")
        events.append(new_event("deploy", item["namespace"], "Deployment", item["name"], "", ",".join(item["images"]), f"新增 Deployment {item['name']}，当前副本 {item['replicas']}，作用倾向：{role}"))

    for key in sorted(old_keys - new_keys):
        item = old[key]
        events.append(new_event("deploy", item["namespace"], "Deployment", item["name"], ",".join(item["images"]), "", f"Deployment {item['name']} 已从命名空间 {item['namespace']} 消失"))

    for key in sorted(old_keys & new_keys):
        before = old[key]
        after = new[key]
        if before["replicas"] != after["replicas"]:
            events.append(new_event("scale", after["namespace"], "Deployment", after["name"], str(before["replicas"]), str(after["replicas"]), f"{after['name']} 副本数变化（{before['replicas']} -> {after['replicas']}）"))
        if before["images"] != after["images"]:
            events.append(new_event("image", after["namespace"], "Deployment", after["name"], ",".join(before["images"]), ",".join(after["images"]), f"{after['name']} 镜像版本变化（{','.join(before['images'])} -> {','.join(after['images'])}）"))

    return events


def diff_pods(old: dict, new: dict) -> list[dict]:
    events = []
    old_keys = set(old)
    new_keys = set(new)

    for key in sorted(new_keys - old_keys):
        item = new[key]
        role = infer_role(item["namespace"], item["name"], "Pod")
        events.append(new_event("topology", item["namespace"], "Pod", item["name"], "", item["phase"], f"新增 Pod {item['name']}，位于节点 {item['node']}，归属 {item['owner']}，作用倾向：{role}"))

    for key in sorted(old_keys - new_keys):
        item = old[key]
        events.append(new_event("topology", item["namespace"], "Pod", item["name"], item["phase"], "", f"Pod {item['name']} 已消失，原节点 {item['node']}，归属 {item['owner']}"))

    return events


def diff_configmaps(old: dict, new: dict) -> list[dict]:
    events = []
    old_keys = set(old)
    new_keys = set(new)

    for key in sorted(new_keys - old_keys):
        item = new[key]
        events.append(new_event("config", item["namespace"], "ConfigMap", item["name"], "", item["hash"], f"新增 ConfigMap {item['name']}"))

    for key in sorted(old_keys - new_keys):
        item = old[key]
        events.append(new_event("config", item["namespace"], "ConfigMap", item["name"], item["hash"], "", f"ConfigMap {item['name']} 已删除"))

    for key in sorted(old_keys & new_keys):
        before = old[key]
        after = new[key]
        if before["hash"] != after["hash"]:
            events.append(new_event("config", after["namespace"], "ConfigMap", after["name"], before["hash"], after["hash"], f"ConfigMap {after['name']} 内容发生变化"))

    return events


def diff_nodes(old: dict, new: dict) -> list[dict]:
    events = []
    old_keys = set(old)
    new_keys = set(new)

    for key in sorted(new_keys - old_keys):
        item = new[key]
        events.append(new_event("infrastructure", "infra", "Node", item["name"], "", item["internal_ip"], f"新增节点 {item['name']}，角色 {item['role']}，内部地址 {item['internal_ip']}"))

    for key in sorted(old_keys - new_keys):
        item = old[key]
        events.append(new_event("infrastructure", "infra", "Node", item["name"], item["internal_ip"], "", f"节点 {item['name']} 已从集群中移除"))

    return events


def diff_snapshots(old_snapshot: dict, new_snapshot: dict) -> list[dict]:
    return (
        diff_deployments(old_snapshot.get("deployments", {}), new_snapshot.get("deployments", {}))
        + diff_pods(old_snapshot.get("pods", {}), new_snapshot.get("pods", {}))
        + diff_configmaps(old_snapshot.get("configmaps", {}), new_snapshot.get("configmaps", {}))
        + diff_nodes(old_snapshot.get("nodes", {}), new_snapshot.get("nodes", {}))
    )


def main() -> None:
    ensure_data_dir()
    load_kube_config()

    previous = load_json_file(SNAPSHOT_FILE, None)
    if previous is None:
        current = build_snapshot()
        save_json_file(SNAPSHOT_FILE, current)
        print("[watcher] initial snapshot created")
    else:
        print("[watcher] loaded existing snapshot")

    while True:
        try:
            current = build_snapshot()
            previous = load_json_file(SNAPSHOT_FILE, None)
            if previous:
                events = diff_snapshots(previous, current)
                if events:
                    append_events(events)
                    print(f"[watcher] appended {len(events)} change events")
                else:
                    print("[watcher] no critical change detected")
            save_json_file(SNAPSHOT_FILE, current)
        except Exception as exc:
            print(f"[watcher] loop failed: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
