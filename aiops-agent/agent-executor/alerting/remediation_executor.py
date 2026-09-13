from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any


ACTION_ANNOTATION = "aiops.local/remediation-action-id"
TIME_ANNOTATION = "aiops.local/remediation-requested-at"


def _apps_api() -> Any:
    from kubernetes import client, config
    from kubernetes.config.config_exception import ConfigException

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()
    return client.AppsV1Api()


def execute_rollback_deployment(action: Any) -> dict[str, Any]:
    """Execute one approved rollback with a current-image precondition."""
    apps = _apps_api()
    try:
        deployment = apps.read_namespaced_deployment(
            action.target_name,
            action.namespace,
        )
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        raise RuntimeError(
            f"kubernetes deployment read failed: {status or 'unknown'}"
        ) from exc

    containers = list(deployment.spec.template.spec.containers or [])
    container = next(
        (item for item in containers if item.name == action.container_name),
        None,
    )
    if container is None:
        raise RuntimeError("target container was not found in Deployment")
    observed_image = str(container.image or "").strip()
    if observed_image != action.current_image:
        raise RuntimeError(
            "current image changed after approval request: "
            f"expected {action.current_image}, observed {observed_image}"
        )

    requested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        ACTION_ANNOTATION: action.action_id,
                        TIME_ANNOTATION: requested_at,
                    }
                },
                "spec": {
                    "containers": [
                        {
                            "name": action.container_name,
                            "image": action.target_image,
                        }
                    ]
                },
            }
        }
    }
    try:
        updated = apps.patch_namespaced_deployment(
            action.target_name,
            action.namespace,
            patch,
        )
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        raise RuntimeError(
            f"kubernetes deployment patch failed: {status or 'unknown'}"
        ) from exc

    return {
        "status": "accepted",
        "action_id": action.action_id,
        "namespace": action.namespace,
        "target_name": action.target_name,
        "container_name": action.container_name,
        "previous_image": observed_image,
        "target_image": action.target_image,
        "generation": int(updated.metadata.generation or 0),
        "requested_at": requested_at,
    }


def execute_scale_deployment(action: Any) -> dict[str, Any]:
    """Execute one approved one-step scale-out with a replica precondition."""
    current_replicas = int(action.current_replicas)
    target_replicas = int(action.target_replicas)
    max_replicas = max(1, int(os.getenv("AIOPS_SCALE_MAX_REPLICAS", "3")))
    if current_replicas < 1:
        raise RuntimeError("current replicas must be at least 1")
    if target_replicas != current_replicas + 1:
        raise RuntimeError("approved scale-out must add exactly one replica")
    if target_replicas > max_replicas:
        raise RuntimeError("target replicas exceed the configured safety limit")

    apps = _apps_api()
    try:
        deployment = apps.read_namespaced_deployment(
            action.target_name,
            action.namespace,
        )
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        raise RuntimeError(
            f"kubernetes deployment read failed: {status or 'unknown'}"
        ) from exc

    observed_replicas = int(deployment.spec.replicas or 0)
    if observed_replicas != current_replicas:
        raise RuntimeError(
            "replica count changed after approval request: "
            f"expected {current_replicas}, observed {observed_replicas}"
        )

    requested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    patch = {
        "metadata": {
            "annotations": {
                ACTION_ANNOTATION: action.action_id,
                TIME_ANNOTATION: requested_at,
            }
        },
        "spec": {"replicas": target_replicas},
    }
    try:
        updated = apps.patch_namespaced_deployment(
            action.target_name,
            action.namespace,
            patch,
        )
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        raise RuntimeError(
            f"kubernetes deployment patch failed: {status or 'unknown'}"
        ) from exc

    return {
        "status": "accepted",
        "action_id": action.action_id,
        "namespace": action.namespace,
        "target_name": action.target_name,
        "previous_replicas": observed_replicas,
        "target_replicas": target_replicas,
        "generation": int(updated.metadata.generation or 0),
        "requested_at": requested_at,
    }
