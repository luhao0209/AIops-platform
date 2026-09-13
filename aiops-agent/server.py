from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request as UrlRequest, urlopen

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
WEB_FILE = BASE_DIR / "web.html"

PROMETHEUS_BASE = "http://prometheus.monitoring.svc.cluster.local:9090"
INSPECTION_ENGINE_BASE = "http://inspection-engine.aiops.svc.cluster.local:9100"
SOP_SERVICE_BASE = "http://sop-service.aiops.svc.cluster.local:9200"
AGENT_EXECUTOR_BASE = "http://agent-executor.aiops.svc.cluster.local:9300"
BUSINESS_GATEWAY_BASE = os.getenv(
    "BUSINESS_GATEWAY_BASE",
    "http://biz-gateway-svc.data-services.svc.cluster.local:8000",
).rstrip("/")
BUSINESS_METRICS_NAMESPACE = os.getenv(
    "AIOPS_BUSINESS_NAMESPACE",
    "data-services",
).strip()
GRAFANA_BUSINESS_DASHBOARD_URL = os.getenv(
    "GRAFANA_BUSINESS_DASHBOARD_URL",
    "",
)
GRAFANA_NODE_DASHBOARD_URL = os.getenv(
    "GRAFANA_NODE_DASHBOARD_URL",
    "",
)

SECKILL_PRODUCT_IDS = [
    "PROD_618_001",
    "PROD_618_002",
    "PROD_618_003",
    "PROD_618_004",
    "PROD_618_005",
]


SERVICE_LEVEL_WINDOW = "30d"
SERVICE_LEVEL_WINDOW_LABEL = "最近30天"
SERVICE_LEVEL_SLO_TARGET = 99.9


BUSINESS_ALERT_NAMES = {
    "GatewayLatency",
    "MySQLLockWait",
    "RedisHitDrop",
    "OrderTechnicalAvailabilityLow",
}
INFRA_ALERT_NAMES = {
    "NodeCPUHigh",
    "NodeMemoryHigh",
    "PodCrashLoop",
    "DiskPressure",
}


DEMO_MAIN_AGENT_TOKENS = 0
DEMO_VECTOR_AGENT_TOKENS = 0

CHANGE_EVENTS_FILE = DATA_DIR / "change_events.json"

AUTH_USERNAME = os.getenv("AIOPS_AUTH_USERNAME", "").strip()
AUTH_PASSWORD = os.getenv("AIOPS_AUTH_PASSWORD", "")
AUTH_SESSION_SECRET = os.getenv("AIOPS_AUTH_SESSION_SECRET", "")
AUTH_SESSION_TTL_SECONDS = int(os.getenv("AIOPS_AUTH_SESSION_TTL_SECONDS", "43200"))
AUTH_COOKIE_SECURE = os.getenv("AIOPS_AUTH_COOKIE_SECURE", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
AUTH_COOKIE_NAME = "aiops_session"
AUTH_MAX_FAILURES = 5
AUTH_FAILURE_WINDOW_SECONDS = 300
AUTH_LOCK_SECONDS = 900
AUTH_PUBLIC_PATHS = {"/login", "/api/auth/login", "/healthz"}

if not AUTH_USERNAME or not AUTH_PASSWORD or len(AUTH_SESSION_SECRET) < 32:
    raise RuntimeError(
        "AIOps web authentication is not configured. Set AIOPS_AUTH_USERNAME, "
        "AIOPS_AUTH_PASSWORD and AIOPS_AUTH_SESSION_SECRET (at least 32 characters)."
    )


LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AIOps Copilot 登录</title>
  <style>
    :root { color-scheme: light; font-family: Inter, "PingFang SC", "Microsoft YaHei", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f7fb; color: #172033; }
    .login-card { width: min(420px, calc(100vw - 32px)); padding: 34px; border: 1px solid #dce3ed; border-radius: 16px; background: #fff; box-shadow: 0 18px 55px rgba(31, 47, 76, .12); }
    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 20px; font-weight: 700; }
    .brand-dot { width: 10px; height: 10px; border-radius: 50%; background: #111827; }
    .hint { margin: 0 0 24px; color: #667085; font-size: 14px; }
    label { display: block; margin: 14px 0 7px; color: #344054; font-size: 14px; font-weight: 600; }
    input { width: 100%; height: 44px; padding: 0 12px; border: 1px solid #cfd7e3; border-radius: 8px; outline: none; font: inherit; }
    input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37, 99, 235, .12); }
    button { width: 100%; height: 44px; margin-top: 22px; border: 0; border-radius: 8px; background: #172033; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
    button:disabled { cursor: wait; opacity: .65; }
    .error { min-height: 20px; margin-top: 12px; color: #d92d20; font-size: 13px; }
  </style>
</head>
<body>
  <main class="login-card">
    <div class="brand"><span class="brand-dot"></span><span>AIOps Copilot</span></div>
    <p class="hint">请输入账号和密码后进入运维控制台。</p>
    <form id="login-form">
      <label for="username">账号</label>
      <input id="username" name="username" autocomplete="username" required autofocus />
      <label for="password">密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button id="submit-btn" type="submit">登录</button>
      <div class="error" id="login-error" role="alert"></div>
    </form>
  </main>
  <script>
    const form = document.getElementById("login-form");
    const submitBtn = document.getElementById("submit-btn");
    const errorEl = document.getElementById("login-error");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorEl.textContent = "";
      submitBtn.disabled = true;
      submitBtn.textContent = "登录中...";
      const next = new URLSearchParams(location.search).get("next") || "/web.html";
      try {
        const response = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value,
            next
          })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || "登录失败");
        location.replace(result.redirect_to || "/web.html");
      } catch (error) {
        errorEl.textContent = error.message || "登录失败，请稍后重试";
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "登录";
      }
    });
  </script>
</body>
</html>
"""


app = FastAPI(title="AIOps Agent Demo", docs_url=None, redoc_url=None)


_auth_attempts: dict[str, dict[str, Any]] = {}
_auth_attempts_lock = threading.Lock()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _create_session_token() -> str:
    issued_at = int(time.time())
    nonce = secrets.token_urlsafe(12)
    payload = f"{AUTH_USERNAME}\n{issued_at}\n{nonce}".encode("utf-8")
    signature = hmac.new(
        AUTH_SESSION_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).digest()
    return f"{_base64url_encode(payload)}.{_base64url_encode(signature)}"


def _session_username(token: str | None) -> str | None:
    if not token:
        return None
    try:
        payload_part, signature_part = token.split(".", 1)
        payload = _base64url_decode(payload_part)
        supplied_signature = _base64url_decode(signature_part)
        expected_signature = hmac.new(
            AUTH_SESSION_SECRET.encode("utf-8"), payload, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        username, issued_at_text, _nonce = payload.decode("utf-8").split("\n", 2)
        issued_at = int(issued_at_text)
        age = int(time.time()) - issued_at
        if username != AUTH_USERNAME or age < 0 or age > AUTH_SESSION_TTL_SECONDS:
            return None
        return username
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None


def _safe_next_path(value: str | None) -> str:
    if (
        not value
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        return "/web.html"
    return value


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_retry_after(client_key: str) -> int:
    now = time.time()
    with _auth_attempts_lock:
        state = _auth_attempts.get(client_key)
        if not state:
            return 0
        locked_until = float(state.get("locked_until", 0))
        if locked_until > now:
            return max(1, int(locked_until - now))
        attempts = [
            attempt
            for attempt in state.get("attempts", [])
            if now - attempt <= AUTH_FAILURE_WINDOW_SECONDS
        ]
        if attempts:
            state["attempts"] = attempts
        else:
            _auth_attempts.pop(client_key, None)
        return 0


def _record_login_failure(client_key: str) -> int:
    now = time.time()
    with _auth_attempts_lock:
        state = _auth_attempts.setdefault(
            client_key, {"attempts": [], "locked_until": 0.0}
        )
        attempts = [
            attempt
            for attempt in state.get("attempts", [])
            if now - attempt <= AUTH_FAILURE_WINDOW_SECONDS
        ]
        attempts.append(now)
        state["attempts"] = attempts
        if len(attempts) >= AUTH_MAX_FAILURES:
            state["locked_until"] = now + AUTH_LOCK_SECONDS
            return AUTH_LOCK_SECONDS
        return 0


def _clear_login_failures(client_key: str) -> None:
    with _auth_attempts_lock:
        _auth_attempts.pop(client_key, None)


@app.middleware("http")
async def require_web_authentication(request: Request, call_next):
    path = request.url.path
    if path not in AUTH_PUBLIC_PATHS:
        username = _session_username(request.cookies.get(AUTH_COOKIE_NAME))
        if not username:
            if path.startswith("/api/"):
                response = JSONResponse(
                    status_code=401,
                    content={"detail": "登录状态已失效，请重新登录"},
                )
            else:
                next_path = _safe_next_path(
                    path + (f"?{request.url.query}" if request.url.query else "")
                )
                response = RedirectResponse(
                    url=f"/login?next={quote(next_path, safe='')}", status_code=303
                )
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if AUTH_COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

if DATA_DIR.exists():
    app.mount("/data", StaticFiles(directory=str(DATA_DIR)), name="data")


class StopInspectionRequest(BaseModel):
    inspection_id: str


class RemediationDecisionRequest(BaseModel):
    decided_by: str = Field(default="web-sre", min_length=1, max_length=80)
    comment: str = Field(default="", max_length=500)


class KnowledgeStepInput(BaseModel):
    step_order: int | None = None
    action: str
    recommended_command: str = ""
    output_focus: str = ""


class KnowledgeFileCreateRequest(BaseModel):
    title: str
    type: str = "official_sop"
    file_name: str = ""
    summary: str = ""
    scene: str = ""
    symptoms: list[str] | str = Field(default_factory=list)
    applicable_components: list[str] | str = Field(default_factory=list)
    recommended_steps: list[KnowledgeStepInput] | str = Field(default_factory=list)
    trigger_conditions: list[str] | str = Field(default_factory=list)
    tags: list[str] | str = Field(default_factory=list)
    risk_warnings: str = ""
    rollback_advice: str = ""
    created_by: str = "web-user"
    markdown_content: str = ""


class KnowledgeFileUpdateRequest(BaseModel):
    title: str | None = None
    type: str | None = None
    summary: str | None = None
    scene: str | None = None
    symptoms: list[str] | str | None = None
    applicable_components: list[str] | str | None = None
    recommended_steps: list[KnowledgeStepInput] | str | None = None
    trigger_conditions: list[str] | str | None = None
    tags: list[str] | str | None = None
    risk_warnings: str | None = None
    rollback_advice: str | None = None
    created_by: str | None = None
    markdown_content: str | None = None


class KnowledgeSearchRequest(BaseModel):
    symptom_query: str
    component_tag: str | None = None
    top_k: int = 3
    knowledge_type: str | None = None


class ChatHistoryItem(BaseModel):
    role: str
    content: str


class ChatRequestPayload(BaseModel):
    message: str
    mode: str = "chat"
    history: list[ChatHistoryItem] = Field(default_factory=list)
    context: dict = Field(default_factory=dict)
    current_incident: dict | None = None


class CreateChatSessionRequest(BaseModel):
    title: str = "新对话"


class LoginRequest(BaseModel):
    username: str
    password: str
    next: str = "/web.html"


def http_get_json(url: str, timeout: int = 8):
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def post_json(url: str, payload: dict, timeout: int = 20):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = UrlRequest(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def put_json(url: str, payload: dict, timeout: int = 20):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = UrlRequest(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def delete_json(url: str, timeout: int = 20):
    request = UrlRequest(url, method="DELETE")
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def query_prometheus(promql: str):
    url = f"{PROMETHEUS_BASE}/api/v1/query?{urlencode({'query': promql})}"
    payload = http_get_json(url)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")
    return payload["data"]["result"]


def get_firing_alert_count():
    return get_alert_breakdown()["total"]


def get_inventory_snapshot():
    product_items = []
    total_stock = 0

    try:
        results = query_prometheus("seckill_inventory_stock")
    except Exception:
        results = []

    for item in results:
        metric = item.get("metric", {})
        value = int(float(item["value"][1]))
        product_id = metric.get("product_id", "unknown")
        total_stock += value
        product_items.append({"product_id": product_id, "stock": value})


    if not product_items:
        for product_id in SECKILL_PRODUCT_IDS:
            try:
                payload = http_get_json(
                    f"{BUSINESS_GATEWAY_BASE}/api/seckill/state/{product_id}",
                    timeout=3,
                )
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                continue

            data = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(data, dict):
                continue

            stock_value = None
            mysql_snapshot = data.get("mysql_stock")
            if isinstance(mysql_snapshot, dict) and mysql_snapshot.get("stock") is not None:
                stock_value = int(mysql_snapshot["stock"])
            elif data.get("redis_stock") is not None:
                stock_value = int(data["redis_stock"])

            if stock_value is None:
                continue
            product_items.append({"product_id": product_id, "stock": stock_value})
            total_stock += stock_value

    product_items.sort(key=lambda x: x["product_id"])
    return total_stock, product_items


def get_business_success_context() -> dict[str, Any]:

    query = urlencode({"namespace": BUSINESS_METRICS_NAMESPACE})
    payload = http_get_json(
        f"{AGENT_EXECUTOR_BASE}/api/metrics/business-success-context?{query}",
        timeout=12,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("invalid business success context response")
    if payload.get("error"):
        raise RuntimeError(str(payload.get("error")))
    return payload


def _business_scope(
    context: dict[str, Any],
    scope_name: str,
) -> dict[str, Any]:
    scopes = context.get("scopes")
    if not isinstance(scopes, dict):
        raise RuntimeError("business success context has no scopes")
    scope = scopes.get(scope_name)
    if not isinstance(scope, dict):
        raise RuntimeError(f"business success context has no {scope_name} scope")
    return scope


def _purchase_summary_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    success = float(scope.get("success_count") or 0.0)
    failure = float(scope.get("failure_count") or 0.0)
    effective = float(scope.get("effective_count") or 0.0)
    raw_total = float(scope.get("raw_total_count") or 0.0)
    excluded = float(scope.get("excluded_count") or 0.0)
    success_rate = scope.get("success_rate")
    return {
        "success_rate": (
            round(float(success_rate), 2)
            if isinstance(success_rate, (int, float))
            else 0.0
        ),
        "success_orders": round(success, 4),
        "failed_orders": round(failure, 4),
        "total_orders": int(effective),
        "raw_total_orders": int(raw_total),
        "excluded_orders": int(excluded),
        "effective_orders": round(effective, 4),
        "distribution": dict(scope.get("distribution") or {}),
    }


def get_recent_order_summary(
    window: str = "15m",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if window != "15m":
        raise ValueError("dashboard purchase summary supports only the 15m scope")
    source = context or get_business_success_context()
    return _purchase_summary_from_scope(
        _business_scope(source, "recent_15m")
    )


def get_all_time_order_summary(
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:

    source = context or get_business_success_context()
    summary = _purchase_summary_from_scope(
        _business_scope(source, "instance_lifetime")
    )
    success_orders = int(round(summary["success_orders"]))
    failed_orders = int(round(summary["failed_orders"]))
    return {
        **summary,
        "success_orders": success_orders,
        "failed_orders": failed_orders,
        "order_result_text": f"{success_orders} / {failed_orders}",
    }


def _service_level_no_data(reason: str) -> dict[str, Any]:
    return {
        "window": SERVICE_LEVEL_WINDOW,
        "window_label": SERVICE_LEVEL_WINDOW_LABEL,
        "sli": None,
        "sli_text": "NoData",
        "sli_level": "warn",
        "sli_5m": None,
        "sli_5m_text": "NoData",
        "sli_5m_level": "warn",
        "burn_rate_5m": None,
        "burn_rate_5m_text": "NoData",
        "burn_rate_5m_level": "warn",
        "slo_target": SERVICE_LEVEL_SLO_TARGET,
        "slo_target_text": f"{SERVICE_LEVEL_SLO_TARGET:.2f}%",
        "error_budget_remaining": None,
        "error_budget_text": "NoData",
        "error_budget_level": "warn",
        "effective_requests": 0.0,
        "success_requests": 0.0,
        "failed_requests": 0.0,
        "reason": reason,
        "source_of_truth": "agent-executor",
    }


def get_service_level_summary(
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:

    try:
        source = context or get_business_success_context()
        sli_scope = _business_scope(source, "sli_30d")
    except Exception as exc:
        return _service_level_no_data(f"query_failed: {exc}")

    technical_policy = source.get("technical_sli_policy") or {}
    scopes = source.get("scopes") if isinstance(source.get("scopes"), dict) else {}
    short_sli_scope = (
        scopes.get("sli_5m")
        if isinstance(scopes.get("sli_5m"), dict)
        else {}
    )
    budget = source.get("error_budget") or {}
    sli = sli_scope.get("sli_percent")
    short_sli = short_sli_scope.get("sli_percent")
    remaining_budget = budget.get("remaining_percent")
    slo_target = float(
        technical_policy.get("slo_target_percent")
        or SERVICE_LEVEL_SLO_TARGET
    )
    window = str(technical_policy.get("sli_window") or SERVICE_LEVEL_WINDOW)

    if isinstance(short_sli, (int, float)):
        short_sli_value = float(short_sli)
        if short_sli_value >= slo_target:
            short_sli_level = "good"
        elif short_sli_value >= 90:
            short_sli_level = "warn"
        else:
            short_sli_level = "bad"
        allowed_error_rate = max(0.000001, 100.0 - slo_target)
        burn_rate_5m = max(0.0, 100.0 - short_sli_value) / allowed_error_rate
        if burn_rate_5m <= 1.0:
            burn_rate_5m_level = "good"
        elif burn_rate_5m <= 6.0:
            burn_rate_5m_level = "warn"
        else:
            burn_rate_5m_level = "bad"
        short_sli_text = f"{short_sli_value:.2f}%"
        burn_rate_5m_text = f"{burn_rate_5m:.2f}x"
    else:
        short_sli_value = None
        short_sli_level = "warn"
        burn_rate_5m = None
        burn_rate_5m_level = "warn"
        short_sli_text = "NoData"
        burn_rate_5m_text = "NoData"

    if not isinstance(sli, (int, float)):
        no_data = _service_level_no_data(
            str(sli_scope.get("status") or "no_effective_requests")
        )
        no_data.update(
            {
                "window": window,
                "window_label": f"最近{window}",
                "slo_target": slo_target,
                "slo_target_text": f"{slo_target:.2f}%",
            }
        )
        return no_data

    if float(sli) >= slo_target:
        sli_level = "good"
    elif float(sli) >= 90:
        sli_level = "warn"
    else:
        sli_level = "bad"

    if isinstance(remaining_budget, (int, float)):
        if float(remaining_budget) > 50:
            budget_level = "good"
        elif float(remaining_budget) > 0:
            budget_level = "warn"
        else:
            budget_level = "bad"
        budget_text = f"{float(remaining_budget):.2f}%"
    else:
        budget_level = "warn"
        budget_text = "NoData"

    return {
        "window": window,
        "window_label": f"最近{window}",
        "sli": round(float(sli), 4),
        "sli_text": f"{float(sli):.2f}%",
        "sli_level": sli_level,
        "sli_5m": (
            round(short_sli_value, 4)
            if short_sli_value is not None
            else None
        ),
        "sli_5m_text": short_sli_text,
        "sli_5m_level": short_sli_level,
        "sli_5m_effective_requests": float(
            short_sli_scope.get("effective_count") or 0.0
        ),
        "sli_5m_failed_requests": float(
            short_sli_scope.get("technical_failure_count") or 0.0
        ),
        "burn_rate_5m": (
            round(burn_rate_5m, 4)
            if burn_rate_5m is not None
            else None
        ),
        "burn_rate_5m_text": burn_rate_5m_text,
        "burn_rate_5m_level": burn_rate_5m_level,
        "slo_target": slo_target,
        "slo_target_text": f"{slo_target:.2f}%",
        "error_budget_remaining": (
            round(float(remaining_budget), 4)
            if isinstance(remaining_budget, (int, float))
            else None
        ),
        "error_budget_text": budget_text,
        "error_budget_level": budget_level,
        "error_budget_exhausted": (
            isinstance(remaining_budget, (int, float))
            and float(remaining_budget) <= 0
        ),
        "effective_requests": float(sli_scope.get("effective_count") or 0.0),
        "success_requests": float(sli_scope.get("good_count") or 0.0),
        "failed_requests": float(
            sli_scope.get("technical_failure_count") or 0.0
        ),
        "raw_requests": float(sli_scope.get("raw_total_count") or 0.0),
        "excluded_requests": float(sli_scope.get("excluded_count") or 0.0),
        "excluded_results": list(
            technical_policy.get("excluded_business_results") or []
        ),
        "technical_failure_results": list(
            technical_policy.get("technical_failure_results") or []
        ),
        "sli_type": str(
            sli_scope.get("sli_type") or "technical_availability"
        ),
        "reason": "",
        "source_of_truth": str(
            source.get("source_of_truth") or "agent-executor"
        ),
    }


def get_order_latency_ms(window: str = "15m") -> float | None:
    promql = (
        f"sum(rate(db_request_latency_seconds_sum[{window}])) "
        f"/ sum(rate(db_request_latency_seconds_count[{window}]))"
    )
    try:
        results = query_prometheus(promql)
    except Exception:
        return None
    if not results:
        return None
    try:
        seconds = float(results[0]["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if seconds != seconds:
        return None
    return round(seconds * 1000, 1)


def get_token_usage_today() -> dict[str, Any]:
    main_agent = DEMO_MAIN_AGENT_TOKENS
    main_agent_total = DEMO_MAIN_AGENT_TOKENS
    vector_agent = DEMO_VECTOR_AGENT_TOKENS
    vector_agent_total = DEMO_VECTOR_AGENT_TOKENS
    estimated = False
    date_text = ""

    try:
        main_payload = http_get_json(f"{AGENT_EXECUTOR_BASE}/api/token-usage/today", timeout=3)
        if isinstance(main_payload, dict):
            main_agent = int(main_payload.get("main_agent") or 0)
            main_agent_total = int(main_payload.get("main_agent_total") or main_agent)
            estimated = estimated or bool(main_payload.get("estimated"))
            date_text = str(main_payload.get("date") or date_text)
    except Exception:
        pass

    try:
        vector_payload = http_get_json(f"{SOP_SERVICE_BASE}/api/token-usage/today", timeout=3)
        if isinstance(vector_payload, dict):
            vector_agent = int(vector_payload.get("vector_agent") or 0)
            vector_agent_total = int(vector_payload.get("vector_agent_total") or vector_agent)
            estimated = estimated or bool(vector_payload.get("estimated"))
            if not date_text:
                date_text = str(vector_payload.get("date") or "")
    except Exception:
        pass

    return {
        "date": date_text,
        "main_agent": main_agent,
        "main_agent_total": main_agent_total,
        "vector_agent": vector_agent,
        "vector_agent_total": vector_agent_total,
        "total": main_agent + vector_agent,
        "total_all_time": main_agent_total + vector_agent_total,
        "estimated": estimated,
    }


def get_alert_breakdown():
    url = f"{PROMETHEUS_BASE}/api/v1/alerts"
    payload = http_get_json(url)
    if payload.get("status") != "success":
        return {"total": 0, "business": 0, "infrastructure": 0}

    business_alerts = BUSINESS_ALERT_NAMES
    infrastructure_alerts = INFRA_ALERT_NAMES

    total = 0
    business = 0
    infrastructure = 0

    for alert in payload.get("data", {}).get("alerts", []):
        if alert.get("state") != "firing":
            continue
        total += 1
        name = alert.get("labels", {}).get("alertname", "")
        if name in business_alerts:
            business += 1
        elif name in infrastructure_alerts:
            infrastructure += 1

    return {
        "total": total,
        "business": business,
        "infrastructure": infrastructure,
    }


def build_agent_tokens_panel() -> dict[str, Any]:

    token_usage = get_token_usage_today()
    main_tokens = int(token_usage.get("main_agent") or 0)
    main_tokens_total = int(token_usage.get("main_agent_total") or main_tokens)
    vector_tokens = int(token_usage.get("vector_agent") or 0)
    vector_tokens_total = int(token_usage.get("vector_agent_total") or vector_tokens)
    total_tokens = int(token_usage.get("total") or (main_tokens + vector_tokens))
    total_tokens_all_time = int(
        token_usage.get("total_all_time") or (main_tokens_total + vector_tokens_total)
    )
    token_period = "今日(含估算)" if token_usage.get("estimated") else "今日"
    return {
        "label": "Agent 消耗",
        "total": total_tokens,
        "total_all_time": total_tokens_all_time,
        "main_agent": main_tokens,
        "vector_agent": vector_tokens,
        "main_agent_total": main_tokens_total,
        "vector_agent_total": vector_tokens_total,
        "period": token_period,
        "estimated": bool(token_usage.get("estimated")),
        "value": f"{total_tokens:,} tokens",
        "line0": f"{total_tokens_all_time:,} tokens",
        "line1": f"{main_tokens:,} tokens",
        "line2": f"{vector_tokens:,} tokens",
    }


def load_change_events():
    if not CHANGE_EVENTS_FILE.exists():
        return []

    with CHANGE_EVENTS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("change_events.json must be a JSON array")

    return data


def build_metrics_payload():
    token_panel = build_agent_tokens_panel()
    try:
        business_context = get_business_success_context()
        all_time = get_all_time_order_summary(business_context)
        recent = get_recent_order_summary("15m", business_context)
        service_level = get_service_level_summary(business_context)
        alert_info = get_alert_breakdown()


        percent = all_time["success_rate"]
        order_count = recent["total_orders"]
        all_time_total = all_time["total_orders"]
        all_time_success = all_time["success_orders"]
        all_time_failed = all_time["failed_orders"]
        recent_percent = recent["success_rate"]
        recent_total = recent["total_orders"]

        if all_time_total <= 0:
            status = "无流量"
            status_level = "warn"
        elif percent >= 95:
            status = "正常"
            status_level = "good"
        elif percent >= 80:
            status = "关注"
            status_level = "warn"
        else:
            status = "异常"
            status_level = "bad"

        if recent_total <= 0:
            recent_success_rate_text = "NoData"
            recent_success_rate_level = "warn"
        else:
            recent_success_rate_text = f"{recent_percent:.2f}%"
            if recent_percent >= 95:
                recent_success_rate_level = "good"
            elif recent_percent >= 80:
                recent_success_rate_level = "warn"
            else:
                recent_success_rate_level = "bad"

        try:
            latency_ms = get_order_latency_ms("15m")
        except Exception:
            latency_ms = None

        if latency_ms is None:
            latency_text = "--"
            latency_level = ""
        else:
            latency_text = f"{latency_ms:g} ms"
            if latency_ms >= 500:
                latency_level = "bad"
            elif latency_ms >= 200:
                latency_level = "warn"
            else:
                latency_level = "good"

        return {
            "business_panel": {
                "label": "业务态势",
                "success_rate": f"{percent:.2f}%",
                "success_rate_level": status_level,
                "success_orders": all_time_success,
                "failed_orders": all_time_failed,
                "order_result_text": f"{all_time_success} / {all_time_failed}",
                "recent_success_rate": recent_success_rate_text,
                "recent_success_rate_level": recent_success_rate_level,
                "latency_ms": latency_ms,
                "latency_text": latency_text,
                "latency_level": latency_level,
                "order_count": order_count,
                "status": status,
                "status_level": status_level,
                "value": f"{percent:.2f}%",
                "line1": "业务监控",
                "line2": "节点监控",
                "line1_url": GRAFANA_BUSINESS_DASHBOARD_URL,
                "line2_url": GRAFANA_NODE_DASHBOARD_URL,
            },
            "alert_panel": {
                "label": "告警态势",
                "total": alert_info["total"],
                "business": alert_info["business"],
                "infrastructure": alert_info["infrastructure"],
                "status": "清零" if alert_info["total"] == 0 else "告警中",
                "status_level": "good" if alert_info["total"] == 0 else "bad",
                "value": str(alert_info["total"]),
                "line1": str(alert_info["business"]),
                "line2": str(alert_info["infrastructure"]),
            },
            "service_level": service_level,
            "agent_tokens": token_panel,
            "success_rate": {
                "label": "业务态势",
                "value": f"{percent:.2f}%",
                "status": status,
                "status_level": status_level,
                "description": f"最近订单延迟：{latency_text}",
            },
            "active_alerts": {
                "label": "告警态势",
                "value": str(alert_info["total"]),
                "status": "清零" if alert_info["total"] == 0 else "告警中",
                "status_level": "good" if alert_info["total"] == 0 else "bad",
                "description": (
                    f"业务类 {alert_info['business']} / "
                    f"基础设施类 {alert_info['infrastructure']}"
                ),
            },
        }
    except Exception as exc:
        return {
            "business_panel": {
                "label": "业务态势",
                "success_rate": "--",
                "success_rate_level": "bad",
                "success_orders": None,
                "failed_orders": None,
                "order_result_text": "--",
                "recent_success_rate": "NoData",
                "recent_success_rate_level": "warn",
                "latency_ms": None,
                "latency_text": "--",
                "latency_level": "",
                "order_count": "--",
                "status": "异常",
                "status_level": "bad",
                "value": "--",
                "line1": "业务监控",
                "line2": "节点监控",
                "line1_url": GRAFANA_BUSINESS_DASHBOARD_URL,
                "line2_url": GRAFANA_NODE_DASHBOARD_URL,
            },
            "alert_panel": {
                "label": "告警态势",
                "total": "--",
                "business": "--",
                "infrastructure": "--",
                "status": "未知",
                "status_level": "warn",
                "value": "--",
                "line1": "--",
                "line2": "--",
            },
            "service_level": {
                "window": SERVICE_LEVEL_WINDOW,
                "window_label": SERVICE_LEVEL_WINDOW_LABEL,
                "sli": None,
                "sli_text": "NoData",
                "sli_level": "warn",
                "sli_5m": None,
                "sli_5m_text": "NoData",
                "sli_5m_level": "warn",
                "burn_rate_5m": None,
                "burn_rate_5m_text": "NoData",
                "burn_rate_5m_level": "warn",
                "slo_target": SERVICE_LEVEL_SLO_TARGET,
                "slo_target_text": f"{SERVICE_LEVEL_SLO_TARGET:.2f}%",
                "error_budget_remaining": None,
                "error_budget_text": "NoData",
                "error_budget_level": "warn",
                "reason": f"metrics_payload_failed: {exc}",
            },
            "agent_tokens": token_panel,
        }


def inspection_engine_get(path: str):
    return http_get_json(f"{INSPECTION_ENGINE_BASE}{path}")


def inspection_engine_post(path: str, payload: dict):
    return post_json(f"{INSPECTION_ENGINE_BASE}{path}", payload)


def sop_service_get(path: str):
    return http_get_json(f"{SOP_SERVICE_BASE}{path}")


def sop_service_post(path: str, payload: dict, timeout: int = 20):
    return post_json(f"{SOP_SERVICE_BASE}{path}", payload, timeout=timeout)


def sop_service_put(path: str, payload: dict, timeout: int = 20):
    return put_json(f"{SOP_SERVICE_BASE}{path}", payload, timeout=timeout)


def sop_service_delete(path: str, timeout: int = 20):
    return delete_json(f"{SOP_SERVICE_BASE}{path}", timeout=timeout)


def agent_executor_get(path: str):
    return http_get_json(
        f"{AGENT_EXECUTOR_BASE}{path}",
        timeout=20,
    )


def agent_executor_post(path: str, payload: dict):
    return post_json(f"{AGENT_EXECUTOR_BASE}{path}", payload, timeout=80)


def agent_executor_delete(path: str):
    return delete_json(
        f"{AGENT_EXECUTOR_BASE}{path}",
        timeout=20,
    )


def enrich_inspection_with_agent_analysis(inspection_data: dict):
    if inspection_data.get("status") != "completed":
        return inspection_data

    if inspection_data.get("agent_analysis"):
        return inspection_data

    try:
        analysis = agent_executor_post("/api/analyze/inspection", inspection_data)
        inspection_data["agent_analysis"] = analysis.get("analysis_text", "")
        inspection_data["agent_analysis_meta"] = {
            "analysis_type": analysis.get("analysis_type", ""),
            "used_inputs": analysis.get("used_inputs", {}),
        }
        inspection_data["agent_analysis_error"] = ""
    except Exception as exc:
        inspection_data["agent_analysis"] = ""
        inspection_data["agent_analysis_meta"] = {}
        inspection_data["agent_analysis_error"] = str(exc)

    return inspection_data


def poll_inspection_until_completed(
    inspection_id: str,
    max_wait_seconds: int = 70,
    interval_seconds: float = 2.0,
):
    start_at = time.time()

    while True:
        data = inspection_engine_get(f"/api/inspection/{inspection_id}")
        status = data.get("status")

        if status in {"completed", "stopped"}:
            return data

        if time.time() - start_at > max_wait_seconds:
            raise TimeoutError(
                f"inspection {inspection_id} timed out after {max_wait_seconds}s"
            )

        time.sleep(interval_seconds)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "aiops-agent"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/web.html"):
    if _session_username(request.cookies.get(AUTH_COOKIE_NAME)):
        return RedirectResponse(_safe_next_path(next), status_code=303)
    return HTMLResponse(
        LOGIN_HTML,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'"
            ),
        },
    )


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request):
    client_key = _client_key(request)
    retry_after = _login_retry_after(client_key)
    if retry_after:
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"登录失败次数过多，请在 {retry_after} 秒后重试",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    username_matches = hmac.compare_digest(
        payload.username.encode("utf-8"), AUTH_USERNAME.encode("utf-8")
    )
    password_matches = hmac.compare_digest(
        payload.password.encode("utf-8"), AUTH_PASSWORD.encode("utf-8")
    )
    if not username_matches or not password_matches:
        retry_after = _record_login_failure(client_key)
        if retry_after:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"登录失败次数过多，请在 {retry_after} 秒后重试",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
        raise HTTPException(status_code=401, detail="账号或密码错误")

    _clear_login_failures(client_key)
    redirect_to = _safe_next_path(payload.next)
    response = JSONResponse({"success": True, "redirect_to": redirect_to})
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=_create_session_token(),
        max_age=AUTH_SESSION_TTL_SECONDS,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def logout():
    response = JSONResponse({"success": True})
    response.delete_cookie(
        AUTH_COOKIE_NAME,
        path="/",
        secure=AUTH_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/api/auth/me")
def current_user(request: Request):
    return {"username": _session_username(request.cookies.get(AUTH_COOKIE_NAME))}


@app.get("/")
def root():
    return RedirectResponse("/web.html", status_code=303)


@app.get("/web.html")
def get_web():
    if not WEB_FILE.exists():
        raise HTTPException(status_code=404, detail="web.html not found")
    return FileResponse(WEB_FILE)


@app.get("/api/metrics")
def get_metrics():
    return build_metrics_payload()


@app.get("/api/change-events")
def get_change_events():
    try:
        return load_change_events()
    except Exception as exc:
        return [
            {
                "event_id": "chg-read-error",
                "event_time": "2026-07-27 16:00:00",
                "event_type": "system",
                "namespace": "aiops",
                "resource_kind": "File",
                "resource_name": "change_events.json",
                "before_value": "",
                "after_value": "",
                "summary": f"变更归档读取失败: {exc}",
                "operator": "system",
                "source": "api",
                "during_incident": False,
            }
        ]


@app.get("/api/incidents/latest")
def get_latest_incident():
    firing_count = 0
    try:
        firing_count = get_firing_alert_count()
    except Exception:
        pass

    if firing_count == 0:
        return {
            "incident_id": "",
            "alert_name": "当前无活跃告警",
            "severity": "info",
            "status": "resolved",
            "start_time": "",
            "diagnosis": "当前 Prometheus 中没有 firing 状态告警。",
            "related_changes": [],
            "suggestion": "系统当前处于稳态，可执行巡检或查看近期变更。",
        }

    return {
        "incident_id": "inc-live-001",
        "alert_name": "监控发现活跃告警",
        "severity": "critical",
        "status": "firing",
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "diagnosis": f"当前检测到 {firing_count} 条 firing 告警。",
        "related_changes": [],
        "suggestion": "优先查看 Prometheus 告警详情，并结合变更记录分析。",
        }


@app.get("/api/knowledge/status")
def get_knowledge_status():
    try:
        return sop_service_get("/api/knowledge/status")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.get("/api/knowledge/files")
def list_knowledge_files():
    try:
        return sop_service_get("/api/knowledge/files")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.get("/api/knowledge/files/{doc_id}")
def get_knowledge_file(doc_id: str):
    try:
        return sop_service_get(f"/api/knowledge/files/{doc_id}")
    except HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(status_code=404, detail="knowledge file not found")
        raise HTTPException(status_code=503, detail=f"sop-service http error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.post("/api/knowledge/files")
def create_knowledge_file(payload: KnowledgeFileCreateRequest):
    try:
        return sop_service_post("/api/knowledge/files", payload.model_dump(), timeout=40)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail or "sop-service http error")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.put("/api/knowledge/files/{doc_id}")
def update_knowledge_file(doc_id: str, payload: KnowledgeFileUpdateRequest):
    try:
        return sop_service_put(
            f"/api/knowledge/files/{doc_id}",
            payload.model_dump(exclude_none=True),
            timeout=40,
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail or "sop-service http error")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.delete("/api/knowledge/files/{doc_id}")
def delete_knowledge_file(doc_id: str):
    try:
        return sop_service_delete(f"/api/knowledge/files/{doc_id}", timeout=30)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail or "sop-service http error")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.post("/api/knowledge/sync")
def sync_knowledge():
    try:
        return sop_service_post("/api/knowledge/sync", {}, timeout=120)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail or "sop-service http error")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.post("/api/knowledge/search")
def search_knowledge(payload: KnowledgeSearchRequest):
    try:
        return sop_service_post("/api/knowledge/search", payload.model_dump(), timeout=60)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail or "sop-service http error")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"sop-service unavailable: {exc}")


@app.post("/api/inspection/start")
def start_inspection():
    try:
        return inspection_engine_post("/api/inspection/start", {})
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"inspection-engine unavailable: {exc}",
        )


@app.get("/api/inspection/{inspection_id}")
def get_inspection(inspection_id: str):
    try:
        data = inspection_engine_get(f"/api/inspection/{inspection_id}")
        return enrich_inspection_with_agent_analysis(data)
    except HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(status_code=404, detail="inspection not found")
        raise HTTPException(
            status_code=503,
            detail=f"inspection-engine http error: {exc}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"inspection-engine unavailable: {exc}",
        )


@app.post("/api/inspection/stop")
def stop_inspection(payload: StopInspectionRequest):
    try:
        return inspection_engine_post("/api/inspection/stop", payload.model_dump())
    except HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(status_code=404, detail="inspection not found")
        raise HTTPException(
            status_code=503,
            detail=f"inspection-engine http error: {exc}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"inspection-engine unavailable: {exc}",
        )


@app.post("/api/chat/inspection")
def chat_inspection():
    try:
        started = inspection_engine_post("/api/inspection/start", {})
        inspection_id = started["inspection_id"]

        inspection_data = poll_inspection_until_completed(inspection_id)
        inspection_data = enrich_inspection_with_agent_analysis(inspection_data)

        content = (
            inspection_data.get("agent_analysis")
            or inspection_data.get("result", {}).get("summary")
            or "巡检已完成，但暂无分析结果。"
        )

        return {
            "message_type": "agent_reply",
            "content": content,
            "meta": {
                "source": "inspection_analysis",
                "inspection_id": inspection_id,
                "inspection_status": inspection_data.get("status", ""),
                "agent_analysis_error": inspection_data.get(
                    "agent_analysis_error", ""
                ),
            },
            "raw": inspection_data,
        }
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"chat inspection failed: {exc}")


@app.post("/api/chat/sessions")
def create_chat_session(
    payload: CreateChatSessionRequest,
):
    try:
        return agent_executor_post(
            "/api/chat/sessions",
            {"title": payload.title},
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(
            status_code=exc.code,
            detail=detail,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/incidents")
def list_incidents(
    status: str | None = None,
    fingerprint: str | None = None,
    alert_name: str | None = None,
    limit: int = 100,
):
    query_params: dict[str, Any] = {
        "limit": max(1, min(limit, 500)),
    }
    if status:
        query_params["status"] = status
    if fingerprint:
        query_params["fingerprint"] = fingerprint
    if alert_name:
        query_params["alert_name"] = alert_name

    try:
        return agent_executor_get(
            f"/api/incidents?{urlencode(query_params)}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/incidents/{incident_id}/events")
def get_incident_events(
    incident_id: str,
    limit: int = 500,
):
    safe_incident_id = quote(incident_id, safe="")
    query = urlencode({"limit": max(1, min(limit, 1000))})

    try:
        return agent_executor_get(
            f"/api/incidents/{safe_incident_id}/events?{query}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/incidents/{incident_id}/analysis")
def get_incident_analysis(incident_id: str):
    safe_incident_id = quote(incident_id, safe="")

    try:
        return agent_executor_get(
            f"/api/incidents/{safe_incident_id}/analysis"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/incident-analyses/{analysis_id}/events")
def get_incident_analysis_events(
    analysis_id: str,
    after_sequence: int = 0,
    limit: int = 200,
):
    safe_analysis_id = quote(analysis_id, safe="")
    query = urlencode(
        {
            "after_sequence": max(0, after_sequence),
            "limit": max(1, min(limit, 500)),
        }
    )

    try:
        return agent_executor_get(
            f"/api/incident-analyses/{safe_analysis_id}/events?{query}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.post("/api/remediations/{action_id}/approve")
def approve_remediation(
    action_id: str,
    payload: RemediationDecisionRequest,
):
    safe_action_id = quote(action_id, safe="")
    try:
        return agent_executor_post(
            f"/api/remediations/{safe_action_id}/approve",
            payload.model_dump(),
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.post("/api/remediations/{action_id}/reject")
def reject_remediation(
    action_id: str,
    payload: RemediationDecisionRequest,
):
    safe_action_id = quote(action_id, safe="")
    try:
        return agent_executor_post(
            f"/api/remediations/{safe_action_id}/reject",
            payload.model_dump(),
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    safe_incident_id = quote(incident_id, safe="")

    try:
        return agent_executor_get(
            f"/api/incidents/{safe_incident_id}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=exc.code, detail=detail)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/chat/sessions")
def list_chat_sessions(
    limit: int = 50,
):
    query = urlencode({"limit": limit})

    try:
        return agent_executor_get(
            f"/api/chat/sessions?{query}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(
            status_code=exc.code,
            detail=detail,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/chat/sessions/{session_id}")
def get_chat_session(
    session_id: str,
    message_limit: int = 200,
):
    safe_session_id = quote(session_id, safe="")
    query = urlencode({"message_limit": message_limit})

    try:
        return agent_executor_get(
            f"/api/chat/sessions/{safe_session_id}?{query}"
        )
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(
            status_code=exc.code,
            detail=detail,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.delete("/api/chat/sessions/{session_id}")
def delete_chat_session(session_id: str):
    safe_session_id = quote(session_id, safe="")

    try:
        return agent_executor_delete(
            f"/api/chat/sessions/{safe_session_id}"
        )
    except HTTPError as exc:
        detail = exc.read().decode(
            "utf-8",
            errors="ignore",
        )
        raise HTTPException(
            status_code=exc.code,
            detail=detail,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.post("/api/chat")
def chat(payload: ChatRequestPayload):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is empty")

    executor_payload = {
        "message": payload.message,
        "mode": payload.mode,
        "history": [item.model_dump() for item in payload.history],
        "context": payload.context,
        "current_incident": payload.current_incident,
    }

    try:
        return agent_executor_post("/api/chat", executor_payload)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor http error: {detail}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )


@app.get("/api/agent/healthz")
def get_agent_health():
    try:
        return http_get_json(f"{AGENT_EXECUTOR_BASE}/healthz")
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"agent-executor unavailable: {exc}",
        )
