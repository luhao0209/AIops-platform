from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


_LOCK = threading.Lock()
_TZ_CST = timezone(timedelta(hours=8))


def _usage_file() -> Path:
    return Path(os.getenv("TOKEN_USAGE_FILE", "/tmp/aiops_token_usage.json"))


def today_date() -> str:
    return datetime.now(_TZ_CST).strftime("%Y-%m-%d")


def normalize_embedding_usage(raw: Any, *, texts: list[str] | None = None) -> dict[str, Any]:
    usage = raw if isinstance(raw, dict) else {}
    total_tokens = int(usage.get("total_tokens") or usage.get("prompt_tokens") or 0)
    estimated = False
    if total_tokens <= 0:
        char_count = sum(len(text or "") for text in (texts or []))
        total_tokens = max(1, char_count // 4) if char_count > 0 else 0
        estimated = total_tokens > 0
    return {
        "total_tokens": total_tokens,
        "estimated": estimated,
    }


def _read_unlocked(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"dates": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"dates": {}}
    if not isinstance(payload, dict):
        return {"dates": {}}
    dates = payload.get("dates")
    if not isinstance(dates, dict):
        payload["dates"] = {}
    return payload


def add_tokens(bucket: str, amount: int, *, estimated: bool = False) -> None:
    delta = int(amount or 0)
    if delta <= 0:
        return

    path = _usage_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    day = today_date()

    with _LOCK:
        payload = _read_unlocked(path)
        dates = payload.setdefault("dates", {})
        day_bucket = dates.setdefault(day, {})
        entry = day_bucket.setdefault(
            bucket,
            {"total_tokens": 0, "estimated_tokens": 0, "calls": 0},
        )
        entry["total_tokens"] = int(entry.get("total_tokens") or 0) + delta
        entry["calls"] = int(entry.get("calls") or 0) + 1
        if estimated:
            entry["estimated_tokens"] = int(entry.get("estimated_tokens") or 0) + delta
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def get_bucket_today(bucket: str) -> dict[str, Any]:
    path = _usage_file()
    day = today_date()
    with _LOCK:
        payload = _read_unlocked(path)
        entry = ((payload.get("dates") or {}).get(day) or {}).get(bucket) or {}
    total = int(entry.get("total_tokens") or 0)
    estimated = int(entry.get("estimated_tokens") or 0)
    return {
        "date": day,
        "bucket": bucket,
        "total_tokens": total,
        "estimated_tokens": estimated,
        "calls": int(entry.get("calls") or 0),
        "estimated": estimated > 0 and estimated >= total,
    }


def get_bucket_all_time(bucket: str) -> dict[str, Any]:
    path = _usage_file()
    with _LOCK:
        payload = _read_unlocked(path)

    total = 0
    estimated = 0
    calls = 0

    for day_data in (payload.get("dates") or {}).values():
        if not isinstance(day_data, dict):
            continue
        entry = day_data.get(bucket) or {}
        total += int(entry.get("total_tokens") or 0)
        estimated += int(entry.get("estimated_tokens") or 0)
        calls += int(entry.get("calls") or 0)

    return {
        "bucket": bucket,
        "total_tokens": total,
        "estimated_tokens": estimated,
        "calls": calls,
        "estimated": estimated > 0 and estimated >= total,
    }
