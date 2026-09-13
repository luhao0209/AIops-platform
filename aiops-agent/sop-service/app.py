from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sync_engine.runner import build_default_runner
from token_usage_store import get_bucket_all_time, get_bucket_today, today_date

app = FastAPI(title="AIOps Knowledge Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
KNOWLEDGE_BASE_DIR = BASE_DIR / "knowledge_base"
SOPS_DIR = KNOWLEDGE_BASE_DIR / "sops"
EXPERIENCES_DIR = KNOWLEDGE_BASE_DIR / "experiences"

SOPS_DIR.mkdir(parents=True, exist_ok=True)
EXPERIENCES_DIR.mkdir(parents=True, exist_ok=True)

KNOWLEDGE_TYPE_LABELS = {
    "official_sop": "SOP",
    "incident_experience": "运维经验文档",
    "postmortem": "故障复盘",
}


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


def read_utf8_file(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def write_utf8_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def load_json_file(path: Path) -> dict[str, Any]:
    return json.loads(read_utf8_file(path))


def dump_json_file(path: Path, payload: dict[str, Any]) -> None:
    write_utf8_file(path, json.dumps(payload, ensure_ascii=False, indent=2))


def normalize_lines(value: list[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [line.strip() for line in str(value).splitlines() if line.strip()]


def normalize_tags(value: list[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    raw = str(value).replace("，", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def normalize_step_inputs(
    value: list[KnowledgeStepInput] | list[dict] | list[str] | str | None,
) -> list[dict[str, Any]]:
    if value is None:
        return []

    if isinstance(value, str):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        steps = []
        for idx, line in enumerate(lines, start=1):
            parts = [part.strip() for part in line.split("|")]
            steps.append(
                {
                    "step_order": idx,
                    "action": parts[0] if parts else f"步骤 {idx}",
                    "recommended_command": parts[1] if len(parts) > 1 else "",
                    "output_focus": parts[2] if len(parts) > 2 else "",
                }
            )
        return steps

    steps: list[dict[str, Any]] = []
    for idx, item in enumerate(value, start=1):
        if isinstance(item, KnowledgeStepInput):
            item = item.model_dump()
        if isinstance(item, str):
            item = {
                "step_order": idx,
                "action": item.strip(),
                "recommended_command": "",
                "output_focus": "",
            }
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip()
        if not action:
            continue
        steps.append(
            {
                "step_order": item.get("step_order") or idx,
                "action": action,
                "recommended_command": str(item.get("recommended_command", "")).strip(),
                "output_focus": str(item.get("output_focus", "")).strip(),
            }
        )
    return steps


def slugify_file_name(value: str) -> str:
    raw = value.strip().lower()
    raw = raw.replace(" ", "_").replace("-", "_")
    raw = re.sub(r"[^a-zA-Z0-9_\u4e00-\u9fa5]", "_", raw)
    raw = re.sub(r"_+", "_", raw).strip("_")
    return raw or "untitled"


def make_knowledge_id(doc_id: str) -> str:
    return f"KNOW-{doc_id.upper().replace('__', '-').replace('_', '-')}"


def detect_source_type(knowledge_type: str) -> str:
    if knowledge_type == "official_sop":
        return "official_sop"
    return "incident_experience"


def build_sop_record(payload: dict[str, Any], doc_id: str) -> dict[str, Any]:
    title = str(payload.get("title") or "").strip()
    knowledge_type = str(payload.get("type") or "official_sop").strip()
    summary = str(payload.get("summary") or "").strip()
    scene = str(payload.get("scene") or "").strip()
    symptoms = normalize_lines(payload.get("symptoms", []))
    applicable_components = normalize_tags(payload.get("applicable_components", []))
    recommended_steps = normalize_step_inputs(payload.get("recommended_steps", []))
    trigger_conditions = normalize_lines(payload.get("trigger_conditions", []))
    tags = normalize_tags(payload.get("tags", []))
    risk_warnings = str(payload.get("risk_warnings") or "").strip()
    rollback_advice = str(payload.get("rollback_advice") or "").strip()
    created_by = str(payload.get("created_by") or "web-user").strip()

    if not summary:
        summary = symptoms[0] if symptoms else title
    if not scene:
        scene = summary

    return {
        "knowledge_id": payload.get("knowledge_id") or make_knowledge_id(doc_id),
        "doc_id": doc_id,
        "title": title,
        "type": knowledge_type,
        "type_label": KNOWLEDGE_TYPE_LABELS.get(knowledge_type, knowledge_type),
        "scene": scene,
        "summary": summary,
        "symptoms": symptoms,
        "applicable_components": applicable_components,
        "recommended_steps": recommended_steps,
        "trigger_conditions": trigger_conditions,
        "risk_warnings": risk_warnings,
        "rollback_advice": rollback_advice,
        "tags": tags,
        "created_by": created_by,
    }


def build_markdown_from_experience(payload: dict[str, Any], doc_id: str) -> str:
    title = str(payload.get("title") or "").strip()
    summary = str(payload.get("summary") or "").strip()
    symptoms = normalize_lines(payload.get("symptoms", []))
    applicable_components = normalize_tags(payload.get("applicable_components", []))
    recommended_steps = normalize_step_inputs(payload.get("recommended_steps", []))
    tags = normalize_tags(payload.get("tags", []))
    risk_warnings = str(payload.get("risk_warnings") or "").strip()
    rollback_advice = str(payload.get("rollback_advice") or "").strip()

    lines: list[str] = [f"# {title}", ""]

    if summary:
        lines.extend(["## 摘要", "", summary, ""])

    if symptoms:
        lines.extend(["## 系统出现什么问题", ""])
        for item in symptoms:
            lines.append(f"- {item}")
        lines.append("")

    if applicable_components:
        lines.extend(["## 关联组件 / 场景", "", ", ".join(applicable_components), ""])

    if recommended_steps:
        lines.extend(["## 排查思路 / 处理步骤", ""])
        for step in recommended_steps:
            lines.append(f"{step.get('step_order', 1)}. {step.get('action', '')}")
            cmd = step.get("recommended_command", "")
            focus = step.get("output_focus", "")
            if cmd:
                lines.append(f"   - 推荐动作: {cmd}")
            if focus:
                lines.append(f"   - 关注点: {focus}")
        lines.append("")

    if risk_warnings:
        lines.extend(["## 可能原因 / 风险提示", "", risk_warnings, ""])

    if rollback_advice:
        lines.extend(["## 解决建议 / 经验结论", "", rollback_advice, ""])

    if tags:
        lines.extend(["## 标签", "", ", ".join(tags), ""])

    lines.extend(
        [
            "## 元数据",
            "",
            f"- knowledge_id: {make_knowledge_id(doc_id)}",
            f"- type: incident_experience",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def parse_experience_markdown(path: Path, content: str) -> dict[str, Any]:
    lines = content.splitlines()
    title = path.stem
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# "):
            title = stripped[2:].strip()
            break

    summary = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        summary = stripped
        break

    tags: list[str] = []
    knowledge_id = make_knowledge_id(path.stem)

    metadata_match = re.search(r"^- knowledge_id:\s*(.+)$", content, re.MULTILINE)
    if metadata_match:
        knowledge_id = metadata_match.group(1).strip()

    return {
        "knowledge_id": knowledge_id,
        "doc_id": path.stem,
        "title": title,
        "type": "incident_experience",
        "type_label": KNOWLEDGE_TYPE_LABELS["incident_experience"],
        "scene": summary or title,
        "summary": summary or title,
        "symptoms": [],
        "applicable_components": [],
        "recommended_steps": [],
        "trigger_conditions": [],
        "risk_warnings": "",
        "rollback_advice": "",
        "tags": tags,
        "created_by": "file-system",
        "markdown_content": content,
    }


def load_sop_file(path: Path) -> dict[str, Any]:
    data = load_json_file(path)
    record = build_sop_record(data, path.stem)
    record["file_name"] = path.name
    record["relative_path"] = f"sops/{path.name}"
    record["source_kind"] = "file"
    record["markdown_content"] = ""
    return record


def load_experience_file(path: Path) -> dict[str, Any]:
    content = read_utf8_file(path)
    record = parse_experience_markdown(path, content)
    record["file_name"] = path.name
    record["relative_path"] = f"experiences/{path.name}"
    record["source_kind"] = "file"
    return record


def list_knowledge_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for path in sorted(SOPS_DIR.glob("*.json")):
        try:
            records.append(load_sop_file(path))
        except Exception as exc:
            records.append(
                {
                    "knowledge_id": make_knowledge_id(path.stem),
                    "doc_id": path.stem,
                    "title": path.stem,
                    "type": "official_sop",
                    "type_label": KNOWLEDGE_TYPE_LABELS["official_sop"],
                    "scene": "文件解析失败",
                    "summary": f"文件解析失败: {exc}",
                    "symptoms": [],
                    "applicable_components": [],
                    "recommended_steps": [],
                    "trigger_conditions": [],
                    "risk_warnings": "",
                    "rollback_advice": "",
                    "tags": [],
                    "created_by": "file-system",
                    "file_name": path.name,
                    "relative_path": f"sops/{path.name}",
                    "source_kind": "file",
                    "markdown_content": "",
                }
            )

    for path in sorted(EXPERIENCES_DIR.glob("*.md")):
        try:
            records.append(load_experience_file(path))
        except Exception as exc:
            records.append(
                {
                    "knowledge_id": make_knowledge_id(path.stem),
                    "doc_id": path.stem,
                    "title": path.stem,
                    "type": "incident_experience",
                    "type_label": KNOWLEDGE_TYPE_LABELS["incident_experience"],
                    "scene": "文件解析失败",
                    "summary": f"文件解析失败: {exc}",
                    "symptoms": [],
                    "applicable_components": [],
                    "recommended_steps": [],
                    "trigger_conditions": [],
                    "risk_warnings": "",
                    "rollback_advice": "",
                    "tags": [],
                    "created_by": "file-system",
                    "file_name": path.name,
                    "relative_path": f"experiences/{path.name}",
                    "source_kind": "file",
                    "markdown_content": "",
                }
            )

    return records


def find_record(doc_id: str) -> dict[str, Any]:
    sop_path = SOPS_DIR / f"{doc_id}.json"
    exp_path = EXPERIENCES_DIR / f"{doc_id}.md"

    if sop_path.exists():
        return load_sop_file(sop_path)
    if exp_path.exists():
        return load_experience_file(exp_path)

    raise HTTPException(status_code=404, detail="knowledge file not found")


def write_sop_file(doc_id: str, payload: dict[str, Any]) -> Path:
    path = SOPS_DIR / f"{doc_id}.json"
    record = build_sop_record(payload, doc_id)
    to_write = {
        "knowledge_id": record["knowledge_id"],
        "title": record["title"],
        "type": record["type"],
        "summary": record["summary"],
        "scene": record["scene"],
        "symptoms": record["symptoms"],
        "applicable_components": record["applicable_components"],
        "recommended_steps": record["recommended_steps"],
        "trigger_conditions": record["trigger_conditions"],
        "risk_warnings": record["risk_warnings"],
        "rollback_advice": record["rollback_advice"],
        "tags": record["tags"],
        "created_by": record["created_by"],
    }
    dump_json_file(path, to_write)
    return path


def write_experience_file(doc_id: str, payload: dict[str, Any]) -> Path:
    path = EXPERIENCES_DIR / f"{doc_id}.md"
    content = str(payload.get("markdown_content", "")).strip()
    if not content:
        content = build_markdown_from_experience(payload, doc_id)
    write_utf8_file(path, content)
    return path


def delete_knowledge_file(doc_id: str) -> None:
    sop_path = SOPS_DIR / f"{doc_id}.json"
    exp_path = EXPERIENCES_DIR / f"{doc_id}.md"

    if sop_path.exists():
        sop_path.unlink()
        return
    if exp_path.exists():
        exp_path.unlink()
        return

    raise HTTPException(status_code=404, detail="knowledge file not found")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/token-usage/today")
def token_usage_today() -> dict[str, Any]:
    vector_today = get_bucket_today("vector")
    vector_all_time = get_bucket_all_time("vector")
    return {
        "date": today_date(),
        "main_agent": 0,
        "main_agent_total": 0,
        "vector_agent": int(vector_today.get("total_tokens") or 0),
        "vector_agent_total": int(vector_all_time.get("total_tokens") or 0),
        "total": int(vector_today.get("total_tokens") or 0),
        "total_all_time": int(vector_all_time.get("total_tokens") or 0),
        "estimated": bool(vector_today.get("estimated")) or bool(vector_all_time.get("estimated")),
        "calls": int(vector_today.get("calls") or 0),
        "buckets": {
            "vector_today": vector_today,
            "vector_all_time": vector_all_time,
        },
    }


@app.get("/api/knowledge/status")
def get_knowledge_status():
    return {
        "status": "ok",
        "storage_mode": "file_system",
        "embedding": {
            "api_base": os.getenv("EMBEDDING_API_BASE", ""),
            "model": os.getenv("EMBEDDING_MODEL", ""),
            "dimension": os.getenv("EMBEDDING_DIMENSION", ""),
            "api_key_configured": bool(os.getenv("EMBEDDING_API_KEY", "").strip()),
        },
        "qdrant": {
            "url": os.getenv("QDRANT_URL", ""),
            "collection": os.getenv("QDRANT_COLLECTION", "aiops_knowledge"),
            "api_key_configured": bool(os.getenv("QDRANT_API_KEY", "").strip()),
        },
        "knowledge_base": {
            "root": str(KNOWLEDGE_BASE_DIR),
            "sops_dir": str(SOPS_DIR),
            "experiences_dir": str(EXPERIENCES_DIR),
        },
    }


@app.get("/api/knowledge/files")
def list_knowledge_files():
    records = list_knowledge_records()
    sops = [item for item in records if item["type"] == "official_sop"]
    experiences = [item for item in records if item["type"] != "official_sop"]

    return {
        "records": records,
        "sops": sops,
        "experiences": experiences,
        "library_overview": {
            "total": len(records),
            "sop_count": len(sops),
            "experience_count": len(experiences),
        },
    }


@app.get("/api/knowledge/files/{doc_id}")
def get_knowledge_file(doc_id: str):
    return find_record(doc_id)


@app.post("/api/knowledge/files")
def create_knowledge_file(payload: KnowledgeFileCreateRequest):
    knowledge_type = payload.type or "official_sop"
    file_name = payload.file_name.strip() if payload.file_name else payload.title
    doc_id = slugify_file_name(file_name)

    sop_path = SOPS_DIR / f"{doc_id}.json"
    exp_path = EXPERIENCES_DIR / f"{doc_id}.md"
    if sop_path.exists() or exp_path.exists():
        raise HTTPException(status_code=409, detail="knowledge file already exists")

    data = payload.model_dump()

    if detect_source_type(knowledge_type) == "official_sop":
        path = write_sop_file(doc_id, data)
    else:
        data["type"] = knowledge_type
        path = write_experience_file(doc_id, data)

    return {
        "message": "knowledge file created",
        "doc_id": doc_id,
        "file_name": path.name,
        "relative_path": path.relative_to(KNOWLEDGE_BASE_DIR).as_posix(),
    }


@app.put("/api/knowledge/files/{doc_id}")
def update_knowledge_file(doc_id: str, payload: KnowledgeFileUpdateRequest):
    current = find_record(doc_id)
    merged = {
        "title": payload.title if payload.title is not None else current["title"],
        "type": payload.type if payload.type is not None else current["type"],
        "summary": payload.summary if payload.summary is not None else current["summary"],
        "scene": payload.scene if payload.scene is not None else current["scene"],
        "symptoms": payload.symptoms if payload.symptoms is not None else current["symptoms"],
        "applicable_components": payload.applicable_components if payload.applicable_components is not None else current["applicable_components"],
        "recommended_steps": payload.recommended_steps if payload.recommended_steps is not None else current["recommended_steps"],
        "trigger_conditions": payload.trigger_conditions if payload.trigger_conditions is not None else current["trigger_conditions"],
        "tags": payload.tags if payload.tags is not None else current["tags"],
        "risk_warnings": payload.risk_warnings if payload.risk_warnings is not None else current["risk_warnings"],
        "rollback_advice": payload.rollback_advice if payload.rollback_advice is not None else current["rollback_advice"],
        "created_by": payload.created_by if payload.created_by is not None else current["created_by"],
        "markdown_content": payload.markdown_content if payload.markdown_content is not None else current.get("markdown_content", ""),
    }

    old_type = current["type"]
    new_type = merged["type"]

    if old_type == "official_sop" and new_type != "official_sop":
        old_path = SOPS_DIR / f"{doc_id}.json"
        if old_path.exists():
            old_path.unlink()
        path = write_experience_file(doc_id, merged)
    elif old_type != "official_sop" and new_type == "official_sop":
        old_path = EXPERIENCES_DIR / f"{doc_id}.md"
        if old_path.exists():
            old_path.unlink()
        path = write_sop_file(doc_id, merged)
    elif new_type == "official_sop":
        path = write_sop_file(doc_id, merged)
    else:
        path = write_experience_file(doc_id, merged)

    return {
        "message": "knowledge file updated",
        "doc_id": doc_id,
        "file_name": path.name,
        "relative_path": path.relative_to(KNOWLEDGE_BASE_DIR).as_posix(),
    }


@app.delete("/api/knowledge/files/{doc_id}")
def remove_knowledge_file(doc_id: str):
    delete_knowledge_file(doc_id)
    return {"message": "knowledge file deleted", "doc_id": doc_id}


@app.post("/api/knowledge/sync")
def sync_knowledge():
    try:
        runner = build_default_runner()
        result = runner.run_sync()
        return {
            "success": True,
            "message": "知识库同步完成",
            "result": result,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"knowledge sync failed: {exc}")


@app.post("/api/knowledge/search")
def search_knowledge(payload: KnowledgeSearchRequest):
    try:
        runner = build_default_runner()
        results = runner.search_knowledge(
            symptom_query=payload.symptom_query,
            component_tag=payload.component_tag,
            top_k=payload.top_k,
            knowledge_type=payload.knowledge_type,
        )
        return {
            "success": True,
            "query": payload.symptom_query,
            "count": len(results),
            "items": results,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"knowledge search failed: {exc}")