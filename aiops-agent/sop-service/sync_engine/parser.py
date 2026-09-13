from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .loader import SourceFile


@dataclass
class ParsedDocument:
    doc_id: str
    source_type: str
    title: str
    summary: str
    search_text: str
    payload: dict[str, Any]


def build_knowledge_id(doc_id: str) -> str:
    return f"KNOW-{doc_id.upper().replace('__', '-').replace('_', '-')}"


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                result.append(text)
        return result
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if "\n" in raw:
            return [line.strip() for line in raw.splitlines() if line.strip()]
        if "，" in raw:
            raw = raw.replace("，", ",")
        if "," in raw:
            return [item.strip() for item in raw.split(",") if item.strip()]
        return [raw]
    return [str(value).strip()] if str(value).strip() else []


def normalize_text_block(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return "\n".join(items)
    return str(value).strip()


class DocumentParser:
    def parse(self, source_file: SourceFile) -> ParsedDocument:
        if source_file.source_type == "workflow_sop":
            return self._parse_sop(source_file)
        if source_file.source_type == "skill_experience":
            return self._parse_experience(source_file)
        raise ValueError(f"unsupported source_type: {source_file.source_type}")

    def _parse_sop(self, source_file: SourceFile) -> ParsedDocument:
        data = json.loads(source_file.content)

        title = str(data.get("title") or source_file.path.stem).strip()
        knowledge_type = str(data.get("type") or "official_sop").strip()
        summary = str(
            data.get("summary")
            or data.get("scene")
            or data.get("description")
            or title
        ).strip()

        trigger_conditions = normalize_string_list(data.get("trigger_conditions", []))
        symptoms = normalize_string_list(data.get("symptoms", []))
        applicable_components = normalize_string_list(data.get("applicable_components", []))
        tags = normalize_string_list(data.get("tags", []))
        risk_warnings = normalize_text_block(data.get("risk_warnings", ""))
        rollback_advice = normalize_text_block(data.get("rollback_advice", ""))

        workflow_steps = data.get("workflow_steps", [])
        recommended_steps = data.get("recommended_steps", [])

        workflow_step_texts: list[str] = []
        if isinstance(workflow_steps, list):
            for step in workflow_steps:
                if not isinstance(step, dict):
                    continue
                name = str(step.get("name") or "").strip()
                desc = str(step.get("description") or "").strip()
                expected = str(step.get("expected_result") or "").strip()
                pieces = [item for item in [name, desc, expected] if item]
                if pieces:
                    workflow_step_texts.append("；".join(pieces))

        recommended_step_texts: list[str] = []
        normalized_recommended_steps: list[dict[str, Any]] = []
        if isinstance(recommended_steps, list):
            for index, step in enumerate(recommended_steps, start=1):
                if not isinstance(step, dict):
                    continue
                action = str(step.get("action") or "").strip()
                recommended_command = str(step.get("recommended_command") or "").strip()
                output_focus = str(step.get("output_focus") or "").strip()
                if action:
                    normalized_recommended_steps.append(
                        {
                            "step_order": step.get("step_order") or index,
                            "action": action,
                            "recommended_command": recommended_command,
                            "output_focus": output_focus,
                        }
                    )
                pieces = [item for item in [action, output_focus] if item]
                if pieces:
                    recommended_step_texts.append("；".join(pieces))

        search_parts = [
            title,
            summary,
            "；".join(symptoms),
            "；".join(trigger_conditions),
            "；".join(applicable_components),
            "；".join(tags),
            "；".join(workflow_step_texts),
            "；".join(recommended_step_texts),
            risk_warnings,
            rollback_advice,
        ]
        search_text = "\n".join(part for part in search_parts if part.strip())

        knowledge_id = str(data.get("knowledge_id") or build_knowledge_id(source_file.doc_id)).strip()

        payload = {
            "knowledge_id": knowledge_id,
            "doc_id": source_file.doc_id,
            "title": title,
            "type": knowledge_type,
            "type_label": "SOP",
            "source_type": source_file.source_type,
            "relative_path": source_file.relative_path,
            "file_name": source_file.path.name,
            "summary": summary,
            "scene": str(data.get("scene") or summary).strip(),
            "symptoms": symptoms,
            "trigger_conditions": trigger_conditions,
            "applicable_components": applicable_components,
            "workflow_steps": workflow_steps if isinstance(workflow_steps, list) else [],
            "recommended_steps": normalized_recommended_steps,
            "risk_warnings": risk_warnings,
            "rollback_advice": rollback_advice,
            "tags": tags,
            "created_by": str(data.get("created_by") or "file-system").strip(),
            "source_kind": "file",
            "markdown_content": "",
            "raw_document": data,
        }

        return ParsedDocument(
            doc_id=source_file.doc_id,
            source_type=source_file.source_type,
            title=title,
            summary=summary,
            search_text=search_text,
            payload=payload,
        )

    def _parse_experience(self, source_file: SourceFile) -> ParsedDocument:
        content = source_file.content
        lines = content.splitlines()

        title = source_file.path.stem
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
        if not summary:
            summary = title

        knowledge_id = build_knowledge_id(source_file.doc_id)
        metadata_match = re.search(r"^- knowledge_id:\s*(.+)$", content, re.MULTILINE)
        if metadata_match:
            knowledge_id = metadata_match.group(1).strip()

        tags: list[str] = []
        tags_match = re.search(r"^## 标签\s*(.*?)$", content, re.MULTILINE)
        if tags_match:
            tags = normalize_string_list(tags_match.group(1))

        payload = {
            "knowledge_id": knowledge_id,
            "doc_id": source_file.doc_id,
            "title": title,
            "type": "incident_experience",
            "type_label": "运维经验文档",
            "source_type": source_file.source_type,
            "relative_path": source_file.relative_path,
            "file_name": source_file.path.name,
            "summary": summary,
            "scene": summary,
            "symptoms": [],
            "trigger_conditions": [],
            "applicable_components": [],
            "recommended_steps": [],
            "risk_warnings": "",
            "rollback_advice": "",
            "tags": tags,
            "created_by": "file-system",
            "source_kind": "file",
            "markdown_content": content,
            "raw_markdown": content,
        }

        return ParsedDocument(
            doc_id=source_file.doc_id,
            source_type=source_file.source_type,
            title=title,
            summary=summary,
            search_text=content.strip(),
            payload=payload,
        )