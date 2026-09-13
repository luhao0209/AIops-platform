from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .parser import ParsedDocument


@dataclass
class ChunkedDocument:
    point_id: str
    chunk_id: str
    chunk_type: str
    search_text: str
    content_hash: str
    payload: dict[str, Any]


class ChunkBuilder:
    def build(self, parsed: ParsedDocument) -> list[ChunkedDocument]:
        if parsed.source_type == "workflow_sop":
            return [self._build_full_chunk(parsed)]
        if parsed.source_type == "skill_experience":
            return self._build_markdown_chunks(parsed)
        raise ValueError(f"unsupported source_type: {parsed.source_type}")

    def _build_full_chunk(self, parsed: ParsedDocument) -> ChunkedDocument:
        chunk_id = f"{parsed.doc_id}#full"
        payload = dict(parsed.payload)
        payload["section"] = "full"
        payload["chunk_text"] = parsed.search_text
        return ChunkedDocument(
            point_id=self._make_point_id(chunk_id),
            chunk_id=chunk_id,
            chunk_type="full",
            search_text=parsed.search_text,
            content_hash=self._sha256(parsed.search_text),
            payload=payload,
        )

    def _build_markdown_chunks(self, parsed: ParsedDocument) -> list[ChunkedDocument]:
        text = parsed.search_text.strip()
        if not text:
            return []

        sections = self._split_markdown_sections(text)
        if len(sections) <= 1:
            chunk_id = f"{parsed.doc_id}#section-0"
            payload = dict(parsed.payload)
            payload["section_index"] = 0
            payload["section"] = "section-0"
            payload["chunk_text"] = text
            return [
                ChunkedDocument(
                    point_id=self._make_point_id(chunk_id),
                    chunk_id=chunk_id,
                    chunk_type="markdown_section",
                    search_text=text,
                    content_hash=self._sha256(text),
                    payload=payload,
                )
            ]

        chunks: list[ChunkedDocument] = []
        for index, section in enumerate(sections):
            section_text = section.strip()
            if not section_text:
                continue
            chunk_id = f"{parsed.doc_id}#section-{index}"
            payload = dict(parsed.payload)
            payload["section_index"] = index
            payload["section"] = f"section-{index}"
            payload["chunk_text"] = section_text
            chunks.append(
                ChunkedDocument(
                    point_id=self._make_point_id(chunk_id),
                    chunk_id=chunk_id,
                    chunk_type="markdown_section",
                    search_text=section_text,
                    content_hash=self._sha256(section_text),
                    payload=payload,
                )
            )
        return chunks

    @staticmethod
    def _split_markdown_sections(text: str) -> list[str]:
        pattern = re.compile(r"(?=^##\s+|^###\s+)", re.MULTILINE)
        parts = pattern.split(text)
        return [part for part in parts if part.strip()]

    @staticmethod
    def _sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _make_point_id(chunk_id: str) -> str:
        return hashlib.md5(chunk_id.encode("utf-8")).hexdigest()