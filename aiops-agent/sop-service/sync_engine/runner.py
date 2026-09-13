from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .chunker import ChunkBuilder
from .embedding import EmbeddingProvider
from .loader import KnowledgeLoader
from .parser import DocumentParser
from .vector_db import QdrantConfig, VectorDBManager


class KnowledgeSyncRunner:
    def __init__(
        self,
        knowledge_loader: KnowledgeLoader,
        document_parser: DocumentParser,
        chunk_builder: ChunkBuilder,
        embedding_provider: EmbeddingProvider,
        vector_db: VectorDBManager,
    ) -> None:
        self.knowledge_loader = knowledge_loader
        self.document_parser = document_parser
        self.chunk_builder = chunk_builder
        self.embedding_provider = embedding_provider
        self.vector_db = vector_db

    def run_sync(self) -> dict[str, Any]:
        source_files = self.knowledge_loader.load_all()
        if not source_files:
            return {
                "loaded_files": 0,
                "synced_files": 0,
                "skipped_files": 0,
                "deleted_files": 0,
                "collection": self.vector_db.config.collection_name,
                "message": "no knowledge files found",
            }

        parsed_documents = [self.document_parser.parse(source_file) for source_file in source_files]

        chunked_documents = []
        for parsed in parsed_documents:
            chunked_documents.extend(self.chunk_builder.build(parsed))

        if not chunked_documents:
            return {
                "loaded_files": len(source_files),
                "synced_files": 0,
                "skipped_files": len(source_files),
                "deleted_files": 0,
                "collection": self.vector_db.config.collection_name,
                "message": "no valid knowledge chunks generated",
            }

        texts = [chunk.search_text for chunk in chunked_documents]
        embeddings = self.embedding_provider.embed_many(texts)
        if not embeddings:
            raise ValueError("embedding results are empty")

        self.vector_db.recreate_collection(embeddings[0].dimension)

        points: list[dict[str, Any]] = []
        for chunk, embedding in zip(chunked_documents, embeddings, strict=False):
            payload = dict(chunk.payload)
            payload["chunk_id"] = chunk.chunk_id
            payload["chunk_type"] = chunk.chunk_type
            payload["content_hash"] = chunk.content_hash

            points.append(
                {
                    "point_id": chunk.point_id,
                    "vector": embedding.vector,
                    "payload": payload,
                }
            )

        self.vector_db.upsert_points(points)

        return {
            "loaded_files": len(source_files),
            "synced_files": len(parsed_documents),
            "skipped_files": 0,
            "deleted_files": 0,
            "chunk_count": len(chunked_documents),
            "collection": self.vector_db.config.collection_name,
        }

    def search_knowledge(
        self,
        symptom_query: str,
        component_tag: str | None = None,
        top_k: int = 3,
        knowledge_type: str | None = None,
    ) -> list[dict[str, Any]]:
        query_embedding = self.embedding_provider.embed(symptom_query)

        raw_hits = self.vector_db.search(
            query_vector=query_embedding.vector,
            limit=max(top_k * 4, 8),
            knowledge_type=knowledge_type,
            component_tag=component_tag,
        )

        results: list[dict[str, Any]] = []

        for hit in raw_hits:
            payload = hit.get("payload", {})
            knowledge_id = payload.get("knowledge_id")
            if not knowledge_id:
                continue

            results.append(
                {
                    "knowledge_id": knowledge_id,
                    "doc_id": payload.get("doc_id", ""),
                    "title": payload.get("title", ""),
                    "doc_type": payload.get("type", ""),
                    "type_label": payload.get("type_label", ""),
                    "section": payload.get("section", ""),
                    "section_index": payload.get("section_index", 0),
                    "chunk_id": payload.get("chunk_id", ""),
                    "chunk_type": payload.get("chunk_type", ""),
                    "chunk_text": payload.get("chunk_text", ""),
                    "relative_path": payload.get("relative_path", ""),
                    "file_name": payload.get("file_name", ""),
                    "score": hit.get("score", 0),
                    "tags": payload.get("tags", []),
                    "applicable_components": payload.get("applicable_components", []),
                }
            )

            if len(results) >= top_k:
                break

        return results


def build_default_runner() -> KnowledgeSyncRunner:
    base_dir = Path(__file__).resolve().parent.parent
    knowledge_base_dir = base_dir / "knowledge_base"

    qdrant_url = os.getenv("QDRANT_URL", "http://qdrant:6333")
    qdrant_api_key = os.getenv("QDRANT_API_KEY", "").strip() or None
    qdrant_collection = os.getenv("QDRANT_COLLECTION", "aiops_knowledge")

    knowledge_loader = KnowledgeLoader(knowledge_base_dir)
    document_parser = DocumentParser()
    chunk_builder = ChunkBuilder()
    embedding_provider = EmbeddingProvider()
    vector_db = VectorDBManager(
        QdrantConfig(
            url=qdrant_url,
            collection_name=qdrant_collection,
            api_key=qdrant_api_key,
        )
    )

    return KnowledgeSyncRunner(
        knowledge_loader=knowledge_loader,
        document_parser=document_parser,
        chunk_builder=chunk_builder,
        embedding_provider=embedding_provider,
        vector_db=vector_db,
    )