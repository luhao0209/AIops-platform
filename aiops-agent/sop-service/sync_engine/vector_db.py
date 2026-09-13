from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, FieldCondition, Filter, MatchValue, PointStruct, VectorParams


@dataclass
class QdrantConfig:
    url: str
    collection_name: str
    api_key: str | None = None


class VectorDBManager:
    def __init__(self, config: QdrantConfig) -> None:
        self.config = config
        self.client = QdrantClient(
            url=config.url,
            api_key=config.api_key,
        )

    def collection_exists(self) -> bool:
        collections = self.client.get_collections().collections
        return any(item.name == self.config.collection_name for item in collections)

    def recreate_collection(self, vector_size: int) -> None:
        if self.collection_exists():
            self.client.delete_collection(self.config.collection_name)

        self.client.create_collection(
            collection_name=self.config.collection_name,
            vectors_config=VectorParams(
                size=vector_size,
                distance=Distance.COSINE,
            ),
        )

    def upsert_points(self, points: list[dict[str, Any]]) -> None:
        if not points:
            return

        payloads: list[PointStruct] = []
        for item in points:
            payloads.append(
                PointStruct(
                    id=item["point_id"],
                    vector=item["vector"],
                    payload=item["payload"],
                )
            )

        self.client.upsert(
            collection_name=self.config.collection_name,
            points=payloads,
        )

    def search(
        self,
        query_vector: list[float],
        limit: int = 5,
        knowledge_type: str | None = None,
        component_tag: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []

        if knowledge_type:
            conditions.append(
                FieldCondition(
                    key="type",
                    match=MatchValue(value=knowledge_type),
                )
            )

        if component_tag:
            conditions.append(
                FieldCondition(
                    key="applicable_components",
                    match=MatchValue(value=component_tag),
                )
            )

        query_filter = Filter(must=conditions) if conditions else None

        results = self.client.search(
            collection_name=self.config.collection_name,
            query_vector=query_vector,
            query_filter=query_filter,
            limit=limit,
            with_payload=True,
            with_vectors=False,
        )

        items: list[dict[str, Any]] = []
        for item in results:
            items.append(
                {
                    "id": str(item.id),
                    "score": item.score,
                    "payload": item.payload or {},
                }
            )
        return items