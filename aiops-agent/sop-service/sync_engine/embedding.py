from __future__ import annotations

import os
from dataclasses import dataclass

import requests

from token_usage_store import add_tokens, normalize_embedding_usage


@dataclass
class EmbeddingResult:
    vector: list[float]
    dimension: int
    model: str


class EmbeddingProvider:
    def __init__(
        self,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str | None = None,
        dimension: int | None = None,
        timeout_seconds: int = 30,
        batch_size: int = 10,
    ) -> None:
        self.api_key = api_key or os.getenv("EMBEDDING_API_KEY", "").strip()
        self.api_base = (
            api_base
            or os.getenv("EMBEDDING_API_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        ).rstrip("/")
        self.model = model or os.getenv("EMBEDDING_MODEL", "text-embedding-v4")
        self.dimension = dimension or int(os.getenv("EMBEDDING_DIMENSION", "1024"))
        self.timeout_seconds = timeout_seconds
        self.batch_size = batch_size

        if not self.api_key:
            raise ValueError("EMBEDDING_API_KEY is not configured")

    def _account_usage(self, body: dict, texts: list[str]) -> None:
        usage = normalize_embedding_usage(body.get("usage"), texts=texts)
        total = int(usage.get("total_tokens") or 0)
        if total > 0:
            add_tokens("vector", total, estimated=bool(usage.get("estimated")))

    def _post_embeddings(self, payload: dict) -> dict:
        response = requests.post(
            f"{self.api_base}/embeddings",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout_seconds,
        )

        if not response.ok:
            raise ValueError(
                f"embedding request failed: status={response.status_code}, body={response.text}"
            )

        return response.json()

    def embed(self, text: str) -> EmbeddingResult:
        cleaned = (text or "").strip()
        if not cleaned:
            raise ValueError("embedding text is empty")

        payload = {
            "model": self.model,
            "input": cleaned,
            "dimensions": self.dimension,
            "encoding_format": "float",
        }

        body = self._post_embeddings(payload)
        self._account_usage(body, [cleaned])
        data = body.get("data") or []
        if not data:
            raise ValueError(f"embedding response missing data: {body}")

        vector = data[0].get("embedding")
        if not isinstance(vector, list) or not vector:
            raise ValueError(f"embedding response missing embedding vector: {body}")

        return EmbeddingResult(
            vector=vector,
            dimension=len(vector),
            model=body.get("model") or self.model,
        )

    def embed_many(self, texts: list[str]) -> list[EmbeddingResult]:
        items = [text.strip() for text in texts if text and text.strip()]
        if not items:
            return []

        all_results: list[EmbeddingResult] = []

        for start in range(0, len(items), self.batch_size):
            batch = items[start : start + self.batch_size]

            payload = {
                "model": self.model,
                "input": batch,
                "dimensions": self.dimension,
                "encoding_format": "float",
            }

            body = self._post_embeddings(payload)
            self._account_usage(body, batch)
            data = body.get("data") or []
            if not data:
                raise ValueError(f"embedding response missing data: {body}")

            for item in data:
                vector = item.get("embedding")
                if not isinstance(vector, list) or not vector:
                    raise ValueError(f"embedding response item missing vector: {item}")
                all_results.append(
                    EmbeddingResult(
                        vector=vector,
                        dimension=len(vector),
                        model=body.get("model") or self.model,
                    )
                )

        return all_results
