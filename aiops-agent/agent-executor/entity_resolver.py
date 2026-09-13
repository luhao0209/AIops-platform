from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _normalize_text(value: str) -> str:
    text = (value or "").strip().lower()
    text = text.replace("（", "(").replace("）", ")")
    text = re.sub(r"\s+", " ", text)
    return text


def _contains_alias(query: str, alias: str) -> bool:
    q = _normalize_text(query)
    a = _normalize_text(alias)
    if not q or not a:
        return False
    if a in q:
        return True




    return a.replace(" ", "") in q.replace(" ", "")


class EntityResolver:
    def __init__(self, catalog_path: str | Path) -> None:
        self.catalog_path = Path(catalog_path)
        self.catalog = self._load_catalog()

    def _load_catalog(self) -> dict[str, Any]:
        if not self.catalog_path.exists():
            raise RuntimeError(f"entity catalog not found: {self.catalog_path}")
        return json.loads(self.catalog_path.read_text(encoding="utf-8-sig"))

    def reload(self) -> None:
        self.catalog = self._load_catalog()

    def resolve(self, query: str) -> dict[str, Any]:
        retired_aliases = self.catalog.get("retired_aliases", [])
        if not isinstance(retired_aliases, list):
            retired_aliases = []

        retired_hits = [
            str(alias).strip()
            for alias in retired_aliases
            if str(alias).strip() and _contains_alias(query, str(alias))
        ]
        if retired_hits:
            return {
                "status": "unresolved",
                "query": query,
                "matches": [],
                "reason": "retired_entity_alias",
                "retired_aliases": retired_hits,
            }

        entities = self.catalog.get("entities", [])
        if not isinstance(entities, list):
            entities = []

        matches: list[dict[str, Any]] = []

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            aliases = entity.get("aliases", [])
            if not isinstance(aliases, list):
                aliases = []

            candidate_aliases = [entity.get("name", "")] + aliases
            hit_aliases: list[str] = []

            for alias in candidate_aliases:
                alias_text = str(alias).strip()
                if alias_text and _contains_alias(query, alias_text):
                    hit_aliases.append(alias_text)

            if not hit_aliases:
                continue

            best_alias = sorted(hit_aliases, key=lambda item: len(item), reverse=True)[0]

            matches.append(
                {
                    "entity_id": str(entity.get("entity_id", "")),
                    "name": str(entity.get("name", "")),
                    "kind": str(entity.get("kind", "")),
                    "namespace": entity.get("namespace"),
                    "plane": str(entity.get("plane", "")),
                    "on_request_path": bool(entity.get("on_request_path", False)),
                    "notes": str(entity.get("notes", "")),
                    "matched_alias": best_alias,
                    "matched_alias_length": len(best_alias),
                }
            )

        if not matches:
            return {
                "status": "unresolved",
                "query": query,
                "matches": [],
            }

        matches.sort(
            key=lambda item: (
                item["matched_alias_length"],
                1 if item.get("on_request_path") else 0,
            ),
            reverse=True,
        )

        best_length = matches[0]["matched_alias_length"]
        top_matches = [item for item in matches if item["matched_alias_length"] == best_length]

        unique_top = []
        seen_ids: set[str] = set()
        for item in top_matches:
            entity_id = item["entity_id"]
            if entity_id in seen_ids:
                continue
            seen_ids.add(entity_id)
            unique_top.append(item)

        if len(unique_top) == 1:
            return {
                "status": "resolved",
                "query": query,
                "entity": unique_top[0],
                "matches": unique_top,
            }

        return {
            "status": "ambiguous",
            "query": query,
            "matches": unique_top,
        }


def build_default_entity_resolver() -> EntityResolver:
    base_dir = Path(__file__).resolve().parent
    candidates = [
        Path("/app/data/entity_catalog.json"),
        Path("/app/bootstrap_data/entity_catalog.json"),
        base_dir / "data" / "entity_catalog.json",
        base_dir / "bootstrap_data" / "entity_catalog.json",
    ]
    for catalog_path in candidates:
        if catalog_path.exists():
            return EntityResolver(catalog_path)
    checked = ", ".join(str(path) for path in candidates)
    raise RuntimeError(f"entity catalog not found, checked: {checked}")
