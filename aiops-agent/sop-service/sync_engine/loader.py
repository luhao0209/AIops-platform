from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class SourceFile:
    doc_id: str
    source_type: str
    path: Path
    relative_path: str
    content: str


class KnowledgeLoader:
    def __init__(self, knowledge_base_dir: str | Path) -> None:
        self.knowledge_base_dir = Path(knowledge_base_dir)

    def load_all(self) -> list[SourceFile]:
        files: list[SourceFile] = []
        files.extend(self._load_sops())
        files.extend(self._load_experiences())
        return sorted(files, key=lambda item: item.relative_path)

    def _load_sops(self) -> list[SourceFile]:
        sop_dir = self.knowledge_base_dir / "sops"
        if not sop_dir.exists():
            return []

        items: list[SourceFile] = []
        for path in sorted(sop_dir.rglob("*.json")):
            relative_path = path.relative_to(self.knowledge_base_dir).as_posix()
            items.append(
                SourceFile(
                    doc_id=path.stem,
                    source_type="workflow_sop",
                    path=path,
                    relative_path=relative_path,
                    content=path.read_text(encoding="utf-8-sig"),
                )
            )
        return items

    def _load_experiences(self) -> list[SourceFile]:
        exp_dir = self.knowledge_base_dir / "experiences"
        if not exp_dir.exists():
            return []

        items: list[SourceFile] = []
        for path in sorted(exp_dir.rglob("*.md")):
            relative_path = path.relative_to(self.knowledge_base_dir).as_posix()
            items.append(
                SourceFile(
                    doc_id=path.stem,
                    source_type="skill_experience",
                    path=path,
                    relative_path=relative_path,
                    content=path.read_text(encoding="utf-8-sig"),
                )
            )
        return items