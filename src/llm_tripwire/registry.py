"""The registry: a JSON file listing every canary you have planted.

Keep it out of the systems you protect. Anyone who reads it learns the canary values and could avoid them.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from llm_tripwire.tokens import ALPHABET, ID_LENGTH, Kind

REGISTRY_VERSION = 1
DEFAULT_PATH = "tripwire.json"
ENV_VAR = "LLM_TRIPWIRE_REGISTRY"


class Canary(BaseModel):
    id: str
    kind: Kind
    value: str
    label: str = ""
    created: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    active: bool = True

    @property
    def core(self) -> str:
        """The lower-case ID, which every form of the canary contains."""
        return self.id.lower()


def default_path() -> Path:
    return Path(os.environ.get(ENV_VAR) or DEFAULT_PATH)


def _valid_id(canary_id: str) -> bool:
    return len(canary_id) == ID_LENGTH and all(c in ALPHABET for c in canary_id)


class Registry:
    def __init__(self, canaries: list[Canary] | None = None, path: Path | None = None) -> None:
        self.canaries: list[Canary] = list(canaries or [])
        self.path = path

    @classmethod
    def load(cls, path: Path | str | None = None, *, missing_ok: bool = False) -> Registry:
        p = Path(path) if path is not None else default_path()
        if not p.exists():
            if missing_ok:
                return cls([], p)
            raise FileNotFoundError(f"{p}: no canary registry; create one with `llm-tripwire mint`")
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != REGISTRY_VERSION:
            raise ValueError(
                f"{p}: unsupported registry version {data.get('version') if isinstance(data, dict) else None!r}"
            )
        canaries = [Canary.model_validate(c) for c in data.get("canaries", [])]
        for c in canaries:
            if not _valid_id(c.id):
                raise ValueError(f"{p}: invalid canary id {c.id!r}")
        return cls(canaries, p)

    def save(self, path: Path | str | None = None) -> Path:
        p = Path(path) if path is not None else (self.path or default_path())
        doc = {
            "version": REGISTRY_VERSION,
            "tool": "llm-tripwire",
            "canaries": [c.model_dump(mode="json") for c in self.canaries],
        }
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
        if os.name != "nt":
            tmp.chmod(0o600)
        tmp.replace(p)
        self.path = p
        return p

    def add(self, canary: Canary) -> Canary:
        if self.get(canary.id) is not None:
            raise ValueError(f"duplicate canary id {canary.id}")
        self.canaries.append(canary)
        return canary

    def get(self, canary_id: str) -> Canary | None:
        wanted = canary_id.upper()
        return next((c for c in self.canaries if c.id == wanted), None)

    @property
    def active(self) -> list[Canary]:
        return [c for c in self.canaries if c.active]
