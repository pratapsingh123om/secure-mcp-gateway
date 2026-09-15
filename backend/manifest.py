from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from backend.audit import hash_value
from backend.models import ManifestStatus


SUSPICIOUS_DESCRIPTION = re.compile(
    r"ignore (?:all |the )?(?:previous|prior)|system prompt|exfiltrat|send (?:all )?secrets|override instructions",
    re.IGNORECASE,
)


def canonical_catalog(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for tool in tools:
        normalized.append({
            "name": tool.get("name"),
            "description": tool.get("description") or "",
            "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
            "outputSchema": tool.get("outputSchema") or tool.get("output_schema"),
            "annotations": tool.get("annotations"),
        })
    return sorted(normalized, key=lambda item: str(item["name"]))


class ManifestRegistry:
    def __init__(self, path: Path, cache_seconds: int = 30):
        self.path = path
        self.cache_seconds = cache_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, tuple[float, ManifestStatus]] = {}
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "upstreams": {}}
        with self.path.open("r", encoding="utf-8") as stream:
            return json.load(stream)

    def evaluate(self, upstream: str, tools: list[dict[str, Any]]) -> ManifestStatus:
        catalog = canonical_catalog(tools)
        current_hash = hash_value(catalog)
        suspicious = [
            str(tool["name"])
            for tool in catalog
            if SUSPICIOUS_DESCRIPTION.search(str(tool.get("description") or ""))
        ]
        with self._lock:
            approved = self._load().get("upstreams", {}).get(upstream)
        approved_hash = approved.get("hash") if isinstance(approved, dict) else None
        allow_suspicious = bool(approved.get("allow_suspicious")) if isinstance(approved, dict) else False
        if approved_hash is None:
            status = "UNAPPROVED"
        elif approved_hash != current_hash:
            status = "QUARANTINED_DRIFT"
        elif suspicious and not allow_suspicious:
            status = "QUARANTINED_SUSPICIOUS"
        elif suspicious:
            status = "TRUSTED_WITH_WARNINGS"
        else:
            status = "TRUSTED"
        result = ManifestStatus(
            upstream=upstream,
            approved_hash=approved_hash,
            current_hash=current_hash,
            status=status,
            suspicious_descriptions=suspicious,
            tools=[str(tool["name"]) for tool in catalog],
        )
        self._cache[upstream] = (time.monotonic(), result)
        return result

    def cached(self, upstream: str) -> ManifestStatus | None:
        cached = self._cache.get(upstream)
        if not cached or time.monotonic() - cached[0] > self.cache_seconds:
            return None
        return cached[1]

    def approve(self, upstream: str, tools: list[dict[str, Any]], *, allow_suspicious: bool = False) -> ManifestStatus:
        catalog = canonical_catalog(tools)
        record = {
            "hash": hash_value(catalog),
            "catalog": catalog,
            "allow_suspicious": allow_suspicious,
        }
        with self._lock:
            data = self._load()
            data.setdefault("upstreams", {})[upstream] = record
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temporary.replace(self.path)
        return self.evaluate(upstream, tools)
