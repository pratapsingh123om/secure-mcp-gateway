from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    def __init__(self):
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._lock = threading.Lock()

    def increment(self, name: str, amount: float = 1.0, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += amount

    def render(self) -> str:
        lines = ["# Zero-Trust MCP Gateway metrics"]
        with self._lock:
            items = sorted(self._counters.items())
        for (name, labels), value in items:
            label_text = ""
            if labels:
                encoded = ",".join(f'{key}="{val}"' for key, val in labels)
                label_text = "{" + encoded + "}"
            lines.append(f"mcp_gateway_{name}{label_text} {value}")
        return "\n".join(lines) + "\n"
