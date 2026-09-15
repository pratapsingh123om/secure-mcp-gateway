from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from backend.models import DLPFinding, DLPResult


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("api_key", re.compile(r"\b(?:sk|pk|api|key)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{12,}\b", re.IGNORECASE)),
    ("synthetic_api_key", re.compile(r"\bsynthetic-sk-[A-Za-z0-9]+\b", re.IGNORECASE)),
    ("ssn", re.compile(r"\b(?:synthetic-)?\d{3}-\d{2}-\d{4}\b")),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]\d{4}(?!\w)")),
    ("payment_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
)

SENSITIVE_FIELDS = frozenset({
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key",
    "ssn", "social_security_number", "credit_card", "card_number", "private_key",
})


def _replacement(kind: str) -> str:
    return f"[REDACTED {kind.replace('_', ' ').upper()}]"


class DLPEngine:
    def inspect(self, value: Any, *, direction: str) -> DLPResult:
        findings: list[DLPFinding] = []
        result = self._walk(value, direction=direction, path="$", findings=findings)
        return DLPResult(result, tuple(findings))

    def _walk(self, value: Any, *, direction: str, path: str, findings: list[DLPFinding]) -> Any:
        if isinstance(value, Mapping):
            cleaned: dict[str, Any] = {}
            for key, child in value.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}"
                if key_text.lower() in SENSITIVE_FIELDS:
                    action = "BLOCK" if direction == "outbound" else "REDACT"
                    findings.append(DLPFinding("sensitive_field", child_path, action))
                    cleaned[key_text] = child if action == "BLOCK" else _replacement("sensitive_field")
                else:
                    cleaned[key_text] = self._walk(child, direction=direction, path=child_path, findings=findings)
            return cleaned
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._walk(item, direction=direction, path=f"{path}[{index}]", findings=findings)
                    for index, item in enumerate(value)]
        if not isinstance(value, str):
            return value

        cleaned = value
        for kind, pattern in PATTERNS:
            matches = list(pattern.finditer(cleaned))
            if not matches:
                continue
            action = "BLOCK" if direction == "outbound" else "REDACT"
            findings.extend(DLPFinding(kind, path, action) for _ in matches)
            if action == "REDACT":
                cleaned = pattern.sub(_replacement(kind), cleaned)
        return cleaned
