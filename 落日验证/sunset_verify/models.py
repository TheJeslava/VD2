"""Data models for 落日验证 (Sunset Verify)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "body": self.body.decode("utf-8", errors="replace")[:4000],
            "raw": self.raw[:4000],
        }


@dataclass
class PocCase:
    result_dir: str
    finding_id: str
    vulnerability_type: str
    title: str
    endpoint: str
    mode: str
    target_url: str = ""
    baseline: HttpRequest | None = None
    attack: HttpRequest | None = None
    # Requests after the baseline are replayed in order with one cookie jar.
    # A single-request POC keeps this list empty for backward compatibility.
    attack_sequence: list[HttpRequest] = field(default_factory=list)
    last_attack_sequence: list[HttpEvidence] = field(default_factory=list)
    source: str = ""
    notes: str = ""


@dataclass
class HttpEvidence:
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    error: str = ""
    duration_ms: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headers": dict(self.headers),
            "body_length": len(self.body),
            "body_preview": self.body[:1200],
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class VerificationResult:
    result_dir: str
    finding_id: str
    vulnerability_type: str
    title: str
    endpoint: str
    mode: str
    verdict: str = "inconclusive"  # verified / rejected / inconclusive / unsupported / error
    confidence: float = 0.0
    reason: str = ""
    target_url: str = ""
    baseline: HttpEvidence = field(default_factory=HttpEvidence)
    attack: HttpEvidence = field(default_factory=HttpEvidence)
    attack_sequence: list[HttpEvidence] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_dir": self.result_dir,
            "finding_id": self.finding_id,
            "vulnerability_type": self.vulnerability_type,
            "title": self.title,
            "endpoint": self.endpoint,
            "mode": self.mode,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reason": self.reason,
            "target_url": self.target_url,
            "baseline": self.baseline.summary(),
            "attack": self.attack.summary(),
            "attack_sequence": [item.summary() for item in self.attack_sequence],
            "markers": self.markers,
            "notes": self.notes,
        }
