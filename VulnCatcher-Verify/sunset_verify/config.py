"""Configuration helpers for VulnCatcher-Verify."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class VerifySettings:
    mode: str = "url"  # url / zip
    result_dir: Path | None = None
    results_dir: Path | None = None
    target_base: str = ""
    out_dir: Path | None = None
    timeout: float = 15.0
    insecure: bool = True
    follow_redirects: bool = False
    workers: int = 4
    allow_hosts: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
