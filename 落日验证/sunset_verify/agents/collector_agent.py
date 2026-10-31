"""PocCollectorAgent: read a 落日二号 result and turn POCs into replay cases."""

from __future__ import annotations

import time
from pathlib import Path

from ..collector import collect_from_result
from ..models import PocCase


class PocCollectorAgent:
    name = "poc_collector"
    codename = "POC 收集"

    def run(self, result_dir: Path, *, mode: str, base: str) -> tuple[list[PocCase], dict]:
        started = time.time()
        cases = collect_from_result(result_dir, mode=mode, base=base)
        return cases, {
            "agent": self.name,
            "codename": self.codename,
            "result_dir": str(result_dir),
            "cases": len(cases),
            "duration_sec": round(time.time() - started, 2),
        }
