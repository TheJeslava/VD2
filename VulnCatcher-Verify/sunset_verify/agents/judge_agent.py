"""EvidenceJudgeAgent: compare baseline/attack and classify the POC."""

from __future__ import annotations

import time

from ..judge import judge
from ..models import HttpEvidence, PocCase, VerificationResult


class EvidenceJudgeAgent:
    name = "evidence_judge"
    codename = "证据研判"

    def run(self, case: PocCase, baseline: HttpEvidence, attack: HttpEvidence) -> tuple[VerificationResult, dict]:
        started = time.time()
        result = judge(case, baseline, attack, case.last_attack_sequence)
        return result, {
            "agent": self.name,
            "codename": self.codename,
            "finding_id": case.finding_id,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "duration_sec": round(time.time() - started, 2),
        }
