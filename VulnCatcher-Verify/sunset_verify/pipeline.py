"""VulnCatcher-Verify pipeline: collect POCs -> sandbox execute -> judge -> report."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .agents import (
    EvidenceJudgeAgent,
    PocCollectorAgent,
    SandboxExecutorAgent,
    VerificationReporterAgent,
)
from .collector import discover_results
from .config import VerifySettings
from .models import VerificationResult


def _one(result_dir: Path, settings: VerifySettings) -> tuple[list[VerificationResult], list[dict]]:
    started = time.time()
    stages: list[dict] = []
    collector = PocCollectorAgent()
    cases, stage = collector.run(result_dir, mode=settings.mode, base=settings.target_base)
    stages.append(stage)
    executor = SandboxExecutorAgent()
    judge_agent = EvidenceJudgeAgent()
    results: list[VerificationResult] = []
    for case in cases:
        baseline, attack, exec_stage = executor.run(
            case,
            timeout=settings.timeout,
            insecure=settings.insecure,
            allow_hosts=settings.allow_hosts,
            follow_redirects=settings.follow_redirects,
        )
        stages.append(exec_stage)
        result, judge_stage = judge_agent.run(case, baseline, attack)
        stages.append(judge_stage)
        results.append(result)
    reporter = VerificationReporterAgent()
    out = reporter.write_run(
        result_dir, results, stages, mode=settings.mode, target_base=settings.target_base
    )
    stages.append({
        "agent": "verification_reporter",
        "codename": "验证报告",
        "out": str(out),
        "duration_sec": round(time.time() - started, 2),
    })
    return results, stages


def verify_result(result_dir: Path, settings: VerifySettings) -> tuple[list[VerificationResult], list[dict]]:
    return _one(result_dir, settings)


def verify_batch(settings: VerifySettings) -> tuple[list[VerificationResult], list[dict]]:
    root = settings.results_dir
    if root is None:
        raise ValueError("results_dir is required for batch mode")
    result_dirs = discover_results(root)
    all_results: list[VerificationResult] = []
    all_stages: list[dict] = []
    if not result_dirs:
        return all_results, all_stages
    workers = max(1, min(settings.workers, 8, len(result_dirs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_one, item, settings): item for item in result_dirs}
        for future in as_completed(futures):
            result_dir = futures[future]
            try:
                results, stages = future.result()
            except Exception as exc:  # noqa: BLE001
                all_stages.append({
                    "agent": "verification_pipeline",
                    "result_dir": str(result_dir),
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue
            all_results.extend(results)
            all_stages.extend(stages)
    if settings.out_dir:
        VerificationReporterAgent().write_aggregate(
            settings.out_dir, all_results, mode=settings.mode, target_base=settings.target_base
        )
    return all_results, all_stages


def summarize(results: list[VerificationResult]) -> dict:
    from collections import Counter
    counts = Counter(item.verdict for item in results)
    return {
        "total": len(results),
        "verified": counts.get("verified", 0),
        "rejected": counts.get("rejected", 0),
        "inconclusive": counts.get("inconclusive", 0),
        "unsupported": counts.get("unsupported", 0),
        "error": counts.get("error", 0),
        "by_verdict": dict(counts),
    }
