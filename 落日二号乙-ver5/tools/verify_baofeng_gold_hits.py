"""Verify all replayable POCs from gold-category-correct Baofeng samples."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
VERIFIER = ROOT / "wasted" / "落日验证-ver4"
sys.path.insert(0, str(PROJECT / "tools"))
sys.path.insert(0, str(VERIFIER))

from evaluate_baofeng import build_report  # noqa: E402
from sunset_verify.config import VerifySettings  # noqa: E402
from sunset_verify.pipeline import verify_result  # noqa: E402
from sunset_verify.agents.reporter_agent import VerificationReporterAgent  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--target-base", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()

    _, evaluation = build_report(args.results)
    hits = {sample for sample, info in evaluation["samples"].items() if info["hit"]}
    reporter = VerificationReporterAgent()
    results = []
    missing: list[str] = []
    for sample in sorted(hits):
        source = args.results / sample
        report_path = source / "report.json"
        if not report_path.is_file():
            missing.append(sample)
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        selected = [finding for finding in report.get("findings", [])
                    if isinstance(finding, dict) and finding.get("poc")]
        if not selected:
            missing.append(sample)
            continue
        report["findings"] = selected
        with tempfile.TemporaryDirectory(prefix=f"sunset-verify-{sample}-") as tmp:
            staged = Path(tmp) / sample
            staged.mkdir(parents=True)
            (staged / "report.json").write_text(
                json.dumps(report, ensure_ascii=False), encoding="utf-8"
            )
            run_results, stages = verify_result(staged, VerifySettings(
                mode="zip", result_dir=staged, target_base=args.target_base,
                out_dir=None, timeout=args.timeout, insecure=True,
                workers=args.workers,
            ))
            for item in run_results:
                item.result_dir = str(source)
            results.extend(run_results)
            reporter.write_run(source, run_results, stages, mode="zip",
                               target_base=args.target_base)

    args.out.mkdir(parents=True, exist_ok=True)
    reporter.write_aggregate(args.out, results, mode="zip", target_base=args.target_base)
    payload = json.loads((args.out / "verification-batch.json").read_text(encoding="utf-8"))
    payload["selection"] = {
        "gold_hit_samples": sorted(hits),
        "gold_hit_sample_count": len(hits),
        "samples_without_replayable_poc": missing,
    }
    (args.out / "verification-batch.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "gold_hit_samples": len(hits),
        "poc_total": payload["summary"]["total"],
        "summary": payload["summary"],
        "samples_without_replayable_poc": missing,
        "out": str(args.out),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
