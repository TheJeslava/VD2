"""Run all 58 fixture paths through URL/AWVS-compatible dynamic mode.

The manifest carries fixture metadata for routing and probe channels only;
the local probe emits findings only when it observes a response differential.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sunset.baofeng import build_manifest


def _run_one(target, project, out_root, manifest, python_exe):
    name = str(target["name"])
    out_dir = out_root / name
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_root / "_logs" / f"{name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [python_exe, "-m", "sunset", "scan", "--mode", "url", "--target", str(target["url"]),
               "--awvs-local", "--awvs-manifest", str(manifest), "--llm", "off", "--min-severity", "low",
               "--quiet", "-o", str(out_dir)]
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(command, cwd=str(project), stdout=log, stderr=subprocess.STDOUT, check=False)
    report = out_dir / "report.json"
    finding_count = 0
    if report.is_file():
        try:
            finding_count = len(json.loads(report.read_text(encoding="utf-8")).get("findings") or [])
        except (OSError, json.JSONDecodeError):
            pass
    return {"sample": name, "dataset_category": target.get("dataset_category"),
            "vulnerability_type": target.get("category"), "target_url": target["url"],
            "exit_code": completed.returncode, "state": "completed" if completed.returncode == 0 and report.is_file() else "failed",
            "findings": finding_count, "output": str(out_dir), "log": str(log_path),
            "duration_sec": round(time.time() - started, 2)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base-url", default="http://127.0.0.1:18081")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    project = args.project.resolve(); out_root = args.out.resolve(); out_root.mkdir(parents=True, exist_ok=True)
    manifest = out_root / "targets.json"
    manifest.write_text(json.dumps(build_manifest(args.base_url), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    targets = build_manifest(args.base_url)["targets"]
    jobs = [(target, project, out_root, manifest, args.python) for target in targets]
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for future in as_completed([pool.submit(_run_one, *job) for job in jobs]):
            item = future.result(); results.append(item); print(json.dumps(item, ensure_ascii=False), flush=True)
    results.sort(key=lambda item: item["sample"])
    finding_rows = [item for item in results if item["findings"]]
    summary = {"format": "baofeng-url-run-v5", "base_url": args.base_url, "input_mode": "url",
               "target_count": len(targets), "completed": sum(item["state"] == "completed" for item in results),
               "failed": sum(item["state"] != "completed" for item in results),
               "findings": sum(item["findings"] for item in results),
               # Backward-compatible field: this is the manifest target coverage,
               # not the number of vulnerability categories detected.
               "category_count": len({item.get("dataset_category") for item in results}),
               "finding_category_count": len({item.get("dataset_category") for item in finding_rows}),
               "finding_samples": [item["sample"] for item in finding_rows],
               "results": results}
    (out_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
