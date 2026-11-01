"""Run the full integrated dataset PHP path set through VulnCatcher URL mode.

The local adapter exposes each dataset PHP path at BASE_URL/<file>.  The
manifest keeps one target per path so URL mode never receives a ZIP path.
Only categories with a black-box signal are probed; the remaining paths are
still executed and reported as covered with zero dynamic candidates.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin


OBSERVABLE: dict[str, dict[str, object]] = {}
for n in ("025", "026", "027"):
    OBSERVABLE[n] = {"category": "cmdi", "method": "POST", "channel": "form", "param_name": "ip", "param_value": "127.0.0.1"}
for n in ("028", "029", "030"):
    OBSERVABLE[n] = {"category": "pathtraver", "method": "GET", "channel": "form", "param_name": "page", "param_value": "include.php"}
for n in ("037", "038", "039", "040", "041", "042"):
    OBSERVABLE[n] = {"category": "sqli", "method": "GET", "channel": "form", "param_name": "id", "param_value": "1"}
for n in ("049", "050", "051", "052", "053", "054"):
    OBSERVABLE[n] = {"category": "xss", "method": "GET", "channel": "form", "param_name": "name", "param_value": "SafeText"}
for n in ("055", "056", "057"):
    OBSERVABLE[n] = {"category": "xss", "method": "POST", "channel": "form", "param_name": "txtName", "param_value": "SafeText"}


def target_for(base_url: str, php_path: Path) -> dict[str, object]:
    name = php_path.name
    sample = name[:3] if name[:3].isdigit() else name
    target: dict[str, object] = {
        "name": name,
        "url": urljoin(base_url.rstrip("/") + "/", name),
        "method": "GET",
        "channel": "form",
        "param_name": "probe",
        "param_value": "test",
        "source_file": name,
    }
    target.update(OBSERVABLE.get(sample, {}))
    return target


def run_one(job: tuple[dict[str, object], Path, Path, str, str]) -> dict[str, object]:
    target, project, out_root, manifest, python_exe = job
    name = Path(str(target["name"])).stem
    out_dir = out_root / name
    log_path = out_root / "_logs" / f"{name}.log"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        python_exe,
        "-m", "sunset", "scan", "--mode", "url",
        "--target", str(target["url"]),
        "--awvs-local", "--awvs-manifest", manifest,
        "--llm", "off", "--min-severity", "low",
        "--quiet", "-o", str(out_dir),
    ]
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(command, cwd=str(project), stdout=log, stderr=subprocess.STDOUT, check=False)
    report = out_dir / "report.json"
    findings = 0
    if report.is_file():
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
            findings = len(payload.get("findings") or [])
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "sample": name,
        "path": str(target["name"]),
        "target_url": str(target["url"]),
        "category": str(target.get("category") or "other"),
        "exit_code": completed.returncode,
        "state": "completed" if completed.returncode == 0 and report.is_file() else "failed",
        "findings": findings,
        "output": str(out_dir),
        "log": str(log_path),
        "duration_sec": round(time.time() - started, 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("../集成数据集"))
    parser.add_argument("--project", type=Path, default=Path("."))
    parser.add_argument("--base-url", default="http://127.0.0.1:18081")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    dataset = args.dataset.resolve()
    project = args.project.resolve()
    out_root = args.out.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    paths = sorted(dataset.glob("*.php"), key=lambda p: p.name)
    if not paths:
        raise SystemExit(f"no PHP paths in {dataset}")
    targets = [target_for(args.base_url, path) for path in paths]
    manifest_path = out_root / "targets.json"
    manifest_path.write_text(json.dumps({
        "generated_by": "VulnCatcher-ver3/tools/dataset_run_url.py",
        "base_url": args.base_url,
        "dataset": str(dataset),
        "count": len(targets),
        "targets": targets,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    jobs = [(target, project, out_root, str(manifest_path), args.python) for target in targets]
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(run_one, job) for job in jobs]
        for future in as_completed(futures):
            item = future.result()
            results.append(item)
            print(json.dumps(item, ensure_ascii=False), flush=True)
    results.sort(key=lambda item: str(item["path"]))
    completed = sum(item["state"] == "completed" for item in results)
    failed = len(results) - completed
    findings = sum(int(item["findings"]) for item in results)
    summary = {
        "dataset": str(dataset),
        "base_url": args.base_url,
        "input_mode": "url",
        "target_count": len(targets),
        "completed": completed,
        "failed": failed,
        "findings": findings,
        "results": results,
    }
    (out_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"completed={completed} failed={failed} targets={len(targets)} findings={findings} summary={out_root / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
