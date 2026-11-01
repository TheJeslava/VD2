"""Run the full Baofeng ZIP + LLM-finding + AWVS-report batch."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def child_path(path: Path) -> str:
    """Translate WSL-mounted paths for a Windows Python executable."""
    value = str(path)
    if value.startswith("/mnt/") and len(value) > 6:
        return value[5].upper() + ":" + value[6:].replace("/", "\\")
    return value


def run_one(item: tuple[Path, Path, Path, Path, str]) -> dict[str, object]:
    zip_path, report_path, out_dir, log_path, python_exe = item
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [
        python_exe,
        "-m",
        "sunset",
        "scan",
        child_path(zip_path),
        "--mode",
        "zip",
        "--llm",
        "on",
        "--llm-finding",
        "on",
        "--min-severity",
        "low",
        "--awvs-report",
        child_path(report_path),
        "-o",
        child_path(out_dir),
    ]
    started = time.time()
    try:
        project_dir = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            command,
            cwd=str(project_dir),
            stdout=log_path.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
            check=False,
        )
        code = completed.returncode
    except Exception as exc:  # noqa: BLE001
        log_path.write_text(f"runner error: {exc}\n", encoding="utf-8")
        code = 1
    return {
        "sample": zip_path.stem,
        "exit_code": code,
        "state": "completed" if code == 0 and (out_dir / "report.json").is_file() else "failed",
        "output": str(out_dir),
        "log": str(log_path),
        "duration_sec": round(time.time() - started, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("../集成数据集"))
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--python", default="python")
    args = parser.parse_args()

    dataset = args.dataset.resolve()
    reports = args.reports.resolve()
    out_root = args.out.resolve()
    log_root = out_root / "_logs"
    out_root.mkdir(parents=True, exist_ok=True)
    log_root.mkdir(parents=True, exist_ok=True)
    inputs = sorted(dataset.glob("*.zip"))
    if not inputs:
        raise SystemExit(f"no ZIP inputs in {dataset}")

    jobs = []
    for zip_path in inputs:
        name = zip_path.stem
        jobs.append((
            zip_path,
            reports / f"{name}.json",
            out_root / name,
            log_root / f"{name}.log",
            args.python,
        ))

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(run_one, item) for item in jobs]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)

    results.sort(key=lambda item: str(item["sample"]))
    (out_root / "summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    failed = sum(item["state"] != "completed" for item in results)
    print(f"completed={len(results) - failed} failed={failed} summary={out_root / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
