"""Summarize final integrated dataset gold hits and VulnCatcher-Verify results."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


TYPE_TO_CATEGORY = {
    "api_info_disclosure": "api", "information_disclosure": "api",
    "auth_bypass": "authbypass", "idor": "bac", "brute_force": "brute",
    "captcha_bypass": "captcha", "weak_crypto": "cryptography", "csp": "csp",
    "csrf": "csrf", "command_injection": "exec", "path_traversal": "fi",
    "lfi": "fi", "client_side_validation": "javascript",
    "open_redirect": "open_redirect", "sql_injection": "sqli",
    "blind_sql_injection": "sqli_blind", "file_upload": "upload",
    "weak_id": "weak_id", "predictable_id": "weak_id", "insecure_session": "weak_id",
    "xss": "xss_r", "second_order_injection": "sqli_labs_less24",
}


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: dataset_summarize_verification.py RUN_ROOT EVALUATION VERIFICATION", file=sys.stderr)
        return 2
    run_root, evaluation_path, verification_path = map(Path, sys.argv[1:])
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    results = verification.get("results", [])
    samples = []
    for sample, info in evaluation.get("samples", {}).items():
        if not info.get("hit"):
            continue
        items = [item for item in results if Path(item.get("result_dir", "")).name == sample]
        verified = [item for item in items if item.get("verdict") == "verified"]
        matching = [item for item in verified if TYPE_TO_CATEGORY.get(item.get("vulnerability_type")) == info.get("category")]
        nonmatching = [item for item in verified if item not in matching]
        counts = Counter(item.get("verdict", "error") for item in items)
        samples.append({
            "sample": sample,
            "gold_category": info.get("category"),
            "gold_level": info.get("level"),
            "poc_total": len(items),
            "verified": counts.get("verified", 0),
            "rejected": counts.get("rejected", 0),
            "inconclusive": counts.get("inconclusive", 0),
            "unsupported": counts.get("unsupported", 0),
            "error": counts.get("error", 0),
            "matching_verified": len(matching),
            "matching_verified_ids": [item.get("finding_id") for item in matching],
            "nonmatching_verified_ids": [item.get("finding_id") for item in nonmatching],
            "no_poc": not items,
        })
    verdicts = Counter(item.get("verdict", "error") for item in results)
    payload = {
        "run_root": str(run_root),
        "evaluation": str(evaluation_path),
        "verification": str(verification_path),
        "hit_samples": len(samples),
        "hit_samples_with_poc": sum(not row["no_poc"] for row in samples),
        "hit_samples_without_poc": sum(row["no_poc"] for row in samples),
        "poc_total": len(results),
        "verdicts": dict(verdicts),
        "verified_poc_total": verdicts.get("verified", 0),
        "matching_verified_poc_total": sum(row["matching_verified"] for row in samples),
        "samples_with_matching_verified": [row["sample"] for row in samples if row["matching_verified"]],
        "samples_with_nonmatching_verified": [row["sample"] for row in samples if row["nonmatching_verified_ids"]],
        "samples": samples,
        "limitations": [
            "URL target was the local 127.0.0.1:18081 AWVS-compatible DVWA adapter.",
            "The adapter maps sample paths to DVWA category routes; it is not a deployment of every original PHP sample.",
            "058 uses a DVWA SQLi fallback and is excluded because its gold hit is false/partial.",
            "verified means response evidence matched the verifier marker; matching_verified additionally requires the gold category.",
        ],
    }
    out_json = run_root / "verification_vs_gold.json"
    out_md = run_root / "verification_vs_gold.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# 集成数据集最终联合结果与VulnCatcher-Verify",
        "",
        f"- 金标判断正确样本：{payload['hit_samples']}/58（仅这些样本执行 POC 验证）",
        f"- 验证 POC：{payload['poc_total']}；verified={verdicts.get('verified', 0)}，rejected={verdicts.get('rejected', 0)}，inconclusive={verdicts.get('inconclusive', 0)}，unsupported={verdicts.get('unsupported', 0)}，error={verdicts.get('error', 0)}",
        f"- 与金标类别一致的 verified POC：{payload['matching_verified_poc_total']}，样本：{', '.join(payload['samples_with_matching_verified']) or '无'}",
        "",
        "| 样本 | 金标类别 | POC | verified | rejected | inconclusive | 类别一致 verified |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in samples:
        lines.append(f"| {row['sample']} | {row['gold_category']} | {row['poc_total']} | {row['verified']} | {row['rejected']} | {row['inconclusive']} | {row['matching_verified']} |")
    lines += ["", "## 限制", ""] + [f"- {item}" for item in payload["limitations"]]
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({key: payload[key] for key in ("hit_samples", "poc_total", "verdicts", "matching_verified_poc_total", "samples_with_matching_verified")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
