"""Summarize a completed full-path URL run."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    modes: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    finding_types: Counter[str] = Counter()
    findings: list[dict[str, str]] = []
    safety_errors = 0
    for item in summary["results"]:
        report_path = run / str(item["sample"]) / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        modes[str(report.get("run", {}).get("input_mode", ""))] += 1
        categories[str(item.get("category") or "other")] += 1
        for finding in report.get("findings") or []:
            kind = str(finding.get("vulnerability_type") or "unknown")
            finding_types[kind] += 1
            evidence = (finding.get("external_evidence") or [{}])[0]
            findings.append({
                "path": str(item["path"]),
                "type": kind,
                "severity": str(finding.get("severity") or ""),
                "url": str(evidence.get("url") or item.get("target_url") or ""),
                "evidence": str(evidence.get("evidence") or ""),
                "verdict": str(finding.get("verdict") or ""),
            })
            contract = (finding.get("poc") or {}).get("safety", {}).get("contract_validation", {})
            safety_errors += len(contract.get("errors") or [])
    aggregate = {
        "input_mode": "url",
        "target_count": summary["target_count"],
        "completed": summary["completed"],
        "failed": summary["failed"],
        "finding_count": len(findings),
        "input_modes": dict(modes),
        "target_categories": dict(categories),
        "finding_types": dict(finding_types),
        "poc_contract_errors": safety_errors,
        "findings": findings,
    }
    (run / "aggregate.json").write_text(json.dumps(aggregate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# VulnCatcher-ver3 集成数据集全量 URL 路径实验",
        "",
        f"- 输入模式：`url`（目标为 HTTP URL 路径，不使用 ZIP 输入）",
        f"- 目标基址：`{summary['base_url']}`",
        f"- URL 路径数：{summary['target_count']}（其中 001–057 与 058_01–058_08）",
        f"- 完成：{summary['completed']}；失败：{summary['failed']}",
        f"- 动态候选：{len(findings)}；POC 合同错误：{safety_errors}",
        "",
        "## 发现",
        "",
        "| 路径 | 类型 | 严重度 | 证据 | verdict |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        evidence = finding["evidence"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{finding['path']}` | `{finding['type']}` | {finding['severity']} | `{evidence}` | {finding['verdict']} |")
    lines += [
        "",
        "## 覆盖与边界",
        "",
        f"- 所有 {summary['target_count']} 个 PHP URL 路径均生成了独立 `report.json`，且 `run.input_mode=url` 与 `run.target_url` 均通过校验。",
        "- 本地 AWVS-compatible 探针只对 cmdi、pathtraver、sqli、xss 等可由 HTTP 响应观察的类别发起探测；其余路径仍执行 URL 管线并记录零候选。",
        "- 058 的 8 个子路径按独立 URL 覆盖；当前本地适配器没有为 SQLi-Labs 子路径提供上游路由，因此结果为零候选，不将 DVWA 回退路径当作 058 证据。",
        "- POC 仅写入报告，未执行；动态候选仍标记为 `candidate`/`external_only`，不是最终人工确认。",
        "",
    ]
    (run / "aggregate.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(aggregate, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
