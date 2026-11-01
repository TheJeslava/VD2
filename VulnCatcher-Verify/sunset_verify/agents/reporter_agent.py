"""VerificationReporterAgent: write per-run and aggregate verification reports."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..models import VerificationResult


class VerificationReporterAgent:
    name = "verification_reporter"
    codename = "验证报告"

    def write_run(self, result_dir: Path, results: list[VerificationResult],
                  stage_log: list[dict], *, mode: str, target_base: str) -> Path:
        out = result_dir / "verification"
        out.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema_version": "1.0",
            "generator": "VulnCatcher-Verify",
            "generated_at": generated,
            "mode": mode,
            "target_base": target_base,
            "result_dir": str(result_dir),
            "summary": self._summary(results),
            "results": [item.to_dict() for item in results],
            "stages": stage_log,
            "safety": {
                "executed": True,
                "network_scope": "allowlisted local target only",
                "shell": False,
                "file_write": False,
            },
        }
        (out / "verification.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out / "verification.md").write_text(
            self._markdown(payload), encoding="utf-8"
        )
        with (out / "poc_results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["finding_id", "type", "mode", "verdict", "confidence",
                             "target", "baseline_status", "attack_status", "attack_steps", "reason"])
            for item in results:
                writer.writerow([
                    item.finding_id, item.vulnerability_type, item.mode, item.verdict,
                    item.confidence, item.target_url, item.baseline.status,
                    item.attack.status, len(item.attack_sequence), item.reason,
                ])
        return out

    def write_aggregate(self, out_dir: Path, all_results: list[VerificationResult],
                        *, mode: str, target_base: str) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema_version": "1.0",
            "generator": "VulnCatcher-Verify",
            "generated_at": generated,
            "mode": mode,
            "target_base": target_base,
            "summary": self._summary(all_results),
            "results": [item.to_dict() for item in all_results],
        }
        (out_dir / "verification-batch.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "verification-batch.md").write_text(
            self._markdown(payload), encoding="utf-8"
        )
        return out_dir

    @staticmethod
    def _summary(results: list[VerificationResult]) -> dict:
        verdicts = Counter(item.verdict for item in results)
        return {
            "total": len(results),
            "verified": verdicts.get("verified", 0),
            "rejected": verdicts.get("rejected", 0),
            "inconclusive": verdicts.get("inconclusive", 0),
            "unsupported": verdicts.get("unsupported", 0),
            "error": verdicts.get("error", 0),
            "by_verdict": dict(verdicts),
        }

    def _markdown(self, payload: dict) -> str:
        summary = payload["summary"]
        lines = [
            "# VulnCatcher-Verify 报告",
            "",
            f"- 生成时间：{payload['generated_at']}",
            f"- 模式：`{payload['mode']}`",
            f"- 目标基址：`{payload['target_base'] or '(POC 自带)'}`",
            f"- 结果目录：`{payload.get('result_dir', '')}`",
            "",
            "## 汇总",
            "",
            f"- 总数：{summary['total']}",
            f"- verified：{summary['verified']}",
            f"- rejected：{summary['rejected']}",
            f"- inconclusive：{summary['inconclusive']}",
            f"- unsupported：{summary['unsupported']}",
            f"- error：{summary['error']}",
            "",
            "| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |",
            "|---|---|---|---|---|---|---|",
        ]
        for item in payload["results"]:
            reason = str(item["reason"]).replace("|", "\\|")[:300]
            lines.append(
                f"| `{item['finding_id']}` | `{item['vulnerability_type']}` | **{item['verdict']}** | "
                f"{item['confidence']} | {item['baseline']['status']} | {item['attack']['status']} | "
                f"{reason} |"
            )
        lines += [
            "",
            "## 安全边界",
            "",
            "- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。",
            "- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。",
            "- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。",
        ]
        return "\n".join(lines)
