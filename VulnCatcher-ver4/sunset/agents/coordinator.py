"""管线协调（Coordinator）：最终汇总与去重。"""

from __future__ import annotations

import time
from collections import Counter

from ..models import Finding
from ..taxonomy import meta
from .base import AgentContext, AgentResult, BaseAgent


class CoordinatorAgent(BaseAgent):
    name = "coordinator"
    codename = "管线协调"
    prompt_name = "coordinator.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)

        deduped: list[Finding] = []
        for finding in ctx.findings:
            duplicate = None
            for existing in deduped:
                if existing.vulnerability_type != finding.vulnerability_type:
                    continue
                if existing.origin == "awvs" or existing.file_path == "" or finding.file_path == "":
                    if existing.endpoint != finding.endpoint:
                        continue
                    duplicate = existing
                    break
                if existing.file_path != finding.file_path:
                    continue
                if abs(existing.line_end - finding.line_end) <= 3:
                    duplicate = existing
                    break
            if duplicate is None:
                deduped.append(finding)
            elif finding.score > duplicate.score:
                deduped[deduped.index(duplicate)] = finding

        deduped.sort(key=lambda item: (-item.score, -item.confidence, item.endpoint, item.file_path))
        deduped = deduped[: ctx.settings.max_findings]
        ctx.findings = deduped

        types = Counter(item.vulnerability_type for item in deduped)
        with_poc = sum(1 for item in deduped if item.poc and item.poc.scripts)
        rule_stats = ctx.project.manifest.get("rule_stats") or {}
        suppressed = rule_stats.get("suppressed") or []
        suppressed_count = int(rule_stats.get("suppressed_count", len(suppressed)) or 0)
        suppressed_by_type = rule_stats.get("suppressed_by_type", {}) or {}
        policy_payload = {
            "min_severity": ctx.settings.min_severity,
            "min_confidence": ctx.settings.min_confidence,
            "suppressed_count": suppressed_count,
            "suppressed_by_type": suppressed_by_type,
            "suppressed_by_reason": rule_stats.get("suppressed_by_reason", {}) or {},
            "suppressed_items": suppressed[:40],
        }
        surface_notes = ctx.project.manifest.get("surface_notes") or {}
        suppressed_text = ""
        if suppressed_count:
            top = "、".join(f"{name}×{count}" for name, count in
                            sorted(suppressed_by_type.items(), key=lambda kv: -kv[1])[:6])
            suppressed_text = (
                f" 另有 {suppressed_count} 条候选因 min_severity={ctx.settings.min_severity} / "
                f"min_confidence={ctx.settings.min_confidence} 未进入 finding（{top}）；"
                "它们是策略抑制而非未检出，明细见 policy.suppressed。"
            )
        if ctx.project.manifest.get("input_mode") == "url":
            fallback = (
                f"URL 模式：AWVS 来源 {ctx.project.manifest.get('awvs_provider', 'unknown')}，"
                f"产出 {len(deduped)} 条动态候选，覆盖 {len(types)} 种漏洞类型；"
                f"{with_poc} 条已生成可重放的 POC。结论仍为 candidate，需VulnCatcher-Verify动态确认。"
            )
            if not deduped:
                fallback = "URL 模式：AWVS 未返回可复现的动态候选；目标可达但未观察到证据。"
        else:
            fallback = (
                f"共发现 {len(deduped)} 条候选 finding，覆盖 {len(types)} 种漏洞类型；"
                f"{with_poc} 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。"
                + suppressed_text
            )
            if not deduped:
                fallback = "未发现满足 CVE 价值阈值的候选；已审计的范围见覆盖统计。" + suppressed_text

        llm_data = self._llm_json(
            ctx,
            {
                "findings": [
                    {
                        "finding_id": item.finding_id,
                        "type": item.vulnerability_type,
                        "severity": item.severity,
                        "title": item.title,
                        "file_path": item.file_path,
                        "line_end": item.line_end,
                        "has_poc": bool(item.poc and item.poc.scripts),
                        "origin": item.origin,
                    }
                    for item in deduped
                ],
                "type_counts": dict(types),
                "with_poc": with_poc,
                "coverage": {
                    "files": len(ctx.project.files),
                    "endpoints": len(ctx.project.endpoints),
                    "languages": ctx.project.languages,
                    "frameworks": ctx.project.frameworks,
                    "quarantined": sorted(ctx.quarantined),
                },
                "policy": policy_payload,
                "surface_notes": surface_notes,
            },
            label="summary",
            max_chars=20000,
        )
        summary = fallback
        if llm_data:
            result.used_llm = True
            candidate_summary = llm_data.get("summary")
            if isinstance(candidate_summary, str) and candidate_summary.strip():
                summary = candidate_summary.strip()[:4000]
            result.data["top_findings"] = llm_data.get("top_findings", [])[:10]
            result.data["coverage_gaps"] = llm_data.get("coverage_gaps", [])[:20]
            result.data["human_review"] = llm_data.get("human_review", [])[:20]
            result.data["policy_note"] = str(llm_data.get("policy_note", ""))[:800]
        ctx.summary = summary
        ctx.project.manifest["llm_policy_note"] = result.data.get("policy_note", "")
        result.data["findings"] = deduped
        result.data["summary"] = summary
        result.data["policy"] = policy_payload
        result.data["stats"] = {
            "findings": len(deduped),
            "with_poc": with_poc,
            "types": dict(types),
            "quarantined": len(ctx.quarantined),
            "suppressed": suppressed_count,
        }
        ctx.log(self.name, f"最终 {len(deduped)} 条 finding，{with_poc} 条含 POC")
        result.duration_sec = round(time.time() - started, 2)
        return result
