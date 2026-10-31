"""POC 生成（PocWriter）：POC 生成 agent（只写不跑）。"""

from __future__ import annotations

import re
import time

from ..poc import build_poc_for_finding
from ..security.guard import inspect_poc_safety
from .base import AgentContext, AgentResult, BaseAgent


class PocWriterAgent(BaseAgent):
    name = "poc_writer"
    codename = "POC 生成"
    prompt_name = "poc_writer.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)

        for finding in ctx.findings:
            if finding.poc and finding.poc.steps:
                continue
            finding.poc = build_poc_for_finding(finding, ctx.project)

        # LLM 只补充叙述字段，不替换确定性请求结构
        if ctx.findings and ctx.llm and ctx.llm.available:
            payload = []
            for finding in ctx.findings[: min(10, len(ctx.findings))]:
                payload.append({
                    "finding_id": finding.finding_id,
                    "vulnerability_type": finding.vulnerability_type,
                    "file_path": finding.file_path,
                    "line_end": finding.line_end,
                    "endpoint": finding.poc.steps[1]["request"] if len(finding.poc.steps) > 1 else "",
                    "current_poc": finding.poc.to_dict(),
                })
            llm_data = self._llm_json(
                ctx,
                {"pocs": payload, "instruction": "只补全 finding_id 对应的描述/步骤说明，不要改目标占位符，不要执行。"},
                label="poc",
                max_chars=30000,
            )
            if llm_data and isinstance(llm_data.get("pocs"), list):
                result.used_llm = True
                by_id = {finding.finding_id: finding for finding in ctx.findings}
                for patch in llm_data["pocs"][:20]:
                    if not isinstance(patch, dict):
                        continue
                    finding = by_id.get(str(patch.get("finding_id", "")))
                    if not finding:
                        continue
                    endpoint_path = ""
                    for step in finding.poc.steps:
                        request = str(step.get("request") or "")
                        match = re.search(r"https?://TARGET:8080(/[^\s'\\]*)", request)
                        if match:
                            endpoint_path = match.group(1)
                            break
                    for field in ("description", "impact", "cve_justification"):
                        value = patch.get(field)
                        if not isinstance(value, str) or not value.strip():
                            continue
                        # 模型改写描述时不得丢掉真实端点，否则可能把 POC 指到错误路径
                        if field in {"description", "cve_justification"} and endpoint_path and endpoint_path not in value:
                            finding.verification_notes = (
                                finding.verification_notes + f"\nPocWriter 建议（未采纳，缺少端点 {endpoint_path}）：" + value.strip()[:800]
                            )[:6000]
                            continue
                        setattr(finding.poc, field, value.strip()[:3000])
                    notes = patch.get("script_notes")
                    if isinstance(notes, str) and notes.strip():
                        finding.verification_notes = (finding.verification_notes + "\nPOC 备注：" + notes.strip()[:1000])[:5000]
                    # 不采纳模型给出的 steps/scripts，保留确定性请求结构

        for finding in ctx.findings:
            finding.poc.safety = inspect_poc_safety(finding.poc.scripts, finding.poc.payload)
            if not finding.poc.safety.get("target_uses_placeholder"):
                finding.poc.safety["warnings"].append("POC 未使用 TARGET 占位符，请人工检查目标地址")
            finding.needs_verification = True
            finding.verdict = "candidate"

        result.data["findings"] = ctx.findings
        ctx.log(self.name, f"生成 {len(ctx.findings)} 份 POC（LLM={'是' if result.used_llm else '否'}）")
        result.duration_sec = round(time.time() - started, 2)
        return result
