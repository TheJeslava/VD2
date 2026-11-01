"""候选筛选（CandidateScreener）：筛选 LLM 或外部扫描器提供的候选。"""

from __future__ import annotations

import time
import re

from .base import AgentContext, AgentResult, BaseAgent

HIGH_RISK = {"command_injection", "sql_injection", "deserialization", "ssti", "path_traversal", "rce", "code_injection"}
SEMANTIC_RULES = {
    "api_info_disclosure", "captcha_bypass", "csp", "weak_id",
    "client_side_validation", "brute_force", "weak_crypto", "csrf",
    "open_redirect", "xss",
}
EXPLICIT_DISPROOF = re.compile(
    r"(?:没有|无|未见|未发现|不存在|不构成|不是|并非|仅是|只是).{0,90}"
    r"(?:危险汇点|汇点|sink|source.?sink|文件读取|文件包含|include|require|"
    r"用户可控|数据流|sql|数据库|重定向|可预测|验证码|csrf|跨站请求|"
    r"权限校验|授权检查|客户端校验|response|响应头)", re.I | re.S
)


class CandidateScreenerAgent(BaseAgent):
    name = "candidate_screener"
    codename = "候选筛选"
    prompt_name = "candidate_screener.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)
        candidates = list(ctx.candidates)
        assessments: dict[str, dict] = {}

        llm_data = None
        if candidates:
            dossiers = [self._scrub_dossier(ctx, self._candidate_dossier(item)) for item in candidates[:24]]
            rule_stats = ctx.project.manifest.get("rule_stats") or {}
            llm_data = self._llm_json(
                ctx,
                {
                    "candidates": dossiers,
                    "policy": {
                        "min_severity": ctx.settings.min_severity,
                        "min_confidence": ctx.settings.min_confidence,
                        "suppressed_count": rule_stats.get("suppressed_count", 0),
                        "suppressed_by_type": rule_stats.get("suppressed_by_type", {}),
                    },
                    "instruction": "只评价输入中的 candidate_id；不要新增候选，也不要假设未提供的源码或证据。",
                },
                label="assessment",
                max_chars=28000,
            )
        if llm_data and isinstance(llm_data.get("assessments"), list):
            result.used_llm = True
            for item in llm_data["assessments"][:40]:
                if not isinstance(item, dict):
                    continue
                cid = str(item.get("candidate_id", ""))
                assessments[cid] = {
                    "keep": bool(item.get("keep", True)),
                    "reason": str(item.get("reason", ""))[:500],
                    "confidence_adjustment": item.get("confidence_adjustment", 0) or 0,
                    "missing_evidence": item.get("missing_evidence", [])[:10],
                }

        kept = []
        for candidate in candidates:
            decision = assessments.get(candidate.candidate_id)
            keep = True
            if decision and not decision["keep"]:
                # 高危类型不允许仅凭 LLM 一句话丢弃；只有低置信度且非高危才允许
                if (candidate.vuln_type in HIGH_RISK or candidate.confidence >= 0.8
                        or (candidate.rule_id.startswith("php-") and candidate.vuln_type in SEMANTIC_RULES)):
                    keep = True
                    candidate.notes.append("LLM 建议 drop，但因高危/高置信度保留")
                else:
                    keep = False
            if decision:
                try:
                    adjustment = float(decision.get("confidence_adjustment") or 0)
                except (TypeError, ValueError):
                    adjustment = 0.0
                candidate.confidence = round(max(0.4, min(0.98, candidate.confidence + adjustment)), 2)
                if decision.get("reason"):
                    candidate.notes.append(f"CandidateScreener: {decision['reason'][:300]}")
            if keep:
                kept.append(candidate)

        # 按类型价值/严重度/置信度排序
        kept.sort(key=lambda item: (0 if item.vuln_type in HIGH_RISK else 1, -item.confidence, item.file, item.line_end))
        ctx.candidates = kept
        result.data["candidates"] = kept
        result.data["assessments"] = assessments
        result.data["dropped"] = len(candidates) - len(kept)
        result.data["notes"] = (llm_data or {}).get("notes", "")
        ctx.log(self.name, f"候选 {len(candidates)} → 保留 {len(kept)}（LLM={'是' if result.used_llm else '否'}）")
        result.duration_sec = round(time.time() - started, 2)
        return result
