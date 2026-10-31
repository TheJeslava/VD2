"""二次注入分析（SecondOrderAnalyzer）：二次注入专属 agent。"""

from __future__ import annotations

import time
from pathlib import Path

from ..models import Finding, PocPlan, SecondOrderChain
from ..second_order import analyze_second_order
from ..taxonomy import meta
from .base import AgentContext, AgentResult, BaseAgent


def _lines_around(ctx: AgentContext, file_path: str, line: int, span: int = 2) -> str:
    text = ctx.contents.get(file_path, "")
    lines = text.splitlines()
    if not lines:
        return ""
    start = max(1, line - span)
    end = min(len(lines), line + span)
    return "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1))


def chain_to_finding(chain: SecondOrderChain) -> Finding:
    item = meta(chain.vuln_type)
    stem = Path(chain.file).stem
    return Finding(
        finding_id=chain.chain_id,
        vulnerability_type=chain.vuln_type,
        severity=item.default_severity,
        title=f"{stem} 二次注入（{item.cwe}）",
        description=(
            f"攻击者输入先通过 {chain.endpoint_store or '写入端点'} 写入 {chain.storage}（{chain.storage_key}），"
            f"之后由 {chain.endpoint_trigger or '读取端点'} 读出到变量，并在 {chain.file}:{chain.sink_line} 拼接进危险汇点。"
            "第一阶段的净化无法覆盖第二阶段的上下文，构成跨请求二次注入。"
        ),
        file_path=chain.file,
        line_start=chain.store_line,
        line_end=chain.sink_line,
        code_snippet=_lines_around_simple(chain, ""),
        source=f"{chain.source_kind} `{chain.source_name}` → {chain.storage} `{chain.storage_key}`",
        sink=f"{chain.file}:{chain.sink_line}",
        suggestion="对从存储读出的数据按当前上下文重新参数化/编码；不要假设写入时的转义在读取上下文仍然有效；SQL 使用参数化查询，命令使用参数数组，模板使用变量绑定。",
        confidence=chain.confidence,
        needs_verification=True,
        verdict="candidate",
        exploit_chain=chain.chain,
        poc=chain.poc or PocPlan(),
        impact="攻击者可绕过第一阶段净化，在第二阶段改变 SQL/命令/模板语义，造成数据泄露、越权或 RCE。",
        cve_justification=(
            f"符合 {item.cwe}。具备外部可达写点、跨请求持久化、读取后进入危险汇点三个要素；"
            "第一阶段的输入校验不能保护第二阶段的上下文。"
        ),
        verification_notes=(
            "静态验证：store→read→sink 三要素齐全；"
            + "；".join(chain.notes)
            + "。未执行两阶段 POC，未搭建沙箱。"
        ),
        endpoint=chain.endpoint_trigger or chain.endpoint_store,
        http_method="GET",
        origin="second_order",
        evidence_level="static_closed",
        safety={"executed": False, "requires_authorization": True},
        score=round(chain.confidence * 10 + 40, 2),
    )


def _lines_around_simple(chain: SecondOrderChain, _: str) -> str:
    # 由调用方在 agent 内用上下文覆盖；这里给一个稳定的占位
    return f"{chain.file}:{chain.store_line} → {chain.file}:{chain.sink_line}"


class SecondOrderAnalyzerAgent(BaseAgent):
    name = "second_order_analyzer"
    codename = "二次注入分析"
    prompt_name = "second_order_analyzer.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)
        chains = analyze_second_order(ctx.project, ctx.contents)
        ctx.second_order = chains

        if chains:
            payload_chains = []
            for chain in chains[:20]:
                payload_chains.append({
                    "chain_id": chain.chain_id,
                    "storage": chain.storage,
                    "storage_key": chain.storage_key,
                    "store": {"file": chain.file, "line": chain.store_line,
                              "snippet": _lines_around(ctx, chain.file, chain.store_line)},
                    "read": {"file": chain.file, "line": chain.read_line,
                             "snippet": _lines_around(ctx, chain.file, chain.read_line)},
                    "sink": {"file": chain.file, "line": chain.sink_line,
                             "snippet": _lines_around(ctx, chain.file, chain.sink_line)},
                    "endpoint_store": chain.endpoint_store,
                    "endpoint_trigger": chain.endpoint_trigger,
                })
            llm_data = self._llm_json(
                ctx,
                {"chains": payload_chains, "instruction": "只评价/补充输入中的 chain_id，不要新增文件或行号。"},
                label="second_order",
                max_chars=24000,
            )
            if llm_data and isinstance(llm_data.get("chains"), list):
                result.used_llm = True
                by_id = {chain.chain_id: chain for chain in chains}
                for patch in llm_data["chains"][:30]:
                    if not isinstance(patch, dict):
                        continue
                    chain = by_id.get(str(patch.get("chain_id", "")))
                    if not chain:
                        continue
                    reason = str(patch.get("reason", "")).strip()
                    if reason:
                        chain.notes.append(f"SecondOrderAnalyzer: {reason[:500]}")
                    missing = patch.get("missing_evidence") or []
                    if missing:
                        chain.notes.append("证据缺口: " + "；".join(str(item)[:200] for item in missing[:5]))
                    try:
                        chain.confidence = round(max(0.5, min(0.98, float(patch.get("confidence", chain.confidence)))), 2)
                    except (TypeError, ValueError):
                        pass

        findings = []
        for chain in chains:
            finding = chain_to_finding(chain)
            # 用真实上下文补 code_snippet
            if chain.file in ctx.contents:
                lines = ctx.contents[chain.file].splitlines()
                start = max(1, chain.store_line - 2)
                end = min(len(lines), chain.sink_line + 1)
                finding.code_snippet = "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))[:3000]
            if chain.file in ctx.quarantined:
                finding.verification_notes += "\n该文件被 SafetyGuard 隔离：LLM 未读取正文，结论仅基于确定性证据。"
            findings.append(finding)

        ctx.findings.extend(findings)
        result.data["chains"] = chains
        result.data["findings"] = findings
        ctx.log(self.name, f"二次注入链 {len(chains)} 条（LLM={'是' if result.used_llm else '否'}）")
        result.duration_sec = round(time.time() - started, 2)
        return result
