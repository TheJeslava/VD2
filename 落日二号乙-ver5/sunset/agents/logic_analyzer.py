"""隐性逻辑漏洞专属判定；静态结论和实验验证分开记录。"""

from __future__ import annotations

import ast
import hashlib
import json
import time
from collections import Counter
from pathlib import Path, PurePosixPath

from ..logic_analysis import analyze_logic
from ..models import ChainStep, Finding, PocPlan
from ..security.guard import sanitize_model_text
from ..taxonomy import meta
from .base import AgentContext, AgentResult, BaseAgent

CATEGORIES = {"workflow_bypass", "object_authorization", "business_constraint"}


def load_logic_policies(path: str) -> tuple[list[dict], dict]:
    """只接受操作者显式选择的 JSON；不在待审 ZIP/README 中自动发现规则。"""
    if not path:
        return [], {"source": "builtin_php_workflow", "rule_count": 0}
    raw = Path(path).read_bytes()
    if len(raw) > 256_000:
        raise ValueError("logic policy 文件超过 256 KB")
    payload = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("logic policy 需要 version=1 和 rules 数组")
    rules = payload.get("rules")
    if not isinstance(rules, list) or len(rules) > 200:
        raise ValueError("logic policy rules 必须是最多 200 条的数组")
    ids = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("每条 logic policy 必须是对象")
        for key in ("id", "category", "file", "function", "operation", "required_condition", "description"):
            if not isinstance(rule.get(key), str) or not rule[key].strip() or len(rule[key]) > 2000:
                raise ValueError(f"logic policy 的 {key} 必须是非空短字符串")
        if rule["category"] not in CATEGORIES:
            raise ValueError("logic policy category 不受支持")
        if rule["id"] in ids:
            raise ValueError(f"重复的 logic policy id: {rule['id']}")
        ids.add(rule["id"])
        rel = rule["file"].replace("\\", "/")
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts or ":" in rel:
            raise ValueError("logic policy file 必须是 ZIP 内相对路径")
        rule["file"] = rel
        if not isinstance(rule.get("context_complete", False), bool):
            raise ValueError("context_complete 必须是布尔值；缺省为 false")
        trusted = rule.get("trusted_inputs", [])
        if not isinstance(trusted, list) or not all(isinstance(x, str) and x.isidentifier() for x in trusted):
            raise ValueError("trusted_inputs 必须是标识符数组")
        # 仅解析语法，绝不 eval/exec 表达式。
        ast.parse(rule["required_condition"], mode="eval")
        bindings = rule.get("operation_bindings", {})
        if not isinstance(bindings, dict) or len(bindings) > 20:
            raise ValueError("operation_bindings 必须是最多 20 项的参数绑定对象")
        for argument, expression in bindings.items():
            if (not isinstance(argument, str) or not (argument.isdecimal() or argument.isidentifier())
                    or not isinstance(expression, str) or not expression.strip() or len(expression) > 2000):
                raise ValueError("operation_bindings 需用参数位置/关键字对应非空 Python 表达式")
            ast.parse(expression, mode="eval")
    return rules, {"source": "operator_selected_file", "sha256": hashlib.sha256(raw).hexdigest(),
                   "rule_count": len(rules)}


def assessment_to_finding(item: dict, contents: dict[str, str]) -> Finding:
    """只转换 candidate；guarded/needs_context 保留在独立判定报告。"""
    kind = meta(item["vulnerability_type"])
    rel = item["file"]
    start, end = item["line_start"], item["line_end"]
    lines = contents.get(rel, "").splitlines()
    snippet = "\n".join(f"{i}: {lines[i - 1]}" for i in range(max(1, start), min(len(lines), end) + 1))[:4000]
    verification = item.get("verification_steps", []) or [
        "准备合法流程、违反业务规则的请求和修复版对照。",
        "比较实际账户/对象/金额状态；不能仅凭 HTTP 200 判定成功。",
    ]
    steps = [{"step": n, "action": step, "request": "",
              "expected_response": "同时核对响应与服务端业务状态"}
             for n, step in enumerate(verification, 1)]
    readme = (f"# 隐性逻辑验证计划\n\n源码：{rel}:{start}-{end}\n\n"
              f"业务规则：{item['expected_rule']}\n\n静态判断：{item['reason']}\n\n"
              + "\n".join(f"{n}. {s}" for n, s in enumerate(verification, 1))
              + "\n\n此文件是人工验证计划，未执行。需补充真实路由、测试账号、状态读取方法。"
                "只有本地逻辑实验运行器会执行其自建靶场；本报告不继承该实验的动态结论。\n")
    plan = PocPlan(description=f"{rel}:{end} 的业务状态对照验证计划（未执行）",
                   preconditions=["操作者确认业务规则适用", "已授权的测试环境与独立测试账号",
                                  "可读取操作前后的真实业务状态"],
                   steps=steps, scripts={"poc_readme.md": readme},
                   safety={"executed": False, "requires_authorization": True})
    chain = [ChainStep(step=n, location=f"{rel}:{e['line']}",
                       description=e.get("role", "源码证据"), data_state=e.get("code", ""))
             for n, e in enumerate(item.get("evidence", []), 1)]
    return Finding(
        finding_id=item["assessment_id"], vulnerability_type=kind.name,
        severity=kind.default_severity, title=f"隐性逻辑：{item['expected_rule']}",
        description=item["reason"], file_path=rel, line_start=start, line_end=end,
        code_snippet=snippet, source="业务入口及操作者指定的信任边界",
        sink=f"{rel}:{end}", suggestion=f"在服务端敏感操作之前强制执行：{item['expected_rule']}；确保校验与操作使用同一对象、身份和数值。",
        confidence=item["confidence"], needs_verification=True, verdict="candidate",
        exploit_chain=chain, poc=plan,
        impact="可能违反所列业务规则；实际影响以受控环境的状态对照实验为准。",
        cve_justification=f"关联 {kind.cwe}；此结果是指定规则下的静态候选，不表示已获 CVE 或已完成动态验证。",
        verification_notes="未执行目标 POC。规则来源：" + item.get("policy_source", "")
                           + "；" + "；".join(item.get("missing_evidence", [])),
        origin="logic_specialist", evidence_level="static_candidate",
        safety={"executed": False, "requires_authorization": True},
        score=round(item["confidence"] * 10 + {"critical": 40, "high": 30, "medium": 20}.get(kind.default_severity, 10), 2),
    )


class LogicAnalyzerAgent(BaseAgent):
    name = "logic_analyzer"
    codename = "隐性逻辑判定"
    prompt_name = "logic_analyzer.md"

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)
        assessments = analyze_logic(ctx.project, ctx.contents, policies=ctx.logic_policies)
        ctx.logic_assessments = assessments
        # 隔离文件的一切派生源码证据都不送给模型。LLM 只能附加复核意见，不能提升结论。
        dossiers = [{"assessment_id": a["assessment_id"], "file_path": a["file"],
                     "status": a["status"], "expected_rule": a["expected_rule"],
                     "reason": a["reason"], "evidence": a["evidence"],
                     "missing_evidence": a["missing_evidence"]}
                    for a in assessments if a["file"] not in ctx.quarantined][:20]
        if dossiers and ctx.llm and ctx.llm.available:
            data = self._llm_json(ctx, {"assessments": dossiers}, label="business_logic", max_chars=24000)
            patches = data.get("reviews") if isinstance(data, dict) else None
            if isinstance(patches, list):
                result.used_llm = True
                by_id = {a["assessment_id"]: a for a in assessments if a["file"] not in ctx.quarantined}
                for patch in patches[:20]:
                    if not isinstance(patch, dict):
                        continue
                    patch_id = patch.get("assessment_id")
                    assessment = by_id.get(patch_id) if isinstance(patch_id, str) else None
                    if assessment is not None and isinstance(patch.get("review_note"), str):
                        assessment["llm_review_note"] = sanitize_model_text(patch["review_note"], 1000)

        additions = []
        candidate_by_id = {c.candidate_id: c for c in ctx.candidates}
        php_workflows_per_file = Counter(a["file"] for a in assessments
                                        if a.get("policy_source") == "inferred_local_workflow")
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for assessment in assessments:
            if assessment["status"] != "candidate":
                continue
            finding = assessment_to_finding(assessment, ctx.contents)
            if (finding.confidence < ctx.settings.min_confidence or
                    severity_order.get(finding.severity, 0) < severity_order.get(ctx.settings.min_severity, 0)):
                assessment["finding_suppressed"] = "min_confidence/min_severity"
                continue
            # 仅合并同类型、同文件、同操作附近的候选；不因某个保护条件存在就删除其他发现。
            matches = [f for f in ctx.findings if f.vulnerability_type == finding.vulnerability_type
                       and f.file_path == finding.file_path and abs(f.line_end - finding.line_end) <= 3]
            if (assessment.get("policy_source") == "inferred_local_workflow"
                    and php_workflows_per_file[finding.file_path] == 1):
                for existing in ctx.findings:
                    source = candidate_by_id.get(existing.finding_id)
                    if (existing not in matches and existing.origin == "rule"
                            and existing.vulnerability_type == "captcha_bypass"
                            and existing.file_path == finding.file_path and source is not None
                            and source.rule_id == "php-captcha-state"):
                        matches.append(existing)
            for existing in matches:
                finding.external_evidence.extend(existing.external_evidence)
                finding.external_evidence.append({"source": existing.origin, "finding_id": existing.finding_id,
                                                   "note": "同一操作的已有候选，合并至专属业务判定"})
                ctx.findings.remove(existing)
            additions.append(finding)
        ctx.findings.extend(additions)
        counts = dict(Counter(a["status"] for a in assessments))
        ctx.project.manifest["logic_analysis"] = {"counts": counts, "executed": False,
                                                  "policy": ctx.logic_policy_provenance}
        result.data = {"assessments": assessments, "findings": additions}
        ctx.log(self.name, f"业务规则判定 {len(assessments)} 条：{counts}；动态验证未执行")
        result.duration_sec = round(time.time() - started, 2)
        return result
