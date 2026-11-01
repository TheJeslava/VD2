"""报告落盘：JSON / Markdown / CSV / POC 文本工件。"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .config import Settings
from .models import Finding, RunResult
from .structured_report import build_structured_report, write_structured_report
from .taxonomy import VULN_TYPES, auto_cve_types, meta


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:80] or "finding"


def _md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _write_poc_files(result: RunResult, out_dir: Path) -> dict[str, str]:
    """写入 POC 文本工件，返回 finding_id → 相对目录。"""
    mapping: dict[str, str] = {}
    for finding in result.findings:
        if not finding.poc or not finding.poc.scripts:
            continue
        folder = out_dir / "poc" / _safe_id(finding.finding_id)
        folder.mkdir(parents=True, exist_ok=True)
        for name, content in finding.poc.scripts.items():
            safe_name = _safe_id(name)
            if not safe_name.endswith((".sh", ".http", ".md", ".txt", ".html")):
                safe_name += ".txt"
            (folder / safe_name).write_text(content, encoding="utf-8")
        readme = [
            f"# POC — {finding.title}",
            "",
            f"- finding_id: `{finding.finding_id}`",
            f"- type: `{finding.vulnerability_type}` / {meta(finding.vulnerability_type).cwe}",
            f"- severity: `{finding.severity}`",
            f"- file: `{finding.file_path}:{finding.line_end}`",
            "",
            "## 步骤",
            "",
        ]
        for step in finding.poc.steps:
            readme.append(f"{step.get('step')}. **{step.get('action', '')}**  ")
            if step.get("request"):
                readme.append("```http")
                readme.append(str(step["request"]))
                readme.append("```")
            if step.get("expected_response"):
                readme.append(f"预期：{step['expected_response']}")
            readme.append("")
        readme.append("## 安全说明")
        readme.append("")
        readme.append("POC 仅为文本工件；VulnCatcher不会执行它，也不会联网或搭建沙箱。仅限授权测试。")
        (folder / "README.md").write_text("\n".join(readme), encoding="utf-8")
        mapping[finding.finding_id] = str(folder.relative_to(out_dir)).replace("\\", "/")
    return mapping


def _finding_section(finding: Finding, index: int, poc_dir: str | None) -> list[str]:
    lines = [
        f"### F-{index}: {finding.title}",
        "",
        f"- **类型**：`{finding.vulnerability_type}` / {meta(finding.vulnerability_type).cwe}",
        f"- **严重度**：`{finding.severity}`",
        f"- **置信度**：`{finding.confidence}`",
        f"- **结论**：`{finding.verdict}` / 证据等级 `{finding.evidence_level}`",
        f"- **位置**：`{finding.file_path}:{finding.line_start}-{finding.line_end}`" if finding.file_path else f"- **位置**：外部扫描端点 `{finding.endpoint or 'unknown'}`",
        f"- **来源**：`{finding.origin}`",
        "",
        "**描述**",
        "",
        finding.description,
        "",
        "**source / sink**",
        "",
        f"- source：{finding.source}",
        f"- sink：{finding.sink}",
        "",
        "**利用链**",
        "",
        "| # | 位置 | 描述 | 数据状态 | 绕过原因 |",
        "|---|---|---|---|---|",
    ]
    for step in finding.exploit_chain:
        lines.append(
            f"| {step.step} | `{_md(step.location)}` | {_md(step.description)} | "
            f"{_md(step.data_state)} | {_md(step.bypass_reason)} |"
        )
    lines += ["", "**POC**", ""]
    if finding.poc and finding.poc.steps:
        lines.append(finding.poc.description)
        lines.append("")
        for step in finding.poc.steps:
            lines.append(f"{step.get('step')}. **{step.get('action', '')}**")
            if step.get("request"):
                lines.append("")
                lines.append("```http")
                lines.append(str(step["request"]))
                lines.append("```")
            if step.get("expected_response"):
                lines.append(f"预期：{step['expected_response']}")
            lines.append("")
        if finding.poc.payload:
            lines.append(f"- payload：`{finding.poc.payload}`")
        if poc_dir:
            lines.append(f"- POC 目录：`{poc_dir}`")
        warnings = (finding.poc.safety or {}).get("warnings") or []
        if warnings:
            lines.append(f"- 风险提示：{', '.join(warnings)}")
        lines.append(f"- 执行状态：未执行（`executed={finding.poc.safety.get('executed', False)}`）")
    else:
        lines.append("未生成 POC（证据不足或类型为静态配置）。")
    lines += [
        "",
        "**影响**",
        "",
        finding.impact,
        "",
        "**CVE / CWE 论证**",
        "",
        finding.cve_justification,
        "",
        "**修复建议**",
        "",
        finding.suggestion,
        "",
        "**验证说明**",
        "",
        finding.verification_notes,
        "",
    ]
    if finding.external_evidence:
        lines += ["**外部佐证**", ""]
        for evidence in finding.external_evidence:
            lines.append(f"- {evidence.get('source')}: {evidence.get('vt_name')} @ {evidence.get('url')}")
        lines.append("")
    return lines


def write_reports(result: RunResult, out_dir: Path, *, settings: Settings,
                  log: Callable[[str], None] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    poc_mapping = _write_poc_files(result, out_dir)
    generated_at = datetime.now(timezone.utc).isoformat()
    input_mode = result.project.manifest.get("input_mode", result.project.input_mode or "zip")

    # 规范化结构化报告（面向交付/平台消费）
    structured = build_structured_report(result, settings, poc_mapping)
    structured_paths = write_structured_report(structured, out_dir)

    # 内部全量结果（调试/复现）
    payload = result.to_dict()
    payload["generated_at"] = generated_at
    payload["version"] = __version__
    payload["settings"] = settings.public()
    _write_json(out_dir / "result.json", payload)

    # 安全报告
    _write_json(out_dir / "security" / "injection_report.json", {
        "generated_at": generated_at,
        "signals": [signal.to_dict() for signal in result.injection_signals],
        "summary": result.project.manifest.get("security", {}),
        "policy": {
            "untrusted_envelope": "nonce 包裹 + trust=untrusted",
            "file_allowlist": "LLM 输出的 file_path 必须在仓库清单中",
            "line_validation": "行号必须落在文件行数内",
            "tool_call_stripping": "<|...|> / tool_call / function_call 会被剥离",
            "passive_poc": "POC 只写不跑；禁止自动执行/反弹 shell/破坏性命令",
            "quarantine": "命中 critical 注入迹象的文件正文不进入 LLM 上下文",
        },
    })

    # 二次注入
    _write_json(out_dir / "second_order.json", {
        "generated_at": generated_at,
        "chains": [chain.to_dict() for chain in result.second_order],
        "note": "静态 store→read→sink 闭环；两阶段 POC 只写不跑。",
    })

    # AWVS
    _write_json(out_dir / "logic_analysis.json", {
        "generated_at": generated_at,
        "assessments": result.logic_assessments,
        "policy": result.project.manifest.get("logic_analysis", {}).get("policy", {}),
        "note": "candidate=静态候选；guarded=指定局部规则有保护；needs_context=证据不足。均不是动态验证结果。",
    })

    _write_json(out_dir / "awvs" / "correlations.json", {
        "generated_at": generated_at,
        "imported": result.awvs_imported,
        "correlations": result.awvs_correlations,
        "note": (
            "URL 模式：AWVS 是候选提出组件；本管线消费其结果并生成 POC，动态确认由落日验证完成。"
            if input_mode == "url" else
            "AWVS 外部结果只作为佐证；本管线未执行扫描。"
        ),
    })

    # 覆盖度
    counts = Counter(item.vulnerability_type for item in result.findings)
    coverage = []
    for name, item in VULN_TYPES.items():
        coverage.append({
            "type": name,
            "label": item.label_zh,
            "cwe": item.cwe,
            "auto_cve": name in auto_cve_types(),
            "count": counts.get(name, 0),
        })
    _write_json(out_dir / "coverage.json", {"counts": dict(counts), "types": coverage})

    # CSV
    with (out_dir / "findings.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding_id", "type", "severity", "title", "file", "line_start", "line_end",
                         "confidence", "verdict", "evidence_level", "origin", "has_poc", "poc_dir"])
        for finding in result.findings:
            writer.writerow([
                finding.finding_id, finding.vulnerability_type, finding.severity, finding.title,
                finding.file_path, finding.line_start, finding.line_end, finding.confidence,
                finding.verdict, finding.evidence_level, finding.origin,
                bool(finding.poc and finding.poc.scripts), poc_mapping.get(finding.finding_id, ""),
            ])

    # Markdown
    rule_stats = result.project.manifest.get("rule_stats") or {}
    suppressed_items = rule_stats.get("suppressed") or []
    suppressed_count = int(rule_stats.get("suppressed_count", len(suppressed_items)) or 0)
    suppressed_by_type = rule_stats.get("suppressed_by_type", {}) or {}
    input_line = (
        f"- 输入 URL：`{result.project.target_url or result.project.zip_path}`"
        if input_mode == "url" else f"- 输入：`{result.project.zip_path}`"
    )
    lines = [
        f"# VulnCatcher漏洞挖掘报告 — {result.run_id}",
        "",
        f"- 生成时间：{generated_at}",
        input_line,
        f"- 输入模式：`{input_mode}`",
        f"- SHA256：`{result.project.zip_sha256}`",
        f"- 文件：{len(result.project.files)}（文本 {sum(1 for f in result.project.files if f.is_text)}）",
        f"- 语言：{', '.join(f'{k}({v})' for k, v in sorted(result.project.languages.items()))}",
        f"- 框架：{', '.join(result.project.frameworks) or '未识别'}",
        f"- 端点：{len(result.project.endpoints)}",
        f"- 版本：{__version__}",
        f"- 严重度档位：`{settings.min_severity}`（min_confidence={settings.min_confidence}）",
        "- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）",
        f"- 策略抑制候选：{suppressed_count} 条" + (
            "（" + "、".join(f"{k}×{v}" for k, v in sorted(suppressed_by_type.items(), key=lambda kv: -kv[1])[:6]) + "）"
            if suppressed_count else ""),
        f"- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`",
        "",
        "## 1. 执行摘要",
        "",
        result.summary,
        "",
        f"共 **{len(result.findings)}** 条 finding；"
        f"**{sum(1 for f in result.findings if f.poc and f.poc.scripts)}** 条已生成 POC；"
        f"**{len(result.second_order)}** 条二次注入链；"
        f"**{len(result.injection_signals)}** 条 Prompt 注入迹象，隔离 **{len(result.project.manifest.get('security', {}).get('quarantined_files', []))}** 个文件。",
        "",
        "> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，"
        "需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。",
        "",
    ]
    if suppressed_count:
        lines += [
            "## 1.1 策略抑制（不是未检出）",
            "",
            f"本次按 `min_severity={settings.min_severity}` / `min_confidence={settings.min_confidence}` 交付；"
            f"以下 **{suppressed_count}** 条候选被门禁抑制，切换档位后可重新进入 finding：",
            "",
            "| 类型 | 位置 | 严重度 | 置信度 | 规则 | 原因 |",
            "|---|---|---|---|---|---|",
        ]
        for item in suppressed_items[:50]:
            lines.append(
                f"| `{item.get('vulnerability_type','')}` | `{item.get('file','')}:{item.get('line','')}` | "
                f"{item.get('severity','')} | {item.get('confidence','')} | `{item.get('rule_id','')}` | "
                f"{'/'.join(item.get('reasons') or [])} |"
            )
        if suppressed_count > len(suppressed_items[:50]):
            lines.append(f"| … | 另有 {suppressed_count - len(suppressed_items[:50])} 条 | | | | 见 `report.json` 的 `policy.suppressed` |")
        lines.append("")
    lines += [
        "## 2. LLM 安全防护（SafetyGuard）",
        "",
    ]
    security = result.project.manifest.get("security", {})
    if result.injection_signals:
        lines += [
            f"- 扫描文件：{security.get('scanned_files', 0)}",
            f"- 注入迹象：{security.get('signal_count', 0)}",
            f"- 隔离文件：{', '.join(security.get('quarantined_files', [])) or '无'}",
            "",
            "| 文件 | 行 | 类别 | 严重度 | 片段 |",
            "|---|---|---|---|---|",
        ]
        for signal in result.injection_signals[:50]:
            lines.append(
                f"| `{_md(signal.file)}` | {signal.line} | {signal.category} | {signal.severity} | {_md(signal.excerpt)[:220]} |"
            )
        lines.append("")
    else:
        lines += ["未检测到 Prompt 注入迹象。", ""]

    llm_finding = result.project.manifest.get("llm_finding") or {}
    lines += ["## 2.1 LLM 深挖（LLM-finding / DeepFinder）", ""]
    if llm_finding.get("enabled"):
        lines += [
            f"- 模式：`{llm_finding.get('mode', 'auto')}`；工具调用：`{llm_finding.get('tool_calls', 0)}`"
            "（无 tools / tool_choice / function calling）",
            f"- 送入源码：{llm_finding.get('files', 0)} 个文件 / {llm_finding.get('chars', 0)} 字符；"
            f"截断 {llm_finding.get('truncated_files', 0)} 个",
            f"- 模型新增候选：{llm_finding.get('findings', 0)} 条；"
            f"同批重复合并：{llm_finding.get('duplicates', 0)} 条；"
            f"安全校验拒绝：{llm_finding.get('rejected_count', len(llm_finding.get('rejected') or []))} 条",
        ]
        if llm_finding.get("summary"):
            lines += ["", f"模型覆盖说明：{_md(llm_finding['summary'])[:1200]}"]
        if llm_finding.get("gaps"):
            lines += ["", "未覆盖 / 证据缺口："]
            lines += [f"- {_md(item)[:300]}" for item in llm_finding["gaps"][:10]]
    else:
        lines.append(f"- 未执行：{llm_finding.get('reason', 'LLM 未启用')}")
    lines.append("")

    lines += [
        "## 3. Findings",
        "",
    ]
    if not result.findings:
        lines += ["未发现满足阈值的候选。", ""]
    for index, finding in enumerate(result.findings, 1):
        lines += _finding_section(finding, index, poc_mapping.get(finding.finding_id))

    lines += [
        "## 隐性逻辑专属判定（LogicAnalyzer）",
        "",
        "详细证据、缺口与对照验证步骤见 `logic_analysis.json`。未执行目标 POC。",
        "`guarded` 只表示指定局部规则有保护，不代表应用安全；`needs_context` 不算已检出漏洞。",
        "",
        "| 规则 | 位置 | 状态 | 理由 |",
        "|---|---|---|---|",
    ]
    for assessment in result.logic_assessments:
        lines.append(f"| {_md(assessment['expected_rule'])} | `{_md(assessment['file'])}:{assessment['line_end']}` | "
                     f"{assessment['status']} | {_md(assessment['reason'])} |")
    if not result.logic_assessments:
        lines.append("| — | — | 未覆盖 | 未匹配内置流程模式或未提供适用的业务规则，不能据此认定安全 |")
    lines += [
        "",
        "## 4. 二次注入（SecondOrderAnalyzer）",
        "",
    ]
    if not result.second_order:
        lines += ["本次未发现 store→read→sink 闭环的二次注入链。", ""]
    else:
        for chain in result.second_order:
            lines += [
                f"### {chain.chain_id} — {chain.storage} `{chain.storage_key}`",
                "",
                f"- 写点：`{chain.file}:{chain.store_line}`",
                f"- 读点：`{chain.file}:{chain.read_line}`",
                f"- 汇点：`{chain.file}:{chain.sink_line}`",
                f"- 端点：`{chain.endpoint_store}` → `{chain.endpoint_trigger}`",
                f"- 置信度：`{chain.confidence}`",
                "",
                "| # | 位置 | 描述 |",
                "|---|---|---|",
            ]
            for step in chain.chain:
                lines.append(f"| {step.step} | `{_md(step.location)}` | {_md(step.description)} |")
            lines.append("")
            if chain.poc:
                lines.append(chain.poc.description)
                lines.append("")
                for step in chain.poc.steps:
                    lines.append(f"{step.get('step')}. **{step.get('action', '')}**")
                    lines.append("")
                    lines.append("```http")
                    lines.append(str(step.get("request", "")))
                    lines.append("```")
                lines.append("")
        lines.append("")

    lines += [
        "## 5. AWVS 联动",
        "",
        f"- 输入模式：`{input_mode}`",
        f"- 导入结果：{len(result.awvs_imported)} 条",
        f"- 关联明细：{len(result.awvs_correlations)} 条",
        "- 目标种子：`awvs/targets.json`",
        (
            "- 说明：URL 模式下 AWVS 是候选提出组件；本管线消费其 URL/请求/证据并生成 POC，"
            "不执行扫描；动态确认由落日验证完成。"
            if input_mode == "url" else
            "- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。"
        ),
        "",
    ]
    if result.awvs_correlations:
        lines += ["| finding | AWVS | URL | 结论 |", "|---|---|---|---|"]
        for item in result.awvs_correlations:
            lines.append(f"| `{_md(item.get('finding_id'))}` | {_md(item.get('awvs'))} | {_md(item.get('url'))} | {item.get('verdict')} |")
        lines.append("")

    lines += [
        "## 6. 漏洞类型覆盖",
        "",
        "| 类型 | CWE | AutoCVE | 本次数量 |",
        "|---|---|---|---|",
    ]
    for item in coverage:
        lines.append(f"| `{item['type']}` | {item['cwe']} | {'是' if item['auto_cve'] else ''} | {item['count']} |")
    lines += [
        "",
        "## 7. 运行阶段",
        "",
        "| agent | 代号 | 耗时(s) | 使用 LLM |",
        "|---|---|---|---|",
    ]
    for entry in result.stage_log:
        if not entry.get("agent"):
            continue  # ctx.log 的普通日志行没有 agent 字段，不进入阶段表
        lines.append(
            f"| {entry.get('agent')} | {entry.get('codename')} | {entry.get('duration_sec')} | "
            f"{'是' if entry.get('used_llm') else '否'} |"
        )
    lines += [
        "",
        "## 8. 限制",
        "",
        "- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；",
        "- finding 的 `verdict` 为 `candidate`，不是动态确认；",
        "- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；",
        "- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。",
        "",
    ]
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")

    # manifest
    _write_json(out_dir / "manifest.json", {
        "run_id": result.run_id,
        "version": __version__,
        "generated_at": generated_at,
        "zip": result.project.zip_path,
        "zip_sha256": result.project.zip_sha256,
        "project_manifest": result.project.manifest,
        "settings": settings.public(),
        "counts": {
            "findings": len(result.findings),
            "with_poc": sum(1 for finding in result.findings if finding.poc and finding.poc.scripts),
            "second_order": len(result.second_order),
            "logic_assessments": len(result.logic_assessments),
            "candidates": len(result.candidates),
            "injection_signals": len(result.injection_signals),
            "awvs_imported": len(result.awvs_imported),
        },
        "llm_usage": result.llm_usage,
        "structured_report": structured_paths,
        "files": ["report.md", "report.json", "report.schema.json", "report.sarif", "report.html",
                  "result.json", "findings.csv", "coverage.json",
                  "security/injection_report.json", "second_order.json", "logic_analysis.json", "awvs/targets.json",
                  "awvs/correlations.json", "poc/"],
    })
    if log:
        log(f"报告已写入 {out_dir}")
