"""规范化结构化漏洞报告。

输出四件套：
- report.json       稳定的报告契约（供平台/CI/二次开发消费）
- report.schema.json 报告 JSON Schema（契约本身）
- report.sarif      SARIF 2.1.0（供代码扫描平台/IDE 消费）
- report.html       人类可读的独立 HTML（无外部依赖）

与 result.json 的区别：result.json 是管线内部全量结果；report.json 是面向交付的
稳定结构，字段、统计、证据、POC、安全标记都有明确位置。
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import Settings
from .models import Finding, RunResult
from .taxonomy import VULN_TYPES, auto_cve_types, meta

SCHEMA_VERSION = "1.0"
SEVERITY_CVSS = {"critical": 9.8, "high": 8.1, "medium": 5.5, "low": 3.1, "info": 0.0}
SEVERITY_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

REPORT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://sunset-one.local/schema/report-1.0.json",
    "title": "落日二号结构化漏洞报告",
    "type": "object",
    "required": [
        "schema_version", "generator", "run", "project", "summary",
        "findings", "second_order", "security", "awvs", "coverage", "llm", "limitations",
    ],
    "properties": {
        "schema_version": {"type": "string"},
        "generator": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {"name": {"type": "string"}, "version": {"type": "string"}},
        },
        "run": {
            "type": "object",
            "required": ["run_id", "generated_at", "zip_path", "zip_sha256"],
            "properties": {
                "run_id": {"type": "string"},
                "generated_at": {"type": "string"},
                "zip_path": {"type": "string"},
                "zip_sha256": {"type": "string"},
                "duration_sec": {"type": "number"},
            },
        },
        "project": {
            "type": "object",
            "required": ["file_count", "languages", "frameworks", "endpoint_count"],
            "properties": {
                "file_count": {"type": "integer"},
                "text_file_count": {"type": "integer"},
                "languages": {"type": "object"},
                "frameworks": {"type": "array", "items": {"type": "string"}},
                "endpoint_count": {"type": "integer"},
                "endpoints": {"type": "array"},
                "files": {"type": "array"},
            },
        },
        "summary": {
            "type": "object",
            "required": ["total_findings", "with_poc", "by_severity", "by_verdict", "by_evidence_level"],
            "properties": {
                "total_findings": {"type": "integer"},
                "with_poc": {"type": "integer"},
                "by_severity": {"type": "object"},
                "by_verdict": {"type": "object"},
                "by_evidence_level": {"type": "object"},
                "second_order": {"type": "integer"},
                "injection_signals": {"type": "integer"},
                "quarantined_files": {"type": "array", "items": {"type": "string"}},
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id", "title", "vulnerability_type", "cwe", "severity",
                    "confidence", "verdict", "evidence_level", "location",
                    "exploit_chain", "poc", "safety",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "vulnerability_type": {"type": "string"},
                    "cwe": {"type": "string"},
                    "severity": {"type": "string"},
                    "cvss_estimate": {"type": "number"},
                    "confidence": {"type": "number"},
                    "verdict": {"type": "string"},
                    "evidence_level": {"type": "string"},
                    "location": {"type": "object"},
                    "exploit_chain": {"type": "array"},
                    "poc": {"type": "object"},
                    "safety": {"type": "object"},
                },
            },
        },
        "second_order": {"type": "array"},
        "logic_assessments": {"type": "array"},
        "security": {"type": "object"},
        "awvs": {"type": "object"},
        "coverage": {"type": "object"},
        "policy": {"type": "object"},
        "llm": {"type": "object"},
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
}

LIMITATIONS = [
    "只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱。",
    "finding 的 verdict 为 candidate 或 external，不是动态确认。",
    "POC 仅为文本工件，目标使用 TARGET 占位符，仅限授权测试。",
    "规则为轻量级启发式，复杂控制流/常量传播/跨文件调用可能漏报或误报。",
    "AWVS 是外部动态扫描器，结果只作为佐证；本管线不执行 AWVS 扫描。",
]


def _cvss(severity: str) -> float:
    return SEVERITY_CVSS.get((severity or "").lower(), 0.0)


def _finding(finding: Finding, poc_dir: str) -> dict[str, Any]:
    item = meta(finding.vulnerability_type)
    poc = finding.poc
    return {
        "id": finding.finding_id,
        "title": finding.title,
        "vulnerability_type": finding.vulnerability_type,
        "cwe": item.cwe,
        "cwe_name": item.label_zh,
        "severity": finding.severity,
        "cvss_estimate": _cvss(finding.severity),
        "cvss_note": "按严重度给出的粗略估计，不是正式 CVSS 评分。",
        "confidence": finding.confidence,
        "verdict": finding.verdict,
        "evidence_level": finding.evidence_level,
        "origin": finding.origin,
        "needs_verification": finding.needs_verification,
        "location": {
            "file": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "endpoint": finding.endpoint,
            "http_method": finding.http_method,
        },
        "source": finding.source,
        "sink": finding.sink,
        "description": finding.description,
        "impact": finding.impact,
        "cve_justification": finding.cve_justification,
        "suggestion": finding.suggestion,
        "exploit_chain": [step.to_dict() for step in finding.exploit_chain],
        "poc": {
            "description": poc.description,
            "preconditions": poc.preconditions,
            "steps": poc.steps,
            "payload": poc.payload,
            "impact": poc.impact,
            "cve_justification": poc.cve_justification,
            "scripts": poc.scripts,
            "safety": poc.safety,
            "artifact_dir": poc_dir,
        },
        "external_evidence": finding.external_evidence,
        "verification_notes": finding.verification_notes,
        "safety": finding.safety,
        "tags": [finding.vulnerability_type, item.cwe, finding.severity, finding.origin, finding.evidence_level],
    }


def build_structured_report(result: RunResult, settings: Settings,
                            poc_mapping: dict[str, str] | None = None) -> dict[str, Any]:
    poc_mapping = poc_mapping or {}
    findings = [_finding(item, poc_mapping.get(item.finding_id, "")) for item in result.findings]
    severity_counts = Counter(item.severity for item in result.findings)
    verdict_counts = Counter(item.verdict for item in result.findings)
    evidence_counts = Counter(item.evidence_level for item in result.findings)
    security = result.project.manifest.get("security", {})
    coverage_counts = Counter(item.vulnerability_type for item in result.findings)
    coverage = {
        "counts": dict(coverage_counts),
        "types": [
            {
                "type": name,
                "label": item.label_zh,
                "cwe": item.cwe,
                "auto_cve": name in auto_cve_types(),
                "count": coverage_counts.get(name, 0),
            }
            for name, item in VULN_TYPES.items()
        ],
    }
    generated_at = datetime.now(timezone.utc).isoformat()
    input_mode = result.project.manifest.get("input_mode", result.project.input_mode or "zip")
    rule_stats = result.project.manifest.get("rule_stats") or {}
    suppressed = rule_stats.get("suppressed") or []
    policy = {
        "rule_generation_enabled": bool(rule_stats.get("enabled", True)),
        "min_severity": settings.min_severity,
        "min_confidence": settings.min_confidence,
        "raw_candidates": rule_stats.get("raw_candidates", 0),
        "kept_candidates": rule_stats.get("kept_candidates", 0),
        "suppressed_count": rule_stats.get("suppressed_count", len(suppressed)),
        "suppressed_by_type": rule_stats.get("suppressed_by_type", {}),
        "suppressed_by_reason": rule_stats.get("suppressed_by_reason", {}),
        "suppressed": suppressed,
        "note": (
            "落日二号乙不运行确定性规则候选生成；suppressed 仅在外部输入或后续阶段"
            "显式产生策略抑制项时使用。"
        ),
    }
    trace_data = result.project.manifest.get("llm_traces") or []
    llm_payload = {
        "enabled": settings.llm_enabled,
        "mode": settings.llm_mode,
        "model": settings.llm_model,
        "calls": len(result.llm_usage),
        "usage": result.llm_usage,
        "traces": trace_data,
    }
    if result.project.manifest.get("surface_notes"):
        llm_payload["surface_notes"] = result.project.manifest["surface_notes"]
    if result.project.manifest.get("llm_finding"):
        llm_payload["finding"] = result.project.manifest["llm_finding"]
    if result.project.manifest.get("llm_policy_note"):
        llm_payload["policy_note"] = result.project.manifest["llm_policy_note"]
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "落日二号乙 / Sunset Two Beta", "version": __version__},
        "run": {
            "run_id": result.run_id,
            "generated_at": generated_at,
            "input_mode": input_mode,
            "target_url": result.project.target_url or "",
            "zip_path": result.project.zip_path,
            "zip_sha256": result.project.zip_sha256,
            "duration_sec": result.project.manifest.get("duration_sec", 0),
        },
        "project": {
            "file_count": len(result.project.files),
            "text_file_count": sum(1 for item in result.project.files if item.is_text),
            "languages": result.project.languages,
            "frameworks": result.project.frameworks,
            "endpoint_count": len(result.project.endpoints),
            "endpoints": [item.to_dict() for item in result.project.endpoints[:500]],
            "files": [
                {"path": item.rel_path, "language": item.language, "lines": item.lines, "size": item.size}
                for item in result.project.files[:5000]
            ],
        },
        "summary": {
            "text": result.summary,
            "total_findings": len(result.findings),
            "with_poc": sum(1 for item in result.findings if item.poc and item.poc.scripts),
            "by_severity": dict(severity_counts),
            "by_verdict": dict(verdict_counts),
            "by_evidence_level": dict(evidence_counts),
            "by_origin": dict(Counter(item.origin for item in result.findings)),
            "second_order": len(result.second_order),
            "logic_assessments": dict(Counter(a["status"] for a in result.logic_assessments)),
            "injection_signals": len(result.injection_signals),
            "quarantined_files": sorted(set(result.project.manifest.get("security", {}).get("quarantined_files", []))),
        },
        "findings": findings,
        "second_order": [chain.to_dict() for chain in result.second_order],
        "logic_assessments": result.logic_assessments,
        "security": {
            "scanned_files": security.get("scanned_files", 0),
            "signal_count": security.get("signal_count", 0),
            "quarantined_files": security.get("quarantined_files", []),
            "by_category": security.get("by_category", {}),
            "signals": [signal.to_dict() for signal in result.injection_signals[:100]],
            "policy": "untrusted-data-envelope + file-allowlist + passive-poc",
        },
        "awvs": {
            "role": "external_corroboration",
            "note": "AWVS 是外部动态扫描器；本管线只做目标播种与结果回灌，不执行 AWVS 扫描。",
            "imported": result.awvs_imported,
            "correlations": result.awvs_correlations,
            "targets_file": "awvs/targets.json",
        },
        "coverage": coverage,
        "policy": policy,
        "llm": llm_payload,
        "limitations": LIMITATIONS + ([
            f"本次按 min_severity={settings.min_severity} 交付：{policy['suppressed_count']} 条候选被档位/置信度门禁抑制，"
            "不代表目标不存在这些类型的漏洞；明细见 policy.suppressed。"
        ] if policy["suppressed_count"] else []),
    }


def validate_structured_report(report: dict[str, Any]) -> list[str]:
    """轻量契约校验（不引入 jsonschema 依赖）。返回错误列表。"""
    errors: list[str] = []
    required = REPORT_SCHEMA["required"]
    for key in required:
        if key not in report:
            errors.append(f"缺少顶层字段: {key}")
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version 应为 {SCHEMA_VERSION}")
    findings = report.get("findings")
    if not isinstance(findings, list):
        errors.append("findings 不是数组")
        return errors
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] 不是对象")
            continue
        for key in REPORT_SCHEMA["properties"]["findings"]["items"]["required"]:
            if key not in item:
                errors.append(f"findings[{index}] 缺少 {key}")
        location = item.get("location", {})
        if not isinstance(location, dict):
            errors.append(f"findings[{index}].location 不是对象")
        poc = item.get("poc", {})
        if not isinstance(poc, dict) or "safety" not in poc:
            errors.append(f"findings[{index}].poc 缺少 safety")
    return errors


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in report.get("findings", []):
        vtype = item.get("vulnerability_type", "other")
        rule_id = f"sunset/{vtype}"
        if rule_id not in rules:
            info = meta(vtype)
            rules[rule_id] = {
                "id": rule_id,
                "name": info.label_zh,
                "shortDescription": {"text": f"{info.label_zh}（{info.cwe}）"},
                "fullDescription": {"text": info.description or info.label_zh},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{info.cwe.split('-')[-1]}.html",
                "properties": {"tags": [vtype, info.cwe, "security"]},
            }
        location = item.get("location", {})
        file_path = location.get("file") or ""
        uri = file_path or (location.get("endpoint") or "awvs")
        region = {"startLine": max(1, int(location.get("line_start") or 1)),
                  "endLine": max(1, int(location.get("line_end") or location.get("line_start") or 1))}
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_SARIF.get(str(item.get("severity", "")).lower(), "warning"),
            "message": {"text": f"{item.get('title', '')}\n\n{item.get('description', '')}"[:4000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri.replace("\\", "/")},
                    "region": region,
                }
            }],
            "partialFingerprints": {"sunsetFindingId": item.get("id", "")},
            "properties": {
                "finding_id": item.get("id", ""),
                "confidence": item.get("confidence", 0),
                "verdict": item.get("verdict", ""),
                "evidence_level": item.get("evidence_level", ""),
                "cwe": item.get("cwe", ""),
                "endpoint": location.get("endpoint", ""),
                "http_method": location.get("http_method", ""),
                "has_poc": bool((item.get("poc") or {}).get("scripts")),
                "origin": item.get("origin", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "落日二号乙 / Sunset Two Beta",
                "version": __version__,
                "informationUri": "https://sunset-one.local",
                "rules": list(rules.values()),
            }},
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": report.get("run", {}).get("generated_at", ""),
                "toolExecutionNotifications": [],
            }],
            "results": results,
        }],
    }


def render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    rows = []
    for index, item in enumerate(findings, 1):
        loc = item.get("location", {})
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td><span class='sev sev-{esc(item.get('severity'))}'>{esc(item.get('severity'))}</span></td>"
            f"<td><code>{esc(item.get('vulnerability_type'))}</code></td>"
            f"<td>{esc(item.get('title'))}</td>"
            f"<td><code>{esc(loc.get('file'))}:{esc(loc.get('line_end'))}</code></td>"
            f"<td>{esc(item.get('confidence'))}</td>"
            f"<td>{'是' if (item.get('poc') or {}).get('scripts') else '否'}</td>"
            "</tr>"
        )
    cards = []
    for index, item in enumerate(findings, 1):
        loc = item.get("location", {})
        poc = item.get("poc", {})
        chain_rows = "".join(
            f"<tr><td>{esc(step.get('step'))}</td><td><code>{esc(step.get('location'))}</code></td>"
            f"<td>{esc(step.get('description'))}</td><td>{esc(step.get('data_state'))}</td>"
            f"<td>{esc(step.get('bypass_reason'))}</td></tr>"
            for step in item.get("exploit_chain", [])
        )
        steps = []
        for step in poc.get("steps", []):
            request = f"<pre>{esc(step.get('request'))}</pre>" if step.get("request") else ""
            steps.append(
                f"<li><b>{esc(step.get('action'))}</b>{request}"
                f"<div class='muted'>预期：{esc(step.get('expected_response'))}</div></li>"
            )
        scripts = ""
        if poc.get("scripts"):
            scripts = "<details><summary>POC 脚本</summary>" + "".join(
                f"<h4>{esc(name)}</h4><pre>{esc(content)}</pre>" for name, content in poc["scripts"].items()
            ) + "</details>"
        cards.append(
            f"<section class='card' id='{esc(item.get('id'))}'>"
            f"<h2>F-{index} {esc(item.get('title'))}</h2>"
            f"<p><span class='sev sev-{esc(item.get('severity'))}'>{esc(item.get('severity'))}</span> "
            f"<code>{esc(item.get('vulnerability_type'))}</code> / {esc(item.get('cwe'))} · "
            f"置信度 {esc(item.get('confidence'))} · {esc(item.get('verdict'))} / {esc(item.get('evidence_level'))}</p>"
            f"<p><b>位置：</b><code>{esc(loc.get('file'))}:{esc(loc.get('line_start'))}-{esc(loc.get('line_end'))}</code></p>"
            f"<p>{esc(item.get('description'))}</p>"
            f"<p><b>影响：</b>{esc(item.get('impact'))}</p>"
            f"<p><b>CVE/CWE 论证：</b>{esc(item.get('cve_justification'))}</p>"
            f"<p><b>修复建议：</b>{esc(item.get('suggestion'))}</p>"
            "<h3>利用链</h3><table><thead><tr><th>#</th><th>位置</th><th>描述</th><th>数据状态</th><th>绕过原因</th></tr></thead>"
            f"<tbody>{chain_rows}</tbody></table>"
            "<h3>POC</h3>"
            f"<p>{esc(poc.get('description'))}</p><ol>{''.join(steps)}</ol>{scripts}"
            f"<p class='muted'>执行状态：未执行；POC 仅为文本工件，仅限授权测试。</p>"
            "</section>"
        )
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>落日二号漏洞报告 {esc(report.get('run', {}).get('run_id'))}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f6f7f9;color:#1f2328;line-height:1.6}}
header{{background:#0b1220;color:#fff;padding:28px 40px}}
header h1{{margin:0 0 8px;font-size:26px}} header p{{margin:2px 0;color:#c9d1d9}}
main{{max-width:1180px;margin:24px auto;padding:0 20px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
.card{{background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:18px 20px;margin:18px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
.metric{{background:#fff;border:1px solid #d8dee4;border-radius:10px;padding:12px 16px;min-width:120px}}
.metric b{{display:block;font-size:24px}}
table{{width:100%;border-collapse:collapse;margin:10px 0 16px;font-size:14px}}
th,td{{border:1px solid #d8dee4;padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:#f0f3f6}}
pre{{background:#0b1220;color:#d1f0d1;padding:12px;border-radius:8px;overflow:auto;font-size:13px}}
code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
.muted{{color:#59636e;font-size:13px}}
.sev{{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px}}
.sev-critical{{background:#a40e26}} .sev-high{{background:#cf222e}} .sev-medium{{background:#bf8700}} .sev-low{{background:#6e7781}}
a{{color:#0969da}}
</style></head><body>
<header><h1>落日二号漏洞挖掘报告</h1>
<p>run_id: {esc(report.get('run', {}).get('run_id'))} · 生成时间: {esc(report.get('run', {}).get('generated_at'))}</p>
<p>输入: {esc(report.get('run', {}).get('zip_path'))} · SHA256: {esc(report.get('run', {}).get('zip_sha256'))}</p></header>
<main>
<div class="cards">
<div class="metric"><b>{esc(summary.get('total_findings'))}</b>findings</div>
<div class="metric"><b>{esc(summary.get('with_poc'))}</b>含 POC</div>
<div class="metric"><b>{esc(summary.get('second_order'))}</b>二次注入链</div>
<div class="metric"><b>{esc(summary.get('injection_signals'))}</b>Prompt 注入迹象</div>
</div>
<section class="card"><h2>执行摘要</h2><p>{esc(report.get('summary', {}).get('text', ''))}</p>
<p class="muted">本报告为结构化静态分析结果；未执行 POC、未搭建沙箱。完整机器可读数据见 report.json / report.sarif。</p></section>
<section class="card"><h2>Findings</h2>
<table><thead><tr><th>#</th><th>严重度</th><th>类型</th><th>标题</th><th>位置</th><th>置信度</th><th>POC</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></section>
{''.join(cards)}
<section class="card"><h2>限制</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in report.get('limitations', []))}</ul></section>
</main></body></html>"""


def write_structured_report(report: dict[str, Any], out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report_json": out_dir / "report.json",
        "report_schema": out_dir / "report.schema.json",
        "report_sarif": out_dir / "report.sarif",
        "report_html": out_dir / "report.html",
    }
    paths["report_json"].write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    paths["report_schema"].write_text(json.dumps(REPORT_SCHEMA, ensure_ascii=False, indent=2), encoding="utf-8")
    paths["report_sarif"].write_text(json.dumps(to_sarif(report), ensure_ascii=False, indent=2), encoding="utf-8")
    paths["report_html"].write_text(render_html(report), encoding="utf-8")
    return {key: str(value) for key, value in paths.items()}

