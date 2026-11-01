"""VulnCatcher主管线。

顺序：
  ingest → index → SafetyGuard(隔离) → SurfaceMapper(攻击面)
  → DeepFinder(LLM 自主发现，无工具) → CandidateScreener(筛选) → VulnerabilityAnalyzer(深挖)
  → SecondOrderAnalyzer(二次注入) → LogicAnalyzer(隐性逻辑) → AWVS(联动)
  → PocWriter(POC) → Coordinator(汇总) → report

ZIP 模式融合确定性规则与 LLM 候选。管线不执行 POC、不向模型暴露工具；
LLM 仅在各 agent 内做一次 JSON 调用。URL 模式的 AWVS 候选仍作为外部输入保留。
"""

from __future__ import annotations

import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .agents import (
    CoordinatorAgent,
    DeepFinderAgent,
    LogicAnalyzerAgent,
    SecondOrderAnalyzerAgent,
    VulnerabilityAnalyzerAgent,
    CandidateScreenerAgent,
    PocWriterAgent,
    SurfaceMapperAgent,
    SafetyGuardAgent,
)
from .agents.base import AgentContext
from .agents.logic_analyzer import load_logic_policies
from .awvs import AwvsClient, correlate, export_targets, parse_report
from .config import Settings
from .indexer import detect_frameworks, extract_endpoints
from .ingest import ingest_zip
from .llm import LlmClient
from .models import RunResult
from .report import write_reports
from .security.guard import scan_project as guard_scan
from .rules import scan_project as scan_rule_candidates


@dataclass
class PipelineOptions:
    zip_path: Path
    settings: Settings


class SunsetPipeline:
    def __init__(self, options: PipelineOptions):
        self.options = options
        self.settings = options.settings
        self.lines: list[str] = []

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self.lines.append(line)
        if not self.settings.quiet:
            print(line, flush=True)

    def run(self) -> RunResult:
        started = time.time()
        # 配置错误应直接反馈，不能静默跳过操作者要求的业务规则。
        logic_policies, logic_provenance = load_logic_policies(self.settings.logic_policy)
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        out_dir = (self.settings.output_dir or (Path.cwd() / "sunset-results" / run_id)).resolve()
        work_dir = (self.settings.work_dir or (out_dir / ".work" / run_id)).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        self.settings.output_dir = out_dir

        self.log(f"VulnCatcher启动：{self.options.zip_path.name} → {out_dir}")
        ingest = ingest_zip(self.options.zip_path, work_dir)
        project = ingest.project
        project.frameworks = detect_frameworks(ingest.contents)
        project.endpoints = extract_endpoints(project.files, ingest.contents)
        self.log(f"解压 {len(project.files)} 个文件，{len(project.endpoints)} 个端点，框架 {', '.join(project.frameworks) or '未识别'}")

        # SafetyGuard 必须在任何其它 LLM 之前跑：先隔离注入文本
        guard = guard_scan(ingest.contents.items())
        ctx = AgentContext(
            project=project,
            contents=ingest.contents,
            settings=self.settings,
            llm=LlmClient(self.settings) if self.settings.llm_enabled else None,
            injection_signals=guard.signals,
            quarantined=set(guard.quarantined),
            logic_policies=logic_policies,
            logic_policy_provenance=logic_provenance,
        )
        if guard.signals:
            self.log(f"安全防护：{len(guard.signals)} 条注入迹象，隔离 {len(guard.quarantined)} 个文件")
        else:
            self.log("安全防护：未发现 Prompt 注入迹象")
        # 先给默认值：任一 agent 失败时仍能产出报告，而不是让整条管线因缺属性而中断。
        ctx.summary = "（未生成汇总：Coordinator 未成功执行，详见 stage_log。）"

        safety_guard = SafetyGuardAgent()
        self._run_agent(ctx, safety_guard)

        # ver2 启用确定性污点规则，与 LLM 深挖互补。规则只提供可定位的
        # source→sink 候选，后续 CandidateScreener 仍负责证据审查与去重。
        try:
            rule_candidates, rule_stats = scan_rule_candidates(
                project,
                ingest.contents,
                min_severity=self.settings.min_severity,
                min_confidence=self.settings.min_confidence,
                include_config=self.settings.include_config,
            )
        except Exception as exc:  # noqa: BLE001 - 规则引擎失败不阻塞 LLM
            rule_candidates = []
            rule_stats = {
                "raw_candidates": 0,
                "kept_candidates": 0,
                "suppressed_count": 0,
                "suppressed": [],
                "suppressed_by_type": {},
                "suppressed_by_reason": {"rule_engine_error": 1},
                "types": {},
                "errors": [str(exc)],
            }
        rule_stats["enabled"] = True
        rule_stats["engine"] = "deterministic_source_sink_v2"
        ctx.candidates = rule_candidates
        ctx.project.manifest["rule_stats"] = rule_stats
        ctx.log("candidate_screener", f"确定性规则候选 {len(rule_candidates)} 条；继续融合 LLM 深挖")

        surface_mapper = SurfaceMapperAgent()
        self._run_agent(ctx, surface_mapper)

        # LLM-finding：模型基于源码包自主发现候选；无工具、无循环。
        deep_finder = DeepFinderAgent()
        self._run_agent(ctx, deep_finder)

        candidate_screener = CandidateScreenerAgent()
        self._run_agent(ctx, candidate_screener)

        vulnerability_analyzer = VulnerabilityAnalyzerAgent()
        self._run_agent(ctx, vulnerability_analyzer)

        second_order_analyzer = SecondOrderAnalyzerAgent()
        self._run_agent(ctx, second_order_analyzer)

        self._run_agent(ctx, LogicAnalyzerAgent())

        awvs_imported: list[dict] = []
        awvs_correlations: list[dict] = []
        try:
            targets_payload = export_targets(project, out_dir / "awvs" / "targets.json")
            self.log(f"AWVS：导出 {len(targets_payload.get('targets', []))} 个目标种子")
            vulns = []
            if self.settings.awvs_report:
                vulns = parse_report(Path(self.settings.awvs_report))
                awvs_imported = [self._awvs_dict(item) for item in vulns]
                self.log(f"AWVS：导入报告 {len(vulns)} 条")
            if self.settings.awvs_url and self.settings.awvs_key and self.settings.awvs_target:
                client = AwvsClient(self.settings.awvs_url, self.settings.awvs_key,
                                    verify_tls=not self.settings.awvs_insecure_tls)
                profile = self.settings.awvs_profile or "11111111-1111-1111-1111-111111111111"
                self.log(f"AWVS：触发外部扫描 {self.settings.awvs_target}（profile={profile}）")
                live = client.trigger_and_fetch(self.settings.awvs_target, profile,
                                                wait_sec=max(60, self.settings.awvs_wait or 1800))
                vulns.extend(live)
                awvs_imported.extend(self._awvs_dict(item) for item in live)
            if vulns:
                ctx.findings, awvs_correlations = correlate(ctx.findings, vulns, project)
                self.log(f"AWVS：关联 {len(awvs_correlations)} 条（其中外部独有 {sum(1 for c in awvs_correlations if c['verdict'] == 'external_only')} 条）")
        except Exception as exc:  # noqa: BLE001 - AWVS 不可用不应阻塞主流程
            self.log(f"AWVS 联动跳过：{exc}")

        poc_writer = PocWriterAgent()
        self._run_agent(ctx, poc_writer)

        coordinator = CoordinatorAgent()
        self._run_agent(ctx, coordinator)

        result = RunResult(
            run_id=run_id,
            project=project,
            findings=ctx.findings,
            second_order=ctx.second_order,
            candidates=ctx.candidates,
            injection_signals=ctx.injection_signals,
            awvs_imported=awvs_imported,
            awvs_correlations=awvs_correlations,
            llm_usage=list(ctx.llm.usage) if ctx.llm else [],
            stage_log=ctx.stage_log,
            summary=ctx.summary,
            logic_assessments=ctx.logic_assessments,
        )
        result.project.manifest["rule_stats"] = rule_stats
        result.project.manifest["security"] = guard.summary()
        result.project.manifest["duration_sec"] = round(time.time() - started, 1)

        write_reports(result, out_dir, settings=self.settings, log=self.log)
        self.log(f"完成：{len(result.findings)} 条 finding，"
                 f"{sum(1 for f in result.findings if f.poc and f.poc.scripts)} 条含 POC → {out_dir}")

        # 清理巨大的解压目录，只保留报告中的相对路径与 SHA；如需复现可用 --work-dir。
        if not self.settings.extra.get("keep_work"):
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
                # 顺手清掉空的 .work 父目录，保持输出目录干净
                work_dir.parent.rmdir()
            except OSError:
                pass
        return result

    def _run_agent(self, ctx: AgentContext, agent) -> None:
        started = time.time()
        try:
            result = agent.run(ctx)
            ctx.stage_log.append({
                "agent": result.name,
                "codename": result.codename,
                "duration_sec": result.duration_sec or round(time.time() - started, 2),
                "used_llm": result.used_llm,
                "data_keys": sorted(result.data.keys()),
                "errors": result.errors,
            })
        except Exception as exc:  # noqa: BLE001 - agent 失败降级到确定性结果
            ctx.stage_log.append({
                "agent": agent.name,
                "codename": agent.codename,
                "duration_sec": round(time.time() - started, 2),
                "used_llm": False,
                "error": str(exc),
            })
            ctx.log(agent.name, f"agent 失败，保留当前结果：{exc}")

    @staticmethod
    def _awvs_dict(item) -> dict:
        return {
            "vt_name": item.vt_name,
            "url": item.url,
            "severity": item.severity,
            "cwe": item.cwe,
            "details": item.details[:800],
            "has_request": bool(item.request),
        }


def run_pipeline(zip_path: Path, settings: Settings) -> RunResult:
    return SunsetPipeline(PipelineOptions(zip_path=zip_path, settings=settings)).run()
