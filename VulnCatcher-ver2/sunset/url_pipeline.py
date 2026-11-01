"""VulnCatcher URL pipeline: AWVS candidates -> agents -> POC + report.

The zip pipeline starts with source and asks "what could be vulnerable?".
This pipeline starts with a live URL and an AWVS feed (real API, exported
report, or the local AWVS-compatible probe) and asks "what did the scanner
observe, and can we turn each candidate into a replayable POC?".

It intentionally keeps the same agent names and output contract as the zip
pipeline so reports, POCs, and 落日验证 can consume both modes.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .agents import (
    CandidateScreenerAgent,
    CoordinatorAgent,
    PocWriterAgent,
    SafetyGuardAgent,
    SurfaceMapperAgent,
    VulnerabilityAnalyzerAgent,
)
from .agents.base import AgentContext
from .awvs import AwvsClient, AwvsVulnerability, parse_report
from .awvs_local import scan_manifest
from .config import Settings
from .llm import LlmClient
from .models import Endpoint, Project, RunResult
from .report import write_reports
from .url_findings import candidate_from_vuln


@dataclass
class UrlPipelineOptions:
    target_url: str
    settings: Settings


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _awvs_dict(item: AwvsVulnerability) -> dict[str, Any]:
    return {
        "vt_name": item.vt_name,
        "url": item.url,
        "severity": item.severity,
        "cwe": item.cwe,
        "details": item.details[:800],
        "channel": item.channel,
        "parameter": item.parameter,
        "payload": item.payload,
        "has_request": bool(item.request),
        "source": item.source,
    }


class SunsetUrlPipeline:
    def __init__(self, options: UrlPipelineOptions):
        self.options = options
        self.settings = options.settings
        self.lines: list[str] = []

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self.lines.append(line)
        if not self.settings.quiet:
            print(line, flush=True)

    def _collect(self, out_dir: Path) -> tuple[list[AwvsVulnerability], str]:
        target = self.options.target_url
        if self.settings.awvs_report:
            vulns = parse_report(Path(self.settings.awvs_report))
            if target:
                vulns = [item for item in vulns if not item.url or item.url.rstrip("/") == target.rstrip("/")
                         or target.rstrip("/").endswith("/" + item.url.rstrip("/").split("/")[-1])]
            return vulns, "awvs-report"

        if self.settings.awvs_url and self.settings.awvs_key:
            scan_target = self.settings.awvs_target or target
            client = AwvsClient(
                self.settings.awvs_url,
                self.settings.awvs_key,
                verify_tls=not self.settings.awvs_insecure_tls,
            )
            profile = self.settings.awvs_profile or "11111111-1111-1111-1111-111111111111"
            self.log(f"AWVS API: scanning {scan_target} (profile={profile})")
            vulns = client.trigger_and_fetch(
                scan_target,
                profile,
                wait_sec=max(60, self.settings.awvs_wait or 1800),
            )
            return vulns, "awvs-api"

        manifest = self.settings.awvs_manifest
        if not manifest:
            for candidate in (
                Path.cwd() / "runtime" / "lite-targets.json",
                Path(__file__).resolve().parents[1] / "runtime" / "lite-targets.json",
            ):
                if candidate.is_file():
                    manifest = str(candidate)
                    break
        if manifest and Path(manifest).is_file():
            self.log(f"AWVS local probe: manifest={manifest}")
            vulns = scan_manifest(
                manifest,
                target_url=target,
                insecure=self.settings.target_insecure_tls,
            )
            return vulns, "awvs-local-probe"

        raise RuntimeError(
            "URL mode needs an AWVS source: pass --awvs-report, "
            "--awvs-url/--awvs-key, or --awvs-manifest for the local probe."
        )

    def run(self) -> RunResult:
        started = time.time()
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        out_dir = (self.settings.output_dir or (Path.cwd() / "sunset-results" / run_id)).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        self.settings.output_dir = out_dir
        target = self.options.target_url
        self.log(f"VulnCatcher URL 管线启动：{target} -> {out_dir}")

        vulns, provider = self._collect(out_dir)
        self.log(f"AWVS 来源 {provider}：{len(vulns)} 条候选")
        (out_dir / "awvs").mkdir(parents=True, exist_ok=True)
        (out_dir / "awvs" / "scan.json").write_text(
            json.dumps({
                "provider": provider,
                "target": target,
                "vulnerabilities": [_awvs_dict(item) for item in vulns],
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (out_dir / "awvs" / "targets.json").write_text(
            json.dumps({
                "generated_by": "VulnCatcher / URL SurfaceMapper",
                "target": target,
                "targets": [
                    {
                        "url": item.url,
                        "method": (item.method or "POST").upper(),
                        "vt_name": item.vt_name,
                        "channel": item.channel,
                        "parameter": item.parameter,
                    }
                    for item in vulns
                ],
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        endpoints: list[Endpoint] = []
        for vuln in vulns:
            from .awvs import _path_of
            endpoints.append(Endpoint(
                path=_path_of(vuln.url),
                method=(vuln.method or "POST").upper(),
                file="",
                line=0,
                framework="awvs",
                handler=vuln.vt_name,
            ))
        project = Project(
            zip_path=target,
            zip_sha256=_sha256_text(target),
            root=target,
            extracted_dir="",
            files=[],
            endpoints=endpoints,
            languages={},
            frameworks=["http", "awvs"],
            manifest={
                "input_mode": "url",
                "target_url": target,
                "awvs_provider": provider,
                "awvs_raw_count": len(vulns),
            },
            input_mode="url",
            target_url=target,
        )

        ctx = AgentContext(
            project=project,
            contents={},
            settings=self.settings,
            llm=LlmClient(self.settings) if self.settings.llm_enabled else None,
        )
        ctx.candidates = [candidate_from_vuln(item, target) for item in vulns]
        ctx.awvs_vulns = list(vulns)
        ctx.log("candidate_screener", f"AWVS 候选 {len(ctx.candidates)} 条")

        self._run_agent(ctx, SafetyGuardAgent())
        self._run_agent(ctx, SurfaceMapperAgent())
        self._run_agent(ctx, CandidateScreenerAgent())
        self._run_agent(ctx, VulnerabilityAnalyzerAgent())
        self._run_agent(ctx, PocWriterAgent())
        self._run_agent(ctx, CoordinatorAgent())

        result = RunResult(
            run_id=run_id,
            project=project,
            findings=ctx.findings,
            second_order=[],
            candidates=ctx.candidates,
            injection_signals=ctx.injection_signals,
            awvs_imported=[_awvs_dict(item) for item in vulns],
            awvs_correlations=[],
            llm_usage=list(ctx.llm.usage) if ctx.llm else [],
            stage_log=ctx.stage_log,
            summary=ctx.summary,
        )
        result.project.manifest["duration_sec"] = round(time.time() - started, 1)
        result.project.manifest["security"] = {"scanned_files": 0, "signal_count": 0, "quarantined_files": []}
        write_reports(result, out_dir, settings=self.settings, log=self.log)
        self.log(f"完成：{len(result.findings)} 条 finding，"
                 f"{sum(1 for f in result.findings if f.poc and f.poc.scripts)} 条含 POC -> {out_dir}")
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
        except Exception as exc:  # noqa: BLE001
            ctx.stage_log.append({
                "agent": agent.name,
                "codename": agent.codename,
                "duration_sec": round(time.time() - started, 2),
                "used_llm": False,
                "error": str(exc),
            })
            ctx.log(agent.name, f"agent failed, keeping deterministic state: {exc}")


def run_url_pipeline(target_url: str, settings: Settings) -> RunResult:
    return SunsetUrlPipeline(UrlPipelineOptions(target_url=target_url, settings=settings)).run()
