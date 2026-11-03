"""One worker process per invocation. Instrument the upstream engines in this process only."""
import argparse
import json
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

OPTIONAL = {"surface_mapper", "deep_finder", "second_order_analyzer", "logic_analyzer"}
AGENTS = OPTIONAL | {"safety_guard", "candidate_screener", "vulnerability_analyzer", "poc_writer", "coordinator"}


def event(key, name, state, note=""):
    print(json.dumps(dict(key=key, name=name, state=state, note=str(note)[:500], at=time.time()), ensure_ascii=False), flush=True)


@contextmanager
def stage(key, name):
    event(key, name, "running")
    try:
        yield
    except Exception as exc:
        event(key, name, "failed", exc)
        raise
    else:
        event(key, name, "done")


def local_probe(target, settings):
    from sunset.awvs_local import _send, scan_target
    parsed = urlsplit(target)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    path = parsed.path or "/"
    try:
        _send(target, "GET", path + ("?" + parsed.query if parsed.query else ""), {}, b"",
              settings.target_insecure_tls, 6)
    except OSError as exc:
        raise ValueError(f"探针无法连接目标 {parsed.netloc}：{exc}") from exc
    profiles = []
    if settings.awvs_manifest:
        data = json.loads(Path(settings.awvs_manifest).read_text(encoding="utf-8"))
        rows = data.get("targets", []) if isinstance(data, dict) else data
        profiles = [dict(r) for r in rows if r.get("url", "").rstrip("/") == target.rstrip("/")]
    if not profiles:
        for key, value in dict(params or [("q", "test")]).items():
            rest = urlencode([(k, v) for k, v in params if k != key])
            for category in ("xss", "sql_injection"):
                profiles.append(dict(url=urlunsplit(parsed._replace(query=rest)), method="GET", channel="query",
                                     param_name=key, param_value=value, category=category, timeout=6))
    collected = []
    for row in profiles:
        for finding in scan_target(row, insecure=settings.target_insecure_tls):
            finding.url = target
            collected.append(finding)
    return collected


def scan(job, folder):
    from sunset.config import resolve_settings
    from sunset.pipeline import SunsetPipeline, PipelineOptions
    from sunset.url_pipeline import SunsetUrlPipeline, UrlPipelineOptions

    mode, url = job["mode"], job["url"]
    settings = resolve_settings(argparse.Namespace(mode=mode, out=folder / "scan", quiet=True,
                                                 llm="auto" if job["settings"]["llm"] else "off",
                                                 env_file=os.environ.get("SUNSET_ENV_FILE") or os.devnull))
    if job["settings"]["llm"] and not settings.llm_enabled:
        raise ValueError("已开启 LLM，但服务未配置模型密钥。请配置 SUNSET_LLM_API_KEY 或关闭 LLM。")
    settings.max_findings = int(settings.max_findings)
    settings.max_llm_findings = int(settings.max_llm_findings)
    settings.awvs_target = url
    settings.target_url = url
    settings.target_insecure_tls = False
    settings.awvs_report = ""
    controls = job["settings"]
    optional_off = set(controls["off"]) & OPTIONAL
    disabled_llm = set(controls["noLlm"])
    findings = None
    if url and not (settings.awvs_url and settings.awvs_key):
        with stage("probe", "AWVS 兼容探针"):
            findings = local_probe(url, settings)
            if mode == "zip":
                feed = folder / "probe.json"
                feed.write_text(json.dumps([asdict(item) for item in findings]), encoding="utf-8")
                settings.awvs_report = str(feed)
    if mode == "zip":
        pipeline = SunsetPipeline(PipelineOptions(folder / "input.zip", settings))
    else:
        pipeline = SunsetUrlPipeline(UrlPipelineOptions(url, settings))
        original_collect = pipeline._collect
        def collect(out):
            if findings is not None:
                return findings, "awvs-local-probe"
            with stage("probe", "AWVS API 扫描"):
                return original_collect(out)
        pipeline._collect = collect

    run_agent = pipeline._run_agent
    def observed(ctx, agent):
        key, name = agent.name, agent.codename
        if key in optional_off or (key == "deep_finder" and (
                not settings.llm_finding_enabled or key in disabled_llm)):
            event(key, name, "skipped", "模块关闭或未启用 LLM")
            return
        llm = ctx.llm
        if key in disabled_llm:
            ctx.llm = None
        try:
            event(key, name, "running")
            run_agent(ctx, agent)
            record = next((r for r in reversed(ctx.stage_log) if r.get("codename") == name), {})
            errors = record.get("error") or " · ".join(map(str, record.get("errors", [])))
            event(key, name, "warning" if errors else "done", errors or ("使用 LLM" if record.get("used_llm") else "确定性分析"))
        finally:
            ctx.llm = llm
    pipeline._run_agent = observed

    # Capture stages executed outside the agent dispatcher.
    from sunset import pipeline as zip_module, url_pipeline as url_module
    def observe(module, function, key, name):
        original = getattr(module, function)
        def wrapped(*args, **kwargs):
            with stage(key, name):
                return original(*args, **kwargs)
        setattr(module, function, wrapped)
    observe(zip_module, "ingest_zip", "ingest", "源码解包")
    observe(zip_module, "scan_rule_candidates", "rules", "规则候选提取")
    observe(zip_module if mode == "zip" else url_module, "write_reports", "report", "挖掘报告")
    if url and mode == "zip" and findings is None:
        from sunset.awvs import AwvsClient
        observe(AwvsClient, "trigger_and_fetch", "probe", "AWVS API 扫描")
    pipeline.run()


def verify(job, folder):
    from sunset_verify import pipeline
    from sunset_verify.config import VerifySettings
    for cls, method in [(pipeline.PocCollectorAgent, "run"), (pipeline.SandboxExecutorAgent, "run"),
                        (pipeline.EvidenceJudgeAgent, "run"), (pipeline.VerificationReporterAgent, "write_run")]:
        def wrap(original):
            def observed(self, *args, **kwargs):
                with stage(self.name, self.codename):
                    return original(self, *args, **kwargs)
            return observed
        setattr(cls, method, wrap(getattr(cls, method)))
    target = job["verifyUrl"]
    settings = VerifySettings(mode=job["mode"], target_base=target if job["mode"] == "zip" else "",
                              insecure=False, allow_hosts=[urlsplit(target).hostname])
    pipeline.verify_result(folder / "scan", settings)


if __name__ == "__main__":
    repo, folder = map(Path, sys.argv[1:3])
    sys.path[:0] = [str(repo / "VulnCatcher-ver5"), str(repo / "VulnCatcher-Verify")]
    job = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    try:
        (verify if sys.argv[3] == "verify" else scan)(job, folder)
    except Exception as exc:
        event("error", "执行中断", "failed", f"{type(exc).__name__} · {exc}")
        sys.exit(1)
