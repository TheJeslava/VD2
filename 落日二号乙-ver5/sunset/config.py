"""运行配置。

LLM 是可选的：没有 key 时管线仍完成安全防护、测绘和报告流程；zip 模式不会产生静态候选。
有 key 时 agent 会在「已收集、已隔离」的上下文上做一次 JSON 发现/补全。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    input_mode: str = "zip"  # zip / url
    target_url: str = ""
    awvs_local: bool = False
    awvs_manifest: str = ""
    target_insecure_tls: bool = True
    llm_mode: str = "auto"  # auto / on / off
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com/v1"
    llm_model: str = "deepseek-chat"
    llm_timeout: int = 120
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096
    min_severity: str = "high"
    min_confidence: float = 0.6
    max_findings: int = 30
    include_config: bool = True
    max_llm_findings: int = 12
    # LLM-finding（DeepFinder）：模仿 AutoCVE Finding 的源码发现阶段。
    # auto：LLM 启用时执行；on：强制（仍需 API key）；off：关闭。
    llm_finding: str = "auto"
    llm_finding_budget: int = 36000  # 送入模型的源码字符预算
    llm_finding_max_files: int = 12
    awvs_url: str = ""
    awvs_key: str = ""
    awvs_profile: str = ""
    awvs_report: str = ""
    awvs_target: str = ""
    awvs_wait: int = 0
    awvs_insecure_tls: bool = False
    output_dir: Path | None = None
    work_dir: Path | None = None
    quiet: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def llm_enabled(self) -> bool:
        return self.llm_mode != "off" and bool(self.llm_api_key)

    @property
    def llm_finding_enabled(self) -> bool:
        return self.llm_finding != "off" and self.llm_enabled

    def public(self) -> dict:
        return {
            "input_mode": self.input_mode,
            "target_url": self.target_url,
            "awvs_local": self.awvs_local,
            "awvs_manifest": self.awvs_manifest,
            "llm_mode": self.llm_mode,
            "llm_enabled": self.llm_enabled,
            "llm_model": self.llm_model,
            "llm_base_url": self.llm_base_url,
            "llm_finding": self.llm_finding,
            "llm_finding_enabled": self.llm_finding_enabled,
            "llm_finding_budget": self.llm_finding_budget,
            "min_severity": self.min_severity,
            "min_confidence": self.min_confidence,
            "max_findings": self.max_findings,
            "include_config": self.include_config,
            "awvs_enabled": bool(self.awvs_url and self.awvs_key) or bool(self.awvs_report),
            "awvs_report": self.awvs_report,
            "output_dir": str(self.output_dir) if self.output_dir else "",
        }


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def resolve_settings(args) -> Settings:
    settings = Settings()
    env_file = getattr(args, "env_file", "") or os.environ.get("SUNSET_ENV_FILE", "")
    file_values: dict[str, str] = {}
    if env_file:
        file_values = parse_env_file(Path(env_file))
    else:
        default_env = Path.cwd() / ".env"
        if default_env.is_file():
            file_values = parse_env_file(default_env)

    def pick(*names: str, default: str = "") -> str:
        for name in names:
            value = os.environ.get(name)
            if value:
                return value
            if name in file_values:
                return file_values[name]
        return default

    settings.llm_mode = getattr(args, "llm", None) or pick("SUNSET_LLM_MODE", default="auto")
    settings.llm_api_key = pick("SUNSET_LLM_API_KEY", "LLM_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY")
    settings.llm_base_url = pick("SUNSET_LLM_BASE_URL", "LLM_BASE_URL", default=settings.llm_base_url)
    settings.llm_model = pick("SUNSET_LLM_MODEL", "LLM_MODEL", default=settings.llm_model)
    try:
        settings.llm_timeout = int(pick("SUNSET_LLM_TIMEOUT", "LLM_TIMEOUT", default=str(settings.llm_timeout)))
    except ValueError:
        pass
    try:
        settings.llm_max_tokens = int(pick("SUNSET_LLM_MAX_TOKENS", "LLM_MAX_TOKENS", default=str(settings.llm_max_tokens)))
    except ValueError:
        pass
    settings.llm_finding = getattr(args, "llm_finding", None) or pick(
        "SUNSET_LLM_FINDING", default=settings.llm_finding)
    if settings.llm_finding not in {"auto", "on", "off"}:
        settings.llm_finding = "auto"
    try:
        settings.llm_finding_budget = int(pick(
            "SUNSET_LLM_FINDING_BUDGET", default=str(settings.llm_finding_budget)))
    except ValueError:
        pass
    if getattr(args, "llm_finding_budget", None):
        settings.llm_finding_budget = int(args.llm_finding_budget)
    settings.llm_finding_budget = max(4000, min(44000, settings.llm_finding_budget))
    try:
        settings.llm_finding_max_files = int(pick(
            "SUNSET_LLM_FINDING_MAX_FILES", default=str(settings.llm_finding_max_files)))
    except ValueError:
        pass
    settings.llm_finding_max_files = max(1, min(40, settings.llm_finding_max_files))

    for attr, env_names in {
        "min_severity": ("SUNSET_MIN_SEVERITY",),
        "max_findings": ("SUNSET_MAX_FINDINGS",),
        "max_llm_findings": ("SUNSET_MAX_LLM_FINDINGS",),
        "awvs_url": ("SUNSET_AWVS_URL", "AWVS_URL"),
        "awvs_key": ("SUNSET_AWVS_KEY", "AWVS_API_KEY"),
        "awvs_profile": ("SUNSET_AWVS_PROFILE", "AWVS_PROFILE"),
        "awvs_report": ("SUNSET_AWVS_REPORT", "AWVS_REPORT"),
        "awvs_target": ("SUNSET_AWVS_TARGET", "AWVS_TARGET"),
        "target_url": ("SUNSET_TARGET_URL", "TARGET_URL"),
        "awvs_manifest": ("SUNSET_AWVS_MANIFEST", "AWVS_MANIFEST"),
        "input_mode": ("SUNSET_INPUT_MODE",),
    }.items():
        value = pick(*env_names)
        if value:
            setattr(settings, attr, value)
    try:
        settings.min_confidence = float(pick("SUNSET_MIN_CONFIDENCE", default=str(settings.min_confidence)))
    except ValueError:
        pass
    if getattr(args, "max_findings", None):
        settings.max_findings = int(args.max_findings)
    if getattr(args, "min_severity", None):
        settings.min_severity = args.min_severity
    if getattr(args, "min_confidence", None) is not None:
        settings.min_confidence = float(args.min_confidence)
    if getattr(args, "include_config", None) is not None:
        settings.include_config = bool(args.include_config)
    if getattr(args, "awvs_url", None):
        settings.awvs_url = args.awvs_url
    if getattr(args, "awvs_key", None):
        settings.awvs_key = args.awvs_key
    if getattr(args, "awvs_profile", None):
        settings.awvs_profile = args.awvs_profile
    if getattr(args, "awvs_report", None):
        settings.awvs_report = args.awvs_report
    if getattr(args, "awvs_target", None):
        settings.awvs_target = args.awvs_target
    if getattr(args, "awvs_local", False):
        settings.awvs_local = True
    if getattr(args, "awvs_manifest", None):
        settings.awvs_manifest = args.awvs_manifest
    if getattr(args, "mode", None):
        settings.input_mode = str(args.mode).lower()
    if getattr(args, "target", None):
        settings.target_url = str(args.target)
    if getattr(args, "target_insecure", False):
        settings.target_insecure_tls = True
    if getattr(args, "awvs_wait", None) is not None:
        settings.awvs_wait = int(args.awvs_wait)
    if getattr(args, "awvs_insecure", None):
        settings.awvs_insecure_tls = True
    elif pick("SUNSET_AWVS_INSECURE_TLS", "AWVS_INSECURE_TLS").lower() in {"1", "true", "yes"}:
        settings.awvs_insecure_tls = True
    if getattr(args, "out", None):
        settings.output_dir = Path(args.out)
    if getattr(args, "work_dir", None):
        settings.work_dir = Path(args.work_dir)
    settings.quiet = bool(getattr(args, "quiet", False))

    if settings.llm_mode == "on" and not settings.llm_api_key:
        settings.llm_mode = "off"
    return settings
