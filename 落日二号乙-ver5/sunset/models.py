"""落日二号 数据模型。

设计原则：
- 所有模型都可直接 JSON 序列化，便于管线落盘与复现；
- Finding / POC 字段与 AutoCVE 的 finding 契约保持兼容（vulnerability_type、
  exploit_chain、poc、cve_justification 等），但额外带有证据等级与安全标记；
- 「源码闭环」不等于「动态验证」：本管线不执行 POC，因此 verdict 默认 candidate。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _plain(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


@dataclass
class SourceFile:
    rel_path: str
    size: int
    lines: int
    language: str
    sha256: str
    is_text: bool = True
    trust: str = "untrusted"
    excluded_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class Endpoint:
    path: str
    method: str
    file: str
    line: int
    framework: str = "unknown"
    handler: str = ""
    params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class TaintOrigin:
    """一次污点赋值/传播记录，用于还原 source→sink 链。"""

    var: str
    line: int
    expression: str
    kind: str = ""
    name: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class ChainStep:
    step: int
    location: str
    description: str
    data_state: str = ""
    bypass_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class Candidate:
    candidate_id: str
    vuln_type: str
    file: str
    line_start: int
    line_end: int
    rule_id: str
    sink: str
    source_kind: str
    source_name: str
    endpoint: str
    http_method: str
    code_snippet: str
    tainted_expression: str
    chain: list[ChainStep] = field(default_factory=list)
    sanitized: bool = False
    severity: str = "high"
    confidence: float = 0.6
    origin: str = "rule"
    notes: list[str] = field(default_factory=list)
    # 文本覆盖：LLM 深挖候选带入模型给出的完整论证。
    title: str = ""
    description: str = ""
    impact: str = ""
    cve_justification: str = ""
    suggestion: str = ""
    verification_notes: str = ""
    poc_hint: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class PocPlan:
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    payload: str = ""
    impact: str = ""
    cve_justification: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    safety: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class Finding:
    finding_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    source: str
    sink: str
    suggestion: str
    confidence: float
    needs_verification: bool
    verdict: str
    exploit_chain: list[ChainStep]
    poc: PocPlan
    impact: str
    cve_justification: str
    verification_notes: str
    endpoint: str = ""
    http_method: str = ""
    origin: str = "rule"
    evidence_level: str = "static_closed"
    external_evidence: list[dict[str, Any]] = field(default_factory=list)
    safety: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class SecondOrderChain:
    chain_id: str
    vuln_type: str
    file: str
    store_line: int
    read_line: int
    sink_line: int
    storage: str
    storage_key: str
    source_kind: str
    source_name: str
    endpoint_store: str
    endpoint_trigger: str
    chain: list[ChainStep] = field(default_factory=list)
    confidence: float = 0.7
    notes: list[str] = field(default_factory=list)
    poc: PocPlan | None = None

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class InjectionSignal:
    file: str
    line: int
    category: str
    severity: str
    pattern: str
    excerpt: str
    action: str = "enveloped"

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class Project:
    zip_path: str
    zip_sha256: str
    root: str
    extracted_dir: str
    files: list[SourceFile] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    input_mode: str = "zip"
    target_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)


@dataclass
class RunResult:
    run_id: str
    project: Project
    findings: list[Finding] = field(default_factory=list)
    second_order: list[SecondOrderChain] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    injection_signals: list[InjectionSignal] = field(default_factory=list)
    awvs_imported: list[dict[str, Any]] = field(default_factory=list)
    awvs_correlations: list[dict[str, Any]] = field(default_factory=list)
    llm_usage: list[dict[str, Any]] = field(default_factory=list)
    stage_log: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    logic_assessments: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _plain(self.__dict__)
