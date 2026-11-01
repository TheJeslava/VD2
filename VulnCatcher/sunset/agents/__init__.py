"""VulnCatcher agent 包。

命名刻意与 AutoCVE 的旧 agent 名完全区分；每个 agent 都是
「一次 LLM 调用 + 确定性后备」，不暴露任何工具。
"""

from .base import AgentContext, AgentResult, BaseAgent  # noqa: F401
from .candidate_screener import CandidateScreenerAgent  # noqa: F401
from .coordinator import CoordinatorAgent  # noqa: F401
from .deep_finder import DeepFinderAgent  # noqa: F401
from .poc_writer import PocWriterAgent  # noqa: F401
from .safety_guard import SafetyGuardAgent  # noqa: F401
from .second_order_analyzer import SecondOrderAnalyzerAgent  # noqa: F401
from .surface_mapper import SurfaceMapperAgent  # noqa: F401
from .vulnerability_analyzer import VulnerabilityAnalyzerAgent  # noqa: F401

__all__ = [
    "AgentContext", "AgentResult", "BaseAgent",
    "CoordinatorAgent", "SecondOrderAnalyzerAgent", "VulnerabilityAnalyzerAgent", "CandidateScreenerAgent", "PocWriterAgent",
    "SurfaceMapperAgent", "SafetyGuardAgent", "DeepFinderAgent",
]
