"""VulnCatcher。

两条可选管线：
- zip：LLM 自主源码发现，最终产出 finding + POC + 报告；
- url：AWVS 提出动态候选，同一套 agent 生成 POC + 报告。

不做沙箱搭建、不自动 POC 验证；agent 之间不提供工具调用，所有文件读取/索引/
攻击面测绘由 Python 完成。内置 SafetyGuard 与 SecondOrderAnalyzer。
"""

__version__ = "1.0.0"

AGENT_ROSTER = [
    ("Coordinator", "管线协调", "总控：合并证据、去重、最终裁决与摘要"),
    ("SurfaceMapper", "攻击面测绘", "范围与攻击面：框架、路由、入口、热点文件"),
    ("DeepFinder", "LLM 深挖", "LLM-finding：模仿 AutoCVE Finding，无工具、单次调用自主发现漏洞"),
    ("CandidateScreener", "候选筛选", "候选筛选：LLM/AWVS 候选排序、证据缺口、LLM 复核"),
    ("VulnerabilityAnalyzer", "漏洞分析", "深挖：把候选补成完整 source→sink 链与可利用性判断"),
    ("SecondOrderAnalyzer", "二次注入分析", "二次注入：持久化→回读→危险汇点的专属链路"),
    ("SafetyGuard", "安全防护", "安全防护：Prompt 注入隔离、不可信输出校验、POC 被动化"),
    ("PocWriter", "POC 生成", "POC：按漏洞类型生成可复现请求/脚本（只写不跑）"),
]

__all__ = ["__version__", "AGENT_ROSTER"]
