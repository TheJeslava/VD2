"""漏洞类型taxonomy。

目标：AutoCVE finding 中出现过的漏洞类型一个不少，同时补充 OWASP Benchmark /
常见 Web 审计会遇到的类型。类型名是管线内部与报告中的规范名；别名统一归并。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnType:
    name: str
    label_zh: str
    cwe: str
    default_severity: str
    family: str
    poc_template: str
    cve_grade: bool = True
    description: str = ""


# 说明：前 12 项与 AutoCVE finding.vulnerability_type 对齐；其余为补充类型。
_TYPES: tuple[VulnType, ...] = (
    VulnType("command_injection", "OS 命令注入", "CWE-78", "critical", "injection", "command_injection",
             description="外部输入进入 shell/进程执行参数，攻击者可追加或替换系统命令。"),
    VulnType("sql_injection", "SQL 注入", "CWE-89", "critical", "injection", "sql_injection",
             description="外部输入以字符串拼接方式进入 SQL 语句，改变查询语义。"),
    VulnType("ssrf", "服务端请求伪造", "CWE-918", "high", "injection", "ssrf",
             description="外部输入控制服务端请求目标，可访问内网、云元数据或本地服务。"),
    VulnType("path_traversal", "路径穿越 / 任意文件读写", "CWE-22", "high", "file", "path_traversal",
             description="外部输入控制文件路径，可越出预期目录读取、写入或删除文件。"),
    VulnType("deserialization", "不安全反序列化", "CWE-502", "critical", "injection", "deserialization",
             description="不可信数据进入反序列化入口，可能导致 RCE 或对象状态篡改。"),
    VulnType("ssti", "服务端模板注入", "CWE-1336", "critical", "injection", "ssti",
             description="外部输入进入模板引擎表达式，可读取上下文甚至执行代码。"),
    VulnType("auth_bypass", "认证绕过", "CWE-287", "critical", "auth", "auth_bypass",
             description="认证流程可被跳过、伪造或降级，攻击者获得未授权身份。"),
    VulnType("idor", "越权 / IDOR", "CWE-639", "high", "auth", "idor",
             description="对象标识由客户端控制且缺少归属校验，可访问他人资源。"),
    VulnType("xxe", "XML 外部实体注入", "CWE-611", "high", "injection", "xxe",
             description="XML 解析器允许外部实体，可读取文件或发起 SSRF。"),
    VulnType("xss", "跨站脚本", "CWE-79", "high", "client", "xss",
             description="外部输入未编码进入 HTML/JS 上下文，可在受害者浏览器执行脚本。"),
    VulnType("business_logic", "业务逻辑漏洞", "CWE-840", "high", "logic", "generic",
             description="业务流程/状态机缺陷导致越权、绕过付费、重复领取等。"),
    VulnType("other", "其他高危问题", "CWE-693", "high", "other", "generic",
             description="不属于上述类型但具备明确安全影响的问题。"),

    # ---- 补充类型 ----
    VulnType("rce", "远程代码执行", "CWE-94", "critical", "injection", "command_injection",
             description="外部输入进入代码/表达式执行链路，直接执行攻击者代码。"),
    VulnType("code_injection", "代码注入", "CWE-94", "critical", "injection", "command_injection"),
    VulnType("expression_injection", "表达式注入", "CWE-917", "critical", "injection", "ssti"),
    VulnType("ldap_injection", "LDAP 注入", "CWE-90", "high", "injection", "ldap"),
    VulnType("xpath_injection", "XPath 注入", "CWE-643", "high", "injection", "xpath"),
    VulnType("open_redirect", "开放重定向", "CWE-601", "medium", "client", "open_redirect", False),
    VulnType("csrf", "跨站请求伪造", "CWE-352", "medium", "client", "csrf", False),
    VulnType("file_upload", "不安全文件上传", "CWE-434", "critical", "file", "file_upload"),
    VulnType("race_condition", "竞态条件", "CWE-367", "high", "logic", "generic"),
    VulnType("weak_crypto", "弱加密算法", "CWE-327", "medium", "crypto", "generic", False),
    VulnType("weak_hash", "弱哈希算法", "CWE-328", "medium", "crypto", "generic", False,
             description="使用 MD5/SHA1 等不具备抗碰撞/抗暴力能力的哈希算法处理安全敏感数据。"),
    VulnType("weak_random", "弱随机数", "CWE-330", "medium", "crypto", "generic", False),
    VulnType("hardcoded_secret", "硬编码凭据", "CWE-798", "high", "secrets", "generic"),
    VulnType("trust_boundary", "信任边界违规", "CWE-501", "medium", "logic", "generic", False),
    VulnType("log_injection", "日志注入", "CWE-117", "low", "other", "generic", False),
    VulnType("insecure_cookie", "不安全 Cookie", "CWE-614", "medium", "client", "generic", False),
    VulnType("information_disclosure", "信息泄露", "CWE-200", "medium", "other", "generic", False),
    VulnType("second_order_injection", "二次注入", "CWE-89", "critical", "second_order", "second_order",
             description="恶意输入先被持久化，之后从存储中读出并进入危险汇点。"),
    VulnType("prompt_injection", "LLM Prompt 注入", "CWE-1426", "high", "llm", "generic"),
)

VULN_TYPES: dict[str, VulnType] = {item.name: item for item in _TYPES}

ALIASES: dict[str, str] = {
    "template_injection": "ssti",
    "insecure_deserialization": "deserialization",
    "unsafe_deserialization": "deserialization",
    "arbitrary_file_read": "path_traversal",
    "arbitrary_file_write": "path_traversal",
    "file_read": "path_traversal",
    "file_write": "path_traversal",
    "os_command_injection": "command_injection",
    "cmdi": "command_injection",
    "sqli": "sql_injection",
    "xpathi": "xpath_injection",
    "ldapi": "ldap_injection",
    "weakrand": "weak_random",
    "weak_digest": "weak_hash",
    "hash": "weak_hash",
    "trustbound": "trust_boundary",
    "securecookie": "insecure_cookie",
    "auth_bypass_by_jwt": "auth_bypass",
    "broken_access_control": "idor",
    "business_logic_flaw": "business_logic",
}


def canonical(name: str) -> str:
    name = (name or "").strip().lower().replace(" ", "_").replace("-", "_")
    name = ALIASES.get(name, name)
    return name if name in VULN_TYPES else "other"


def meta(name: str) -> VulnType:
    return VULN_TYPES[canonical(name)]


def severity_for(name: str, floor: str = "high") -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    item = meta(name)
    return item.default_severity if order.get(item.default_severity, 0) >= order.get(floor, 0) else floor


def auto_cve_types() -> list[str]:
    return [item.name for item in _TYPES[:12]]


def all_types() -> list[str]:
    return [item.name for item in _TYPES]
