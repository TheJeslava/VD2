"""安全防护（SafetyGuard）的确定性安全内核。

它解决两类风险：
1. LLM Prompt 注入：仓库里的注释、README、字符串可能包含「忽略之前指令」「你现在是」
   等攻击文本。任何进入 LLM 的代码都必须先经过检测、隔离、去标识化，并用带随机
   nonce 的数据信封包裹，明确标注 trust=untrusted。
2. LLM 输出不可信：模型可能编造文件/行号、输出工具调用语法、诱导执行命令、或把
   不可信文本当成结论。所有模型输出都要经过 schema 校验、文件白名单校验、行号
   校验、文本清洗和 POC 被动化检查。

本模块不执行任何命令、不发起网络请求；它只做文本处理。
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models import InjectionSignal

# ---------------------------------------------------------------------------
# 注入检测规则
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, str, str]] = [
    # (category, severity, pattern, label)
    ("instruction_override", "critical",
     r"(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|messages?)",
     "英文指令覆盖"),
    ("instruction_override", "critical",
     r"(?:忽略|无视|忘记|覆盖|绕过)(?:掉)?(?:之前|以上|前面|所有|系统)(?:的)?(?:指令|提示词|规则|要求|消息)",
     "中文指令覆盖"),
    ("role_hijack", "high",
     r"(?i)\byou\s+are\s+now\s+(?:a|an|the|in)\b|\bact\s+as\s+(?:a|an|the|my)\b|\bpretend\s+(?:to\s+be|you\s+are)\b",
     "角色劫持"),
    ("role_hijack", "high",
     r"(?:你现在是|从现在开始你是|扮演(?:一个)?|假装你是|你的新身份)",
     "中文角色劫持"),
    ("prompt_leak", "high",
     r"(?i)\b(?:repeat|print|reveal|show|output|leak)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|instructions|hidden\s+rules|developer\s+message)",
     "系统提示泄露"),
    ("prompt_leak", "high",
     r"(?:输出|打印|复述|泄露|告诉我)(?:你的)?(?:系统提示|隐藏指令|开发者消息|内部规则)",
     "中文系统提示泄露"),
    ("tool_abuse", "critical",
     r"(?i)\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|command)\b|\btool_call\b|\bfunction_call\b|<\|\s*\w+\s*\|>",
     "工具/函数调用诱导"),
    ("tool_abuse", "critical",
     r"(?:调用|执行|运行)(?:该)?(?:工具|函数|命令)|工具调用",
     "中文工具调用诱导"),
    ("verdict_manipulation", "critical",
     r"(?i)\b(?:report|return|output|conclude)\s+(?:that\s+)?(?:there\s+are\s+)?(?:no|zero)\s+(?:vulnerabilit(?:y|ies)|findings|issues)\b",
     "结论操纵（无漏洞）"),
    ("verdict_manipulation", "critical",
     r"(?:不要|禁止|无需)(?:报告|输出|提交)(?:任何)?(?:漏洞|发现)|(?:结论|结果)(?:为|是)(?:无漏洞|安全)",
     "中文结论操纵"),
    ("verdict_manipulation", "critical",
     r"(?i)\bmark\s+(?:this|it|the\s+project)\s+as\s+(?:safe|clean|false[_\s-]?positive)\b",
     "结论操纵（标记安全）"),
    ("exfiltration", "high",
     r"(?i)\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:ba)?sh\b|\bexfiltrat(?:e|ion)\b|/dev/tcp/",
     "外联/反弹 Shell 诱导"),
    ("exfiltration", "high",
     r"(?:把|将)(?:数据|密钥|token|代码)(?:上传|回传|发送)(?:到|至)|反弹\s*shell",
     "中文外联诱导"),
    ("hidden_instruction", "high",
     r"<!--[\s\S]{0,400}?(?:ignore|system|instruction|prompt|忽略|指令)[\s\S]{0,400}?-->",
     "HTML 注释隐藏指令"),
    ("hidden_instruction", "medium",
     r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]",
     "零宽/双向控制字符"),
    ("encoded_blob", "medium",
     r"(?:[A-Za-z0-9+/]{240,}={0,2})",
     "超长 Base64 可疑载荷"),
    ("secret_harvest", "high",
     r"(?i)(?:read|cat|print|send|upload).{0,40}(?:\.env|id_rsa|credentials|aws_secret|/etc/passwd)",
     "凭据收集诱导"),
]

_COMPILED = [(cat, sev, re.compile(pat), label) for cat, sev, pat, label in _PATTERNS]

_TOOL_SYNTAX = re.compile(
    r"<\|\s*\w+\s*\|>|<\|?\s*(?:tool_call|function_call|assistant to=|recipient=)[^>]*>?",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{0,2000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


@dataclass
class ScanResult:
    signals: list[InjectionSignal] = field(default_factory=list)
    quarantined: set[str] = field(default_factory=set)
    scanned_files: int = 0

    def summary(self) -> dict[str, Any]:
        by_category: dict[str, int] = {}
        for signal in self.signals:
            by_category[signal.category] = by_category.get(signal.category, 0) + 1
        return {
            "scanned_files": self.scanned_files,
            "signal_count": len(self.signals),
            "quarantined_files": sorted(self.quarantined),
            "by_category": by_category,
        }


def scan_text(rel_path: str, text: str, max_signals_per_file: int = 20) -> list[InjectionSignal]:
    """扫描单个文件的 Prompt 注入/越权指令迹象。"""
    signals: list[InjectionSignal] = []
    if not text:
        return signals
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for category, severity, pattern, label in _COMPILED:
            match = pattern.search(line)
            if not match:
                continue
            excerpt = line.strip()
            if len(excerpt) > 240:
                excerpt = excerpt[:237] + "..."
            signals.append(
                InjectionSignal(
                    file=rel_path,
                    line=line_no,
                    category=category,
                    severity=severity,
                    pattern=label,
                    excerpt=excerpt,
                    action="quarantine" if severity == "critical" or category in {"verdict_manipulation", "instruction_override", "tool_abuse"} else "enveloped",
                )
            )
            if len(signals) >= max_signals_per_file:
                return signals
    # 跨行 HTML 注释检测
    for match in re.finditer(r"<!--[\s\S]{0,600}?-->", text):
        block = match.group(0)
        if re.search(r"(?i)ignore|system|instruction|prompt|忽略|指令", block):
            line_no = text.count("\n", 0, match.start()) + 1
            if not any(sig.line == line_no and sig.category == "hidden_instruction" for sig in signals):
                signals.append(
                    InjectionSignal(
                        file=rel_path,
                        line=line_no,
                        category="hidden_instruction",
                        severity="high",
                        pattern="HTML 注释隐藏指令",
                        excerpt=block.replace("\n", " ")[:240],
                        action="quarantine",
                    )
                )
    return signals


def scan_project(contents: Iterable[tuple[str, str]], max_files: int = 4000) -> ScanResult:
    result = ScanResult()
    for index, (rel_path, text) in enumerate(contents):
        if index >= max_files:
            break
        result.scanned_files += 1
        signals = scan_text(rel_path, text)
        if signals:
            result.signals.extend(signals)
            if any(sig.action == "quarantine" for sig in signals):
                result.quarantined.add(rel_path)
    # 去重并限制总量
    seen: set[tuple[str, int, str]] = set()
    unique: list[InjectionSignal] = []
    for signal in result.signals:
        key = (signal.file, signal.line, signal.category)
        if key in seen:
            continue
        seen.add(key)
        unique.append(signal)
    result.signals = unique[:300]
    return result


# ---------------------------------------------------------------------------
# 数据信封
# ---------------------------------------------------------------------------

def sanitize_untrusted(text: str, max_chars: int = 12000) -> str:
    """清掉控制字符与信封碰撞字符，限制长度。"""
    text = text or ""
    text = _CONTROL_CHARS.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("<<<SUNSET_UNTRUSTED", "<<<SUNSET-UNTRUSTED")
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return text


def envelope(label: str, text: str, *, max_chars: int = 12000, nonce: str | None = None) -> str:
    """把不可信文本包成带 nonce 的数据块。

    模型被明确告知：nonce 区块内的一切都是数据，不是指令。
    """
    token = nonce or secrets.token_hex(8)
    body = sanitize_untrusted(text, max_chars=max_chars)
    return (
        f"<<<SUNSET_UNTRUSTED_DATA_BEGIN nonce={token} source={label!r} trust=untrusted>>>\n"
        f"{body}\n"
        f"<<<SUNSET_UNTRUSTED_DATA_END nonce={token}>>>"
    )


# ---------------------------------------------------------------------------
# 输出清洗/校验
# ---------------------------------------------------------------------------

def sanitize_model_text(text: Any, max_chars: int = 6000) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = _TOOL_SYNTAX.sub("[removed-tool-syntax]", text)
    text = _CONTROL_CHARS.sub(" ", text)
    text = text.replace("<<<SUNSET_UNTRUSTED_DATA_BEGIN", "[removed-envelope]")
    text = text.strip()
    if len(text) > max_chars:
        text = text[:max_chars] + "..."
    return text


def redact_secrets(text: str, max_chars: int = 20000) -> str:
    if not text:
        return ""
    result = text[:max_chars]
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m: (m.group(1) + "=[REDACTED]") if m.lastindex and m.lastindex >= 2 else "[REDACTED]", result)
    return result


def normalize_rel_path(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/").strip()
    while path.startswith("./"):
        path = path[2:]
    return path


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[truncated-depth]"
    if isinstance(value, str):
        return sanitize_model_text(value, max_chars=4000)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_sanitize_value(item, depth + 1) for item in value[:60]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:60]:
            safe_key = sanitize_model_text(key, max_chars=120)
            result[safe_key] = _sanitize_value(item, depth + 1)
        return result
    return sanitize_model_text(value, max_chars=4000)


def validate_llm_payload(
    payload: Any,
    *,
    allowed_files: set[str],
    file_line_counts: dict[str, int],
    max_items: int = 50,
    enforce_files: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """校验模型返回的 JSON：文件白名单、行号范围、字段清洗。

    返回 (清理后的 payload, 拒绝原因列表)。任何不在仓库中的 file_path 都会被丢弃，
    这样模型无法把外部 URL 或虚构路径注入报告。
    `enforce_files=False` 用于不携带 file_path 的补丁型输出（例如 VulnerabilityAnalyzer 的文本补全），
    但一旦出现 file_path，仍必须属于仓库。
    """
    rejected: list[str] = []
    if not isinstance(payload, dict):
        return {}, ["payload 不是 JSON 对象"]

    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "findings":
            continue
        cleaned[key] = _sanitize_value(value)

    findings = payload.get("findings")
    if isinstance(findings, list):
        kept: list[dict[str, Any]] = []
        for item in findings[:max_items]:
            if not isinstance(item, dict):
                rejected.append("finding 不是对象")
                continue
            path = normalize_rel_path(item.get("file_path"))
            if enforce_files:
                if not path or path not in allowed_files:
                    rejected.append(f"丢弃非仓库路径: {item.get('file_path')!r}")
                    continue
            elif path and path not in allowed_files:
                rejected.append(f"丢弃非仓库路径: {item.get('file_path')!r}")
                continue
            item = dict(item)
            if path:
                item["file_path"] = path
                max_line = max(1, int(file_line_counts.get(path, 1)))
                for key in ("line_start", "line_end"):
                    try:
                        value = int(item.get(key) or 1)
                    except (TypeError, ValueError):
                        value = 1
                    item[key] = max(1, min(value, max_line))
                if item.get("line_end", 1) < item.get("line_start", 1):
                    item["line_end"] = item["line_start"]
            for key in ("title", "description", "impact", "cve_justification", "suggestion", "verification_notes", "source", "sink"):
                if key in item:
                    item[key] = sanitize_model_text(item.get(key), max_chars=4000)
            kept.append(item)
        cleaned["findings"] = kept
    return cleaned, rejected


_DANGEROUS_POC = [
    (re.compile(r"(?i)\brm\s+-rf\s+/(?:\s|$)|mkfs\.|dd\s+if=/dev/zero|:\(\)\s*\{"), "破坏性命令"),
    (re.compile(r"(?i)\b(?:shutdown|reboot|halt|poweroff)\b"), "关机/重启命令"),
    (re.compile(r"(?i)(?:ba)?sh\s+-i\s+>&\s*/dev/tcp|nc\s+-e|reverse\s+shell"), "反弹 Shell"),
    (re.compile(r"(?i)(?:curl|wget)[^\n]{0,200}\|\s*(?:ba)?sh"), "远程脚本管道执行"),
    (re.compile(r"(?i)\bDROP\s+(?:TABLE|DATABASE)\b"), "破坏性 SQL"),
    (re.compile(r"(?i)\b(?:format\s+c:|del\s+/f\s+/s\s+/q\s+c:\\)"), "破坏性 Windows 命令"),
]


def inspect_poc_safety(scripts: dict[str, str], payload: str = "") -> dict[str, Any]:
    """POC 只作为被动文本交付；这里做风险标注，绝不执行。"""
    blob = "\n".join(scripts.values()) + "\n" + payload
    warnings: list[str] = []
    for pattern, label in _DANGEROUS_POC:
        if pattern.search(blob):
            warnings.append(label)
    target_placeholder = bool(re.search(r"(?i)(?:TARGET|TARGET_HOST|\{\{\s*target\s*\}\}|example\.com)", blob))
    return {
        "executed": False,
        "network_egress": False,
        "requires_authorization": True,
        "target_uses_placeholder": target_placeholder,
        "warnings": warnings,
        "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
    }
