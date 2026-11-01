"""非 Java 语言的轻量规则 + 跨语言配置/凭据检查。

目标不是替代编译器，而是让 PHP / Python / JS / Go / .NET / Ruby 也能产出
source→sink 候选，覆盖 AutoCVE finding 的主流类型。Java 由 rules.java 专门处理。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Candidate, ChainStep, Endpoint, TaintOrigin
from ..taxonomy import meta
from .common import strip_comments, var_reference_pattern


@dataclass
class SimpleSource:
    kind: str
    name: str
    line: int
    expression: str


@dataclass
class LanguageRules:
    sources: list[tuple[re.Pattern[str], str, str]] = field(default_factory=list)
    sinks: list[tuple[re.Pattern[str], str, str]] = field(default_factory=list)


def _lang_rules(language: str) -> LanguageRules:
    rules = LanguageRules()
    if language == "php":
        rules.sources = [
            (re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*['\"]([^'\"]+)['\"]"), "query", "PHP 超全局变量"),
            (re.compile(r"php://input"), "body", "PHP 请求体"),
            (re.compile(r"\$_FILES\s*\[\s*['\"]([^'\"]+)['\"]"), "upload", "PHP 上传文件"),
        ]
        rules.sinks = [
            (re.compile(r"\b(?:eval|assert)\s*\("), "rce", "php-eval"),
            (re.compile(r"\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\("), "command_injection", "php-exec"),
            (re.compile(r"\b(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\("), "sql_injection", "php-sql"),
            (re.compile(r"\bunserialize\s*\("), "deserialization", "php-unserialize"),
            (re.compile(r"\b(?:include|require)(?:_once)?\s*\(?"), "path_traversal", "php-include"),
            (re.compile(r"\b(?:file_get_contents|fopen|readfile|unlink|file_put_contents|copy|rename)\s*\("), "path_traversal", "php-file"),
            (re.compile(r"\bheader\s*\(\s*['\"]Location"), "open_redirect", "php-redirect"),
            (re.compile(r"\bmove_uploaded_file\s*\("), "file_upload", "php-upload"),
            (re.compile(r"\b(?:echo|print)\b"), "xss", "php-output"),
        ]
    elif language == "python":
        rules.sources = [
            (re.compile(r"request\.(?:args|form|values|json|files|headers|cookies)\.get\s*\(\s*['\"]([^'\"]+)['\"]"), "query", "Flask/Django 请求参数"),
            (re.compile(r"request\.(?:args|form|values|json|files|headers|cookies)\s*\[\s*['\"]([^'\"]+)['\"]"), "query", "Flask/Django 请求参数"),
            (re.compile(r"request\.(?:GET|POST|body|data)\b"), "query", "Django 请求参数"),
            (re.compile(r"\binput\s*\("), "query", "标准输入"),
        ]
        rules.sinks = [
            (re.compile(r"\b(?:eval|exec)\s*\("), "rce", "python-eval"),
            (re.compile(r"\bos\.(?:system|popen)\s*\("), "command_injection", "python-os"),
            (re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\("), "command_injection", "python-subprocess"),
            (re.compile(r"(?:cursor|conn|db|session)\.(?:execute|executemany|executescript)\s*\("), "sql_injection", "python-sql"),
            (re.compile(r"\b(?:pickle|marshal|dill)\.loads?\s*\("), "deserialization", "python-pickle"),
            (re.compile(r"\byaml\.load\s*\("), "deserialization", "python-yaml"),
            (re.compile(r"\b(?:render_template_string|Template)\s*\("), "ssti", "python-ssti"),
            (re.compile(r"\b(?:open|pathlib\.Path)\s*\("), "path_traversal", "python-file"),
            (re.compile(r"\b(?:requests|httpx)\.(?:get|post|put|request)\s*\("), "ssrf", "python-http"),
            (re.compile(r"\bredirect\s*\("), "open_redirect", "python-redirect"),
            (re.compile(r"\b(?:send_file|send_from_directory)\s*\("), "path_traversal", "python-sendfile"),
            (re.compile(r"\b(?:render_template|Markup|HttpResponse)\s*\("), "xss", "python-output"),
        ]
    elif language in {"javascript", "typescript"}:
        rules.sources = [
            (re.compile(r"req\.(?:query|body|params|cookies)\.([A-Za-z_]\w*)"), "query", "Express 请求参数"),
            (re.compile(r"req\.(?:query|body|params|cookies)\s*\[\s*['\"]([^'\"]+)['\"]"), "query", "Express 请求参数"),
            (re.compile(r"request\.(?:query|body|params)\.([A-Za-z_]\w*)"), "query", "HTTP 请求参数"),
        ]
        rules.sinks = [
            (re.compile(r"\beval\s*\("), "rce", "js-eval"),
            (re.compile(r"\bnew\s+Function\s*\("), "rce", "js-function"),
            (re.compile(r"child_process\.(?:exec|execSync|spawn|spawnSync)\s*\("), "command_injection", "js-childprocess"),
            (re.compile(r"\.(?:query|execute)\s*\("), "sql_injection", "js-sql"),
            (re.compile(r"\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink)|sendFile)\s*\("), "path_traversal", "js-file"),
            (re.compile(r"\b(?:axios|fetch|request|https?)\.(?:get|post|request)?\s*\("), "ssrf", "js-http"),
            (re.compile(r"\.innerHTML\s*=|document\.write\s*\(|res\.send\s*\("), "xss", "js-dom"),
            (re.compile(r"\b(?:res\.redirect|redirect)\s*\("), "open_redirect", "js-redirect"),
            (re.compile(r"\b(?:unserialize|node-serialize|deserialize)\s*\("), "deserialization", "js-deserialize"),
            (re.compile(r"\b(?:render|compile)\s*\("), "ssti", "js-template"),
        ]
    elif language == "go":
        rules.sources = [
            (re.compile(r"r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|Header\.Get)\s*\(\s*\"([^\"]+)\""), "query", "Go HTTP 参数"),
            (re.compile(r"c\.(?:Query|PostForm|Param)\s*\(\s*\"([^\"]+)\""), "query", "Gin 参数"),
        ]
        rules.sinks = [
            (re.compile(r"\bexec\.Command\s*\("), "command_injection", "go-exec"),
            (re.compile(r"\b(?:db|tx|conn)\.(?:Query|QueryRow|Exec)\s*\("), "sql_injection", "go-sql"),
            (re.compile(r"\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Remove)\s*\("), "path_traversal", "go-file"),
            (re.compile(r"\b(?:http\.Get|http\.Post|client\.Do)\s*\("), "ssrf", "go-http"),
            (re.compile(r"\btemplate\.(?:HTML|JS|URL)\s*\("), "xss", "go-template"),
            (re.compile(r"\b(?:yaml|json)\.Unmarshal\s*\("), "deserialization", "go-unmarshal"),
            (re.compile(r"\bhttp\.Redirect\s*\("), "open_redirect", "go-redirect"),
        ]
    elif language in {"csharp", "aspx"}:
        rules.sources = [
            (re.compile(r"Request\.(?:QueryString|Form|Headers|Cookies)\s*\[\s*\"([^\"]+)\""), "query", "ASP.NET 请求参数"),
            (re.compile(r"Request\.(?:Query|Form|Headers|Cookies)\b"), "query", "ASP.NET 请求参数"),
        ]
        rules.sinks = [
            (re.compile(r"\bProcess\.Start\s*\("), "command_injection", "dotnet-process"),
            (re.compile(r"\b(?:SqlCommand|OleDbCommand|MySqlCommand)\s*\("), "sql_injection", "dotnet-sql"),
            (re.compile(r"\bFile\.(?:ReadAllText|ReadAllBytes|WriteAllText|Delete|Open)\s*\("), "path_traversal", "dotnet-file"),
            (re.compile(r"\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter).*Deserialize\s*\("), "deserialization", "dotnet-deserialize"),
            (re.compile(r"\b(?:XmlDocument|XmlReader|XDocument)\.(?:Load|Parse)\s*\("), "xxe", "dotnet-xxe"),
            (re.compile(r"\b(?:HttpClient|WebRequest|WebClient)\b"), "ssrf", "dotnet-http"),
            (re.compile(r"\bResponse\.Redirect\s*\("), "open_redirect", "dotnet-redirect"),
            (re.compile(r"\bResponse\.Write\s*\("), "xss", "dotnet-output"),
        ]
    elif language == "ruby":
        rules.sources = [
            (re.compile(r"params\s*\[\s*:([A-Za-z_]\w*)\s*\]"), "query", "Rails 参数"),
            (re.compile(r"params\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"), "query", "Rails 参数"),
        ]
        rules.sinks = [
            (re.compile(r"\b(?:eval|instance_eval|class_eval)\s*\("), "rce", "ruby-eval"),
            (re.compile(r"\b(?:system|exec|spawn|`)\s*"), "command_injection", "ruby-exec"),
            (re.compile(r"\.(?:where|find_by_sql|execute)\s*\("), "sql_injection", "ruby-sql"),
            (re.compile(r"\b(?:File\.(?:read|write|delete|open)|IO\.read)\s*\("), "path_traversal", "ruby-file"),
            (re.compile(r"\b(?:Marshal\.load|YAML\.load)\s*\("), "deserialization", "ruby-deserialize"),
            (re.compile(r"\b(?:redirect_to|render)\s*\("), "open_redirect", "ruby-redirect"),
            (re.compile(r"\b(?:Net::HTTP|open-uri|HTTParty)\b"), "ssrf", "ruby-http"),
        ]
    return rules


def _assignment_target(line: str, match_end: int) -> tuple[str, str] | None:
    """在 source 出现的位置向前找 `var =` / `$var =` / `let var =`。"""
    prefix = line[:match_end]
    assign = re.search(r"(?:\$|@)?([A-Za-z_]\w*)\s*:?=\s*[^=]*$", prefix)
    if not assign:
        return None
    target = assign.group(1)
    # RHS 从赋值号后到行尾
    eq = prefix.rfind("=")
    rhs = line[eq + 1:].rstrip(";").strip()
    return target, rhs


def analyze_generic_file(rel_path: str, text: str, language: str, endpoints: list[Endpoint]) -> list[Candidate]:
    rules = _lang_rules(language)
    if not rules.sources or not rules.sinks:
        return []
    code = strip_comments(text, language)
    lines = code.splitlines()
    raw_lines = text.splitlines()
    tainted: dict[str, SimpleSource] = {}
    findings: list[Candidate] = []
    endpoint = next((item for item in endpoints if item.file == rel_path), None)
    endpoint_path = endpoint.path if endpoint else f"/{Path(rel_path).stem}"
    http_method = endpoint.method if endpoint else "ANY"

    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        inline_source: SimpleSource | None = None
        # 1) source → 变量
        for pattern, kind, label in rules.sources:
            match = pattern.search(line)
            if not match:
                continue
            name = match.group(1) if match.groups() else "*"
            target_info = _assignment_target(line, match.end())
            if target_info:
                target, rhs = target_info
                tainted[target] = SimpleSource(kind, name, line_no, rhs)
            # 直接内联 source 也要能命中汇点（仅当前行）
            inline_source = SimpleSource(kind, name, line_no, line)

        # 2) 赋值传播（污点变量出现在 RHS）
        assign = re.search(r"(?:\$|@)?([A-Za-z_]\w*)\s*:?=\s*([^;]+)", line)
        if assign:
            target, rhs = assign.group(1), assign.group(2)
            inherited = [src for var, src in tainted.items() if not var.startswith("__inline") and var_reference_pattern(var).search(rhs)]
            if inherited:
                tainted[target] = inherited[0]
            elif target not in tainted:
                # 清理旧污点
                pass

        # 3) 汇点
        for pattern, vuln_type, rule_id in rules.sinks:
            match = pattern.search(line)
            if not match:
                continue
            blob = line
            hit_var = None
            for var, source in tainted.items():
                if var_reference_pattern(var).search(blob):
                    hit_var = var
                    break
            if not hit_var and inline_source is None:
                continue
            if _is_sanitized(blob, vuln_type):
                continue
            source = tainted.get(hit_var) if hit_var else inline_source
            if not source:
                continue
            chain = [
                ChainStep(step=1, location=f"{rel_path}:{source.line}",
                          description=f"从 {source.kind} `{source.name}` 读取外部输入",
                          data_state=f"污点进入 {hit_var or '内联表达式'}"),
                ChainStep(step=2, location=f"{rel_path}:{line_no}",
                          description=f"危险汇点：{line.strip()[:300]}",
                          data_state=f"污点进入 {vuln_type} 汇点",
                          bypass_reason="未发现有效净化/参数化"),
            ]
            line_start = max(1, line_no - 2)
            snippet = "\n".join(f"{line_start + offset}: {raw_lines[line_start - 1 + offset] if line_start - 1 + offset < len(raw_lines) else ''}"
                                for offset in range(min(3, len(raw_lines) - line_start + 1)))
            candidate = Candidate(
                candidate_id="GEN-" + hashlib.sha1(f"{rel_path}:{line_no}:{vuln_type}:{rule_id}".encode()).hexdigest()[:12],
                vuln_type=vuln_type,
                file=rel_path,
                line_start=line_start,
                line_end=line_no,
                rule_id=rule_id,
                sink=line.strip()[:400],
                source_kind=source.kind,
                source_name=source.name,
                endpoint=endpoint_path,
                http_method=http_method,
                code_snippet=snippet,
                tainted_expression=blob.strip()[:400],
                chain=chain,
                severity=meta(vuln_type).default_severity,
                confidence=0.78,
                origin="rule",
                notes=[f"语言 {language}", "轻量污点规则", "静态链闭合；未执行 POC"],
            )
            findings.append(candidate)
            break  # 一行只报一个最高优先级汇点

    # 去重
    seen: set[tuple[str, int]] = set()
    unique: list[Candidate] = []
    for item in findings:
        key = (item.vuln_type, item.line_end)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _is_sanitized(line: str, vuln_type: str) -> bool:
    lower = line.lower()
    if vuln_type in {"xss"}:
        return any(token in lower for token in ("htmlspecialchars", "escapehtml", "escape_html", "sanitize", "encodeforhtml", "markupsafe.escape"))
    if vuln_type in {"sql_injection"}:
        return any(token in lower for token in ("prepare(", "prepared", "placeholder", "setstring(", "bindparam", "parameterized"))
    if vuln_type in {"path_traversal"}:
        return any(token in lower for token in ("basename(", "realpath(", "getname(", "secure_filename", "normalize(", "filepath.base"))
    if vuln_type in {"command_injection"}:
        return "shell=False" in lower
    return False


# ---------------------------------------------------------------------------
# 跨语言配置/凭据/安全控制检查
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "私钥"),
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), "明文密码"),
    (re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([^'\"]{12,})['\"]"), "API Key/Token"),
    (re.compile(r"(?i)jdbc:[a-z0-9]+://[^\s'\"]+[?&](?:user|password)="), "JDBC 连接串凭据"),
]

_CONFIG_RULES = [
    (re.compile(r"(?i)verify\s*=\s*False"), "other", "python-tls-verify-disabled", "high", "TLS 证书校验被关闭"),
    (re.compile(r"(?i)InsecureSkipVerify\s*:\s*true"), "other", "go-tls-insecure", "high", "TLS 证书校验被关闭"),
    (re.compile(r"(?i)Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*"), "other", "cors-wildcard", "medium", "CORS 允许任意源"),
    (re.compile(r"(?i)csrf\s*\(\s*\)\s*\.\s*disable\s*\("), "csrf", "csrf-disabled", "medium", "CSRF 防护被关闭"),
    (re.compile(r"(?i)permitAll\s*\(\s*\)"), "auth_bypass", "spring-permit-all", "high", "Spring Security permitAll 暴露接口"),
    (re.compile(r"(?i)debug\s*=\s*True"), "information_disclosure", "debug-true", "medium", "调试模式开启"),
]


def scan_secrets_and_config(rel_path: str, text: str, language: str) -> list[Candidate]:
    results: list[Candidate] = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for pattern, label in _SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1) if match.groups() else match.group(0)
            if any(token in value.lower() for token in ("example", "changeme", "dummy", "placeholder", "xxx", "${", "<", "your_")):
                continue
            if len(value) < 8 and label != "私钥":
                continue
            results.append(
                Candidate(
                    candidate_id="SEC-" + hashlib.sha1(f"{rel_path}:{line_no}:{label}".encode()).hexdigest()[:12],
                    vuln_type="hardcoded_secret",
                    file=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    rule_id="secret-scanner",
                    sink=line.strip()[:300],
                    source_kind="repository",
                    source_name=label,
                    endpoint="",
                    http_method="",
                    code_snippet=f"{line_no}: {line.strip()[:300]}",
                    tainted_expression=line.strip()[:300],
                    chain=[ChainStep(step=1, location=f"{rel_path}:{line_no}", description=f"仓库中硬编码 {label}")],
                    severity="high",
                    confidence=0.7,
                    origin="rule",
                    notes=["凭据需人工确认是否仍有效"],
                )
            )
        for pattern, vuln_type, rule_id, severity, note in _CONFIG_RULES:
            if pattern.search(line):
                results.append(
                    Candidate(
                        candidate_id="CFG-" + hashlib.sha1(f"{rel_path}:{line_no}:{rule_id}".encode()).hexdigest()[:12],
                        vuln_type=vuln_type,
                        file=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        rule_id=rule_id,
                        sink=line.strip()[:300],
                        source_kind="config",
                        source_name=rule_id,
                        endpoint="",
                        http_method="",
                        code_snippet=f"{line_no}: {line.strip()[:300]}",
                        tainted_expression=line.strip()[:300],
                        chain=[ChainStep(step=1, location=f"{rel_path}:{line_no}", description=note)],
                        severity=severity,
                        confidence=0.65,
                        origin="rule",
                        notes=[note],
                    )
                )
    return results
