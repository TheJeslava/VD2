"""Java / Servlet / Spring 的轻量污点分析。

不追求编译器级精度，而是把「HTTP 入口 → 污点变量 → 危险汇点」这条链讲清楚：
- 方法级隔离，避免 doGet/doPost 变量串味；
- 支持 request.getParameter/getHeader/getCookies、Spring 注解参数；
- 支持赋值、拼接、for-each、集合 add/put 的传播；
- 支持路径、命令、SQL、SSRF、反序列化、SSTI、XXE、XSS、重定向、LDAP、
  XPath、日志、信任边界、文件上传、弱加密等汇点；
- 不执行任何东西，只产出 Candidate。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Candidate, ChainStep, Endpoint, TaintOrigin
from ..taxonomy import meta
from .common import (
    JavaMethod,
    enclosing_call_args,
    extract_java_methods,
    split_args,
    strip_comments,
)


@dataclass
class SourceSpec:
    kind: str
    name: str
    description: str


@dataclass
class TaintInfo:
    kind: str
    name: str
    origins: list[TaintOrigin] = field(default_factory=list)


@dataclass
class SinkHit:
    vuln_type: str
    line: int
    expression: str
    sink_text: str
    rule_id: str
    arg_index: int = 0
    confidence: float = 0.85
    note: str = ""


_SOURCE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"getParameter\s*\(\s*[\"']([^\"']+)[\"']"), "query", "HTTP 参数"),
    (re.compile(r"getParameterValues\s*\(\s*[\"']([^\"']+)[\"']"), "query", "HTTP 参数数组"),
    (re.compile(r"getHeader\s*\(\s*[\"']([^\"']+)[\"']"), "header", "HTTP 请求头"),
    (re.compile(r"getHeaders\s*\(\s*[\"']([^\"']+)[\"']"), "header", "HTTP 请求头集合"),
    (re.compile(r"getHeaderNames\s*\(\s*\)"), "header", "HTTP 请求头集合"),
    (re.compile(r"getParameterMap\s*\(\s*\)"), "query", "HTTP 参数 Map"),
    (re.compile(r"getParameterNames\s*\(\s*\)"), "query", "HTTP 参数名集合"),
    (re.compile(r"getCookies\s*\(\s*\)"), "cookie", "HTTP Cookie 集合"),
    (re.compile(r"(?:Utils|Helpers)?\s*\.\s*getCookie\s*\([^,]+,\s*[\"']([^\"']+)[\"']"), "cookie", "HTTP Cookie"),
    (re.compile(r"getQueryString\s*\(\s*\)"), "query", "原始查询串"),
    (re.compile(r"getRequestURI\s*\(\s*\)"), "path", "请求 URI"),
    (re.compile(r"getPathInfo\s*\(\s*\)"), "path", "路径信息"),
    (re.compile(r"getInputStream\s*\(\s*\)"), "body", "请求体输入流"),
    (re.compile(r"getReader\s*\(\s*\)"), "body", "请求体 Reader"),
    (re.compile(r"getPart\s*\(\s*[\"']([^\"']+)[\"']"), "upload", "上传 Part"),
]


def _dedupe(origins: list[TaintOrigin]) -> list[TaintOrigin]:
    seen: set[tuple[str, int]] = set()
    result: list[TaintOrigin] = []
    for origin in origins:
        key = (origin.var, origin.line)
        if key in seen:
            continue
        seen.add(key)
        result.append(origin)
    return result


def _strip_line_comment(text: str) -> str:
    """去掉行内 // 注释（字符串字面量已被处理时调用），避免把注释里的 API 签名当成调用。"""
    index = text.find("//")
    return text[:index] if index >= 0 else text


def _strip_string_literals(text: str) -> str:
    """把字符串字面量内容替换为空格，避免把 "input" 这种文本当成变量引用。"""
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                out.append(" ")
                if index + 1 < len(text):
                    out.append(" ")
                index += 2
                continue
            if char == quote:
                quote = ""
                out.append(char)
            else:
                out.append(" ")
        else:
            if char in {'"', "'"}:
                quote = char
                out.append(char)
            else:
                out.append(char)
        index += 1
    return "".join(out)


def _contains_var(expr: str, var: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(var)}(?![\w$])", expr) is not None


def _delimiter_state(text: str) -> tuple[int, bool, bool]:
    """返回 (圆括号深度, 是否出现语句分号, 是否出现块左花括号)，忽略字符串内容。"""
    depth = 0
    semi = False
    brace = False
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == ";":
            semi = True
        elif char == "{":
            brace = True
        index += 1
    return depth, semi, brace


class JavaAnalyzer:
    def __init__(self, rel_path: str, text: str, endpoints: list[Endpoint],
                 properties: dict[str, str] | None = None):
        self.rel_path = rel_path
        self.raw = text
        self.code = strip_comments(text, "java")
        self.lines = self.code.splitlines()
        self.raw_lines = text.splitlines()
        self.methods = extract_java_methods(self.code)
        self.endpoints = [item for item in endpoints if item.file == rel_path]
        self.properties = properties or {}
        self._property_values: dict[str, str] = {}
        self._const_values: dict[str, int] = {}
        self._constant_vars: set[str] = set()
        self._tainted_keys: dict[str, set[str]] = {}
        self._list_items: dict[str, list[str]] = {}
        self._xpath_vars: set[str] = set()

    # ------------------------------------------------------------------
    # 入口与端点
    # ------------------------------------------------------------------
    def _is_entry(self, method: JavaMethod) -> bool:
        if method.name in {"doGet", "doPost", "doPut", "doDelete", "doPatch", "service"}:
            return True
        if any("Mapping" in annotation or "RequestMapping" in annotation for annotation in method.annotations):
            return True
        return any(endpoint.handler == method.name for endpoint in self.endpoints)

    def _http_method(self, method: JavaMethod) -> str:
        mapping = {"doGet": "GET", "doPost": "POST", "doPut": "PUT", "doDelete": "DELETE", "doPatch": "PATCH"}
        if method.name in mapping:
            return mapping[method.name]
        for endpoint in self.endpoints:
            if endpoint.handler == method.name:
                return endpoint.method
        return "ANY"

    def _endpoint_for(self, method: JavaMethod) -> Endpoint:
        http_method = self._http_method(method)
        for endpoint in self.endpoints:
            if endpoint.handler == method.name and endpoint.method in {http_method, "ANY"}:
                return endpoint
        for endpoint in self.endpoints:
            if endpoint.method in {http_method, "ANY"}:
                return endpoint
        if self.endpoints:
            return self.endpoints[0]
        return Endpoint(
            path=f"/{Path(self.rel_path).stem}",
            method=http_method,
            file=self.rel_path,
            line=method.start_line,
            framework="servlet",
            handler=method.name,
        )

    # ------------------------------------------------------------------
    # 污点传播
    # ------------------------------------------------------------------
    def _source(self, expression: str) -> SourceSpec | None:
        for pattern, kind, label in _SOURCE_PATTERNS:
            match = pattern.search(expression)
            if match:
                name = match.group(1) if match.groups() else "*"
                return SourceSpec(kind=kind, name=name, description=label)
        return None

    def _find_tainted_vars(self, expression: str, taint: dict[str, TaintInfo]) -> list[str]:
        code = _strip_string_literals(expression)
        return [var for var in taint if _contains_var(code, var)]

    def _sanitized(self, expression: str, vuln_type: str) -> bool:
        expr = expression.lower()
        if vuln_type in {"xss"}:
            return any(token in expr for token in (
                "encodeforhtml", "encodeforjavascript", "encodeforcss", "encodeforurl",
                "escapehtml", "escape_html", "htmlspecialchars", "sanitize", "owasp.encoder",
            ))
        if vuln_type in {"sql_injection"}:
            return any(token in expr for token in (
                "encodeforsql", "escapesql", "escape_sql", "setstring(", "setint(",
            ))
        if vuln_type in {"path_traversal"}:
            if any(token in expr for token in ("getname(", "filenameutils.getname", "basename(", "secure_filename")):
                return True
            return any(token in expr for token in ("normalize()", "canonicalpath", "torealpath")) and "startswith(" in expr
        if vuln_type in {"command_injection"}:
            return "processbuilder" in expr and "sh" not in expr and "cmd.exe" not in expr
        return False

    def _set_taint(self, target: str, expression: str, line_no: int,
                   taint: dict[str, TaintInfo], *, append: bool = False,
                   clear_clean: bool = True) -> None:
        source = self._source(expression)
        previous_vars = self._find_tainted_vars(expression, taint)
        inherited: list[TaintOrigin] = []
        for var in previous_vars:
            inherited.extend(taint[var].origins)
        inherited = _dedupe(inherited)

        if source:
            origin = TaintOrigin(
                var=target,
                line=line_no,
                expression=expression.strip()[:500],
                kind=source.kind,
                name=source.name,
                description=source.description,
            )
            origins = _dedupe(inherited + [origin])
            taint[target] = TaintInfo(kind=source.kind, name=source.name, origins=origins)
            return

        if previous_vars:
            # 继承第一个（最早）污点的 kind/name，同时记录本次赋值
            base = taint[previous_vars[0]]
            origin = TaintOrigin(
                var=target,
                line=line_no,
                expression=expression.strip()[:500],
                kind="",
                name="",
                description="赋值/拼接传播",
            )
            origins = _dedupe(base.origins + inherited + [origin])
            name = base.name
            for var in previous_vars:
                if taint[var].name not in {"", "*"}:
                    name = taint[var].name
                    break
            taint[target] = TaintInfo(kind=base.kind, name=name, origins=origins)
            return

        # 被重新赋值为干净值 → 清除旧污点（条件分支内的默认赋值不清除）
        if clear_clean and not append and target in taint:
            del taint[target]

    def _cookie_hint(self, line: str, taint: dict[str, TaintInfo]) -> None:
        for match in re.finditer(r"(\w+)\s*\.\s*getName\s*\(\s*\)\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*[\"']([^\"']+)[\"']", line):
            var, name = match.group(1), match.group(2)
            if var in taint:
                taint[var].name = name
                for origin in taint[var].origins:
                    if origin.kind:
                        origin.name = name

    def _handle_foreach(self, line: str, line_no: int, taint: dict[str, TaintInfo]) -> None:
        match = re.search(
            r"for\s*\(\s*(?:final\s+)?[\w$.<>\[\],?\s]+\s+(\w+)\s*:\s*([^)]+)\)",
            line,
        )
        if not match:
            return
        var, collection = match.group(1), match.group(2)
        source = self._source(collection)
        previous_vars = self._find_tainted_vars(collection, taint)
        if not source and not previous_vars:
            return
        inherited: list[TaintOrigin] = []
        for item in previous_vars:
            inherited.extend(taint[item].origins)
        if source:
            inherited.append(TaintOrigin(var=var, line=line_no, expression=collection.strip(),
                                         kind=source.kind, name=source.name, description=source.description))
            taint[var] = TaintInfo(source.kind, source.name, _dedupe(inherited))
        else:
            base = taint[previous_vars[0]]
            inherited.append(TaintOrigin(var=var, line=line_no, expression=collection.strip(),
                                         kind="", name="", description="集合遍历传播"))
            taint[var] = TaintInfo(base.kind, base.name, _dedupe(inherited))

    def _eval_const_bool(self, expression: str, constants: dict[str, int]) -> bool | None:
        text = expression
        for name, value in constants.items():
            text = re.sub(rf"\b{re.escape(name)}\b", str(value), text)
        text = text.replace("&&", " and ").replace("||", " or ")
        cleaned = re.sub(r"\b(?:and|or|not)\b", "", text)
        if not re.fullmatch(r"[0-9\s+\-*/%().<>=!]*", cleaned):
            return None
        try:
            return bool(eval(text, {"__builtins__": {}}, {}))
        except Exception:  # noqa: BLE001 - 非可折叠表达式
            return None

    def _handle_assignment(self, line: str, line_no: int, taint: dict[str, TaintInfo]) -> None:
        conditional = bool(re.match(r"^\s*(?:if|else|for|while|switch|case)\b", line))

        # 三元表达式：能静态求值时只保留真实分支，避免把常量守卫误判为污点传播。
        ternary = re.match(r"^\s*(\w+)\s*=\s*(.+?)\?\s*(.+?)\s*:\s*(.+?);?\s*$", line)
        if ternary:
            target, condition, true_expr, false_expr = ternary.groups()
            truth = self._eval_const_bool(condition, self._const_values)
            if truth is not None:
                self._set_taint(target, (true_expr if truth else false_expr).strip(), line_no, taint)
                return

        # 集合写入：args.add(tainted) / map.put(key, tainted) / list.append(tainted)
        for match in re.finditer(r"(\w+)\s*\.\s*(add|put|push|append|offer)\s*\(", line):
            open_index = line.find("(", match.start())
            args = enclosing_call_args(line, open_index) or ""
            if match.group(2) in {"add", "push", "append", "offer"}:
                values = split_args(args)
                if values:
                    self._list_items.setdefault(match.group(1), []).append(values[0].strip())
            if self._find_tainted_vars(args, taint) or self._source(args):
                self._set_taint(match.group(1), args, line_no, taint, append=True)
                key = re.match(r"\s*[\"']([^\"']+)[\"']\s*,", args)
                if key:
                    self._tainted_keys.setdefault(match.group(1), set()).add(key.group(1))

        for match in re.finditer(r"(\w+)\s*\.\s*remove\s*\(\s*(\d+)\s*\)", line):
            items = self._list_items.get(match.group(1))
            index = int(match.group(2))
            if items is not None and 0 <= index < len(items):
                items.pop(index)

        # list.get(常量下标)：按 add/remove 的顺序精确取值，避免整个 list 被污染。
        list_get = re.match(
            r"^\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*\.\s*get\s*\(\s*(\d+)\s*\)",
            line,
        )
        if list_get and list_get.group(2) in self._list_items:
            target, collection, raw_index = list_get.groups()
            items = self._list_items[collection]
            index = int(raw_index)
            if 0 <= index < len(items):
                item = items[index].strip()
                if re.fullmatch(r"[\"'][^\"']*[\"']", item):
                    taint.pop(target, None)
                else:
                    self._set_taint(target, item, line_no, taint)
                return

        # map.get("literal-key")：只有该 key 被写入过污点时才继续传播。
        map_get = re.match(
            r"^\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*\.\s*get\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
            line,
        )
        if map_get and map_get.group(2) in taint:
            target, collection, key = map_get.groups()
            if key not in self._tainted_keys.get(collection, set()):
                taint.pop(target, None)
                return

        # +=
        match = re.match(r"^\s*(\w+)\s*\+=\s*(.+?);?\s*$", line)
        if match and not self._sanitized(match.group(2), "sql_injection"):
            self._set_taint(match.group(1), match.group(1) + " + " + match.group(2), line_no, taint, append=True)
            return

        # 普通赋值（排除 == / <= / >= / !=）
        for match in re.finditer(r"(?<![=<>!])\b(\w+)\s*=\s*(?!=)([^;]+)", line):
            target = match.group(1)
            expression = match.group(2).strip()
            if not expression or expression.startswith("="):
                continue
            if target in {"if", "for", "while", "return"}:
                continue
            if target in self._constant_vars:
                taint.pop(target, None)
                continue
            # 简单类型转换/解析视为清洗（仍保留原始污点用于审计？这里选择清除）
            if re.search(r"(?:Integer|Long|Double|Float|Boolean)\s*\.\s*(?:parse|valueOf)", expression):
                if not self._source(expression):
                    taint.pop(target, None)
                    continue
            self._set_taint(target, expression, line_no, taint, clear_clean=not conditional)

    # ------------------------------------------------------------------
    # 汇点
    # ------------------------------------------------------------------
    def _hit_if_tainted(self, vuln_type: str, line_no: int, args: list[str], taint: dict[str, TaintInfo],
                        line: str, rule_id: str, *, arg_index: int = 0, note: str = "",
                        confidence: float = 0.88) -> SinkHit | None:
        if arg_index < 0:
            expression = ", ".join(args)
        else:
            expression = args[arg_index] if len(args) > arg_index else ", ".join(args)
        if not expression:
            return None
        if self._sanitized(expression, vuln_type):
            return None
        if not (self._find_tainted_vars(expression, taint) or self._source(expression)):
            return None
        return SinkHit(
            vuln_type=vuln_type,
            line=line_no,
            expression=expression.strip()[:500],
            sink_text=line.strip()[:500],
            rule_id=rule_id,
            arg_index=arg_index,
            confidence=confidence,
            note=note,
        )

    def _detect_sinks(self, line: str, line_no: int, taint: dict[str, TaintInfo],
                      method: JavaMethod) -> list[SinkHit]:
        hits: list[SinkHit] = []

        def args_of(match: re.Match[str]) -> list[str]:
            # 优先使用匹配自身的左括号（如 response.getWriter().format( 的 format(），
            # 否则回退到 match 之后第一个左括号（如 setHeader("Location",）。
            open_index = match.end() - 1
            if open_index < 0 or open_index >= len(line) or line[open_index] != "(":
                open_index = line.find("(", match.start())
            raw = enclosing_call_args(line, open_index) or ""
            return split_args(raw)

        # 路径 / 文件
        for pattern, rule in (
            (r"new\s+(?:java\.io\.)?(?:FileOutputStream|FileInputStream|FileWriter|FileReader|PrintWriter|RandomAccessFile)\s*\(", "java-file-stream"),
            (r"(?:java\.nio\.file\.)?Files\s*\.\s*(?:write|readAllBytes|readString|newInputStream|newOutputStream|copy|move|delete|createFile)\s*\(", "java-nio-files"),
        ):
            for match in re.finditer(pattern, line):
                args = args_of(match)
                hit = self._hit_if_tainted("path_traversal", line_no, args, taint, line, rule, note="文件路径由外部输入拼接")
                if hit:
                    hits.append(hit)
        # new File(tainted, ...) + exists()/isFile()/length()：路径存在性/读取型汇点
        if re.search(r"\.\s*(?:exists|isFile|length|getCanonicalPath|getAbsolutePath)\s*\(", "\n".join(
                self.lines[method.start_line - 1:method.end_line])):
            for match in re.finditer(r"new\s+(?:java\.io\.)?File\s*\(", line):
                args = args_of(match)
                hit = self._hit_if_tainted("path_traversal", line_no, args, taint, line,
                                           "java-file-exists", note="File 路径由外部输入控制并用于存在性/读取")
                if hit:
                    hits.append(hit)

        # 命令执行
        command_body = "\n".join(self.lines[method.start_line - 1:method.end_line])
        for pattern, rule in (
            (r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "java-runtime-exec"),
            (r"new\s+ProcessBuilder\s*\(", "java-processbuilder"),
            (r"\.\s*command\s*\(", "java-processbuilder-command"),
        ):
            for match in re.finditer(pattern, line):
                args = args_of(match)
                hit = self._hit_if_tainted("command_injection", line_no, args, taint, line, rule, note="进程命令参数由外部输入控制")
                if hit:
                    hits.append(hit)
        # Runtime 变量形式：Runtime r = ...; r.exec(args, env)
        if re.search(r"\bRuntime\b|\bProcessBuilder\b", command_body):
            for match in re.finditer(r"\b\w+\s*\.\s*exec\s*\(", line):
                args = args_of(match)
                hit = self._hit_if_tainted("command_injection", line_no, args, taint, line,
                                           "java-runtime-exec-var", arg_index=-1,
                                           note="Runtime.exec 参数/环境变量由外部输入控制")
                if hit:
                    hits.append(hit)

        # SQL
        method_body_for_sql = "\n".join(self.lines[method.start_line - 1:method.end_line])
        sql_context = bool(re.search(
            r"(?i)\b(?:SELECT|INSERT|DELETE|FROM|WHERE|JDBC|SQL|prepareStatement|prepareCall|"
            r"createStatement|executeQuery|executeUpdate|batchUpdate|queryForList|queryForObject)\b",
            method_body_for_sql,
        ))
        for match in re.finditer(r"\.\s*(executeQuery|executeUpdate|execute|queryForList|queryForObject|query|update|batchUpdate)\s*\(", line):
            method_name = match.group(1)
            if method_name in {"execute", "update", "query"} and not sql_context:
                continue
            args = args_of(match)
            joined = ", ".join(args)
            if "?" in joined and "+" not in joined:
                continue
            hit = self._hit_if_tainted("sql_injection", line_no, args, taint, line, "java-sql-exec", note="SQL 语句由字符串拼接构造")
            if hit:
                hits.append(hit)
        for match in re.finditer(r"(?:prepareStatement|prepareCall)\s*\(", line):
            args = args_of(match)
            joined = ", ".join(args)
            # 只有纯占位符且没有任何拼接时才跳过
            if "?" in joined and "+" not in joined:
                continue
            hit = self._hit_if_tainted("sql_injection", line_no, args, taint, line, "java-sql-prepare",
                                       note="prepareStatement/prepareCall 仍使用拼接 SQL")
            if hit:
                hits.append(hit)

        # XSS（只认 response.getWriter() 或明确的 PrintWriter/JspWriter 变量，
        # 不把 System.out 当成 HTTP 响应）
        if re.search(r"getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println|format|printf)\s*\(|(?<!System\.)\bout\s*\.\s*(?:print|write|println|format|printf)\s*\(", line):
            match = re.search(r"(?:getWriter\s*\(\s*\)\s*\.\s*|(?<!System\.)\bout\s*\.\s*)(?:print|write|println|format|printf)\s*\(", line)
            if match:
                args = args_of(match)
                # format/printf 的第一个参数是 Locale/格式串，污点可能在任意参数位
                arg_index = -1 if re.search(r"\.\s*(?:format|printf)\s*\(", line) else 0
                hit = self._hit_if_tainted("xss", line_no, args, taint, line, "java-xss-writer",
                                           arg_index=arg_index, note="未编码输出到 HTTP 响应")
                if hit:
                    xss_vars = self._find_tainted_vars(hit.expression, taint)
                    # XPath/XML 查询结果不是原始输入；不要把它二次归类为 XSS。
                    if not (xss_vars and all(var in self._xpath_vars for var in xss_vars)):
                        hits.append(hit)

        # SSRF
        for match in re.finditer(r"new\s+(?:java\.net\.)?URL\s*\(", line):
            args = args_of(match)
            hit = self._hit_if_tainted("ssrf", line_no, args, taint, line, "java-url", note="请求 URL 由外部输入控制")
            if hit:
                hits.append(hit)
        if re.search(r"\.\s*openConnection\s*\(\s*\)", line):
            # 目标在上一行/本行的 URL 变量里
            for var in self._find_tainted_vars(line, taint):
                hits.append(SinkHit("ssrf", line_no, var, line.strip()[:500], "java-openconnection", confidence=0.8,
                                    note="openConnection 使用污点 URL"))
                break

        # 反序列化
        for pattern, rule in (
            (r"new\s+ObjectInputStream\s*\(", "java-objectinputstream"),
            (r"\.\s*readObject\s*\(", "java-readobject"),
            (r"new\s+XMLDecoder\s*\(", "java-xmlDecoder"),
            (r"\bYAML\s*\.\s*load\s*\(", "java-yaml-load"),
            (r"\.\s*fromXML\s*\(", "java-xstream"),
        ):
            for match in re.finditer(pattern, line):
                args = args_of(match)
                hit = self._hit_if_tainted("deserialization", line_no, args, taint, line, rule, note="不可信数据进入反序列化入口")
                if hit:
                    hits.append(hit)

        # SSTI / 表达式
        for pattern, rule, vuln in (
            (r"\.\s*process\s*\(", "java-template-process", "ssti"),
            (r"Velocity\s*\.\s*evaluate\s*\(", "java-velocity", "ssti"),
            (r"render_template_string\s*\(", "python-ssti", "ssti"),
            (r"parseExpression\s*\(", "java-spel", "expression_injection"),
            (r"Ognl\s*\.\s*getValue\s*\(", "java-ognl", "expression_injection"),
            (r"MVEL\s*\.\s*eval\s*\(", "java-mvel", "expression_injection"),
        ):
            for match in re.finditer(pattern, line):
                args = args_of(match)
                hit = self._hit_if_tainted(vuln, line_no, args, taint, line, rule, note="表达式/模板由外部输入控制")
                if hit:
                    hits.append(hit)

        # 重定向
        for match in re.finditer(r"sendRedirect\s*\(|setHeader\s*\(\s*[\"']Location[\"']\s*,", line):
            args = args_of(match)
            hit = self._hit_if_tainted("open_redirect", line_no, args, taint, line, "java-redirect", note="跳转目标由外部输入控制")
            if hit:
                hits.append(hit)

        # LDAP / XPath：上下文可能出现在方法内其它行（如 idc 的类型声明）
        method_body = "\n".join(self.lines[method.start_line - 1:method.end_line])
        if re.search(r"DirContext|InitialDirContext|LDAP|ldap", method_body):
            for match in re.finditer(r"\.\s*search\s*\(", line):
                args = args_of(match)
                hit = self._hit_if_tainted("ldap_injection", line_no, args, taint, line, "java-ldap-search",
                                           arg_index=-1, note="LDAP filter 由外部输入拼接")
                if hit:
                    hits.append(hit)
        if re.search(r"XPath|XPathFactory|xpath", method_body):
            for match in re.finditer(r"\.\s*evaluate\s*\(", line):
                args = args_of(match)
                hit = self._hit_if_tainted("xpath_injection", line_no, args, taint, line, "java-xpath-eval",
                                           arg_index=-1, note="XPath 表达式由外部输入拼接")
                if hit:
                    hits.append(hit)

        # 信任边界 / 文件上传 / 日志
        code_without_comment = _strip_line_comment(_strip_string_literals(line))
        for match in re.finditer(r"\.\s*(?:setAttribute|putValue)\s*\(", code_without_comment):
            args = args_of(match)
            hit = self._hit_if_tainted("trust_boundary", line_no, args, taint, line, "java-session-attribute",
                                       arg_index=-1, note="外部输入写入 session/信任边界")
            if hit:
                hits.append(hit)
        for match in re.finditer(r"\.\s*transferTo\s*\(", line):
            args = args_of(match)
            hit = self._hit_if_tainted("file_upload", line_no, args, taint, line, "java-transferto",
                                       note="上传文件名/路径由外部输入控制")
            if hit:
                hits.append(hit)
        for match in re.finditer(r"\b(?:logger|log|LOG)\s*\.\s*(?:info|warn|error|debug|trace)\s*\(", line):
            args = args_of(match)
            hit = self._hit_if_tainted("log_injection", line_no, args, taint, line, "java-log",
                                       confidence=0.6, note="未净化输入写入日志")
            if hit:
                hits.append(hit)

        # XXE：工厂/解析器创建点（配置型）
        if re.search(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|TransformerFactory)\s*\.\s*newInstance\s*\(|new\s+SAXReader\s*\(", line):
            body = "\n".join(self.lines[method.start_line - 1:method.end_line])
            secure = re.search(r"disallow-doctype-decl|external-general-entities|external-parameter-entities|FEATURE_SECURE_PROCESSING|setExpandEntityReferences\s*\(\s*false", body, re.IGNORECASE)
            if not secure:
                hits.append(SinkHit("xxe", line_no, line.strip()[:300], line.strip()[:500], "java-xxe-factory",
                                    confidence=0.72, note="XML 解析器未禁用外部实体"))

        # 配置型弱哈希（CWE-328，不再并入 weak_crypto/CWE-327；medium 严重度由 --min-severity 控制）
        code_line = _strip_string_literals(line)
        if re.search(r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']", line, re.IGNORECASE):
            hits.append(SinkHit("weak_hash", line_no, line.strip()[:300], line.strip()[:500], "java-weak-digest",
                                confidence=0.7, note="使用 MD5/SHA1"))
        for match in re.finditer(r"MessageDigest\s*\.\s*getInstance\s*\(\s*(\w+)\s*\)", line):
            value = self._property_values.get(match.group(1), "")
            if re.search(r"^(?:MD5|SHA-?1)$", value.strip(), re.IGNORECASE):
                hits.append(SinkHit("weak_hash", line_no, line.strip()[:300], line.strip()[:500],
                                    "java-weak-digest-property", confidence=0.7,
                                    note=f"从属性文件解析到弱哈希算法: {value}"))
        if re.search(r"new\s+(?:java\.util\.)?Random\s*\(\s*\)", code_line):
            hits.append(SinkHit("weak_random", line_no, line.strip()[:300], line.strip()[:500], "java-random",
                                confidence=0.66, note="使用非密码学安全随机数"))
        if re.search(r"(?:java\.lang\.)?Math\s*\.\s*random\s*\(\s*\)", code_line):
            hits.append(SinkHit("weak_random", line_no, line.strip()[:300], line.strip()[:500], "java-math-random",
                                confidence=0.66, note="使用 Math.random() 生成安全相关随机值"))
        if re.search(r"(?:Cipher|KeyGenerator)\s*\.\s*getInstance\s*\(\s*[\"'][^\"']*(?:DES|ECB)[^\"']*[\"']", line, re.IGNORECASE):
            hits.append(SinkHit("weak_crypto", line_no, line.strip()[:300], line.strip()[:500], "java-weak-cipher",
                                confidence=0.72, note="使用弱加密算法/ECB 模式"))
        for match in re.finditer(r"(?:Cipher|KeyGenerator)\s*\.\s*getInstance\s*\(\s*(\w+)\s*\)", line):
            value = self._property_values.get(match.group(1), "")
            if re.search(r"DES|ECB", value, re.IGNORECASE):
                hits.append(SinkHit("weak_crypto", line_no, line.strip()[:300], line.strip()[:500],
                                    "java-weak-cipher-property", confidence=0.72,
                                    note=f"从属性文件解析到弱加密算法: {value}"))

        # 不安全 Cookie：创建后未同时设置 Secure + HttpOnly
        cookie = re.search(r"(?:new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(|Cookie\s+\w+\s*=\s*new\s+Cookie\s*\()", line)
        if cookie:
            window = "\n".join(self.lines[line_no - 1:min(len(self.lines), line_no + 14)])
            if not (re.search(r"setSecure\s*\(\s*true\s*\)", window) and re.search(r"setHttpOnly\s*\(\s*true\s*\)", window)):
                hits.append(SinkHit("insecure_cookie", line_no, line.strip()[:300], line.strip()[:500],
                                    "java-insecure-cookie", confidence=0.66,
                                    note="Cookie 未同时设置 Secure 与 HttpOnly"))

        return hits

    # ------------------------------------------------------------------
    # 组装
    # ------------------------------------------------------------------
    def _statement_from(self, line_no: int, end_line: int) -> str:
        """把跨行语句拼起来（最多 12 行），用于多行 prepareStatement/println 等。

        遇到 if/for/while/方法签名等块开始行直接返回原行，避免把整个代码块当成一条语句。
        """
        line = self.lines[line_no - 1]
        stripped = line.strip()
        if not stripped:
            return line
        # 纯括号行（} / }); / };）不可能开启一条跨行语句；否则会把下一条语句吞进来，
        # 导致汇点被记在错误的行号上（如 trust_boundary 命中注释后的 else 块）。
        if re.fullmatch(r"[}\])]+;?", stripped):
            return line
        if re.match(
            r"^(?:if|for|while|switch|catch|try|else|do|public|private|protected|"
            r"static|final|class|interface|enum|return|throw)\b",
            stripped,
        ):
            return line
        depth, semi, brace = _delimiter_state(line)
        if semi and depth == 0:
            return line
        parts = [line]
        index = line_no
        while index < end_line and index - line_no < 12:
            index += 1
            nxt = self.lines[index - 1]
            parts.append(nxt)
            delta_depth, has_semi, has_brace = _delimiter_state(nxt)
            depth += delta_depth
            if has_semi:
                semi = True
            if has_brace and depth == 0:
                break
            # 行末分号是强终止符，即使括号计数因字符串/泛型出现偏差也不再吞后续代码
            if has_semi and nxt.rstrip().endswith(";"):
                break
            if semi and depth <= 0:
                break
        return " ".join(parts)

    def _is_continuation(self, line_no: int) -> bool:
        """当前行是否是上一条语句的续行（例如多行方法调用的参数行）。"""
        if line_no <= 1:
            return False
        previous = self.lines[line_no - 2].rstrip()
        if not previous:
            return False
        if previous.endswith((";", "{", "}", ":")):
            return False
        return previous.endswith((",", "(", "+", "=", ".", "&&", "||", "?", "[", "->"))

    def _analyze_method(self, method: JavaMethod) -> tuple[list[SinkHit], dict[str, TaintInfo]]:
        taint: dict[str, TaintInfo] = {}
        self._property_values = {}
        self._const_values = {}
        self._constant_vars = set()
        self._tainted_keys = {}
        self._list_items = {}
        self._xpath_vars = set()
        body_lines = self.lines[method.start_line - 1:method.end_line]
        for line in body_lines:
            prop = re.search(r"(\w+)\s*=\s*[^;]*?getProperty\s*\(\s*[\"']([^\"']+)[\"']", line)
            if prop and prop.group(2) in self.properties:
                self._property_values[prop.group(1)] = self.properties[prop.group(2)]
            const = re.search(r"\b(?:final\s+)?(?:int|long)\s+(\w+)\s*=\s*(\d+)\s*;", line)
            if const:
                self._const_values[const.group(1)] = int(const.group(2))
            xpath_result = re.search(r"\b(\w+)\s*=\s*[^;]*(?:\.evaluate\s*\(|\.item\s*\()", line)
            if xpath_result:
                self._xpath_vars.add(xpath_result.group(1))
            # Statically true if/else constant assignment: if (cond) bar = "literal";
            conditional = re.search(r"\bif\s*\((.+?)\)\s*(\w+)\s*=\s*[\"']([^\"']*)[\"']\s*;", line)
            if conditional and self._eval_const_bool(conditional.group(1), self._const_values):
                self._constant_vars.add(conditional.group(2))
        # Spring 注解参数直接视为污点源
        for param in method.params:
            annotation = re.search(r"@(RequestParam|PathVariable|RequestBody|RequestHeader|RequestPart)\s*(?:\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'])?", param)
            if not annotation:
                continue
            kind_map = {"RequestParam": "query", "PathVariable": "path", "RequestBody": "body",
                        "RequestHeader": "header", "RequestPart": "upload"}
            kind = kind_map.get(annotation.group(1), "query")
            name_match = re.search(r"([A-Za-z_]\w*)\s*$", re.sub(r"@\w+(?:\([^)]*\))?", " ", param).strip())
            name = annotation.group(2) or (name_match.group(1) if name_match else "*")
            var = name_match.group(1) if name_match else name
            taint[var] = TaintInfo(kind, name, [TaintOrigin(var=var, line=method.start_line, expression=param,
                                                             kind=kind, name=name, description="Spring 注解参数")])

        hits: list[SinkHit] = []
        for line_no in range(method.start_line, method.end_line + 1):
            if line_no - 1 >= len(self.lines):
                break
            raw_line = self.lines[line_no - 1]
            if not raw_line.strip():
                continue
            if self._is_continuation(line_no):
                continue
            statement = self._statement_from(line_no, method.end_line)
            self._cookie_hint(statement, taint)
            self._handle_foreach(statement, line_no, taint)
            self._handle_assignment(statement, line_no, taint)
            hits.extend(self._detect_sinks(statement, line_no, taint, method))
        return hits, taint

    def analyze(self) -> list[Candidate]:
        candidates: list[Candidate] = []
        for method in self.methods:
            if not self._is_entry(method):
                continue
            hits, taint = self._analyze_method(method)
            endpoint = self._endpoint_for(method)
            for hit in hits:
                candidate = self._build_candidate(method, endpoint, hit, taint)
                if candidate:
                    candidates.append(candidate)
        # 去重：同类型同文件的近邻行（多行语句会在多个起始行重复命中）
        candidates.sort(key=lambda item: item.line_end)
        unique: list[Candidate] = []
        for candidate in candidates:
            if any(
                item.vuln_type == candidate.vuln_type
                and item.file == candidate.file
                and (abs(item.line_end - candidate.line_end) <= 2
                     or (item.rule_id == candidate.rule_id and abs(item.line_end - candidate.line_end) <= 8))
                for item in unique
            ):
                continue
            unique.append(candidate)
        return unique

    def _build_candidate(self, method: JavaMethod, endpoint: Endpoint, hit: SinkHit,
                         taint: dict[str, TaintInfo]) -> Candidate | None:
        # 找到汇点参数对应的污点变量，收集 origins
        config_like = hit.vuln_type in {"weak_crypto", "weak_hash", "weak_random", "insecure_cookie"}
        variables = self._find_tainted_vars(hit.expression, taint)
        if not variables and self._source(hit.expression):
            variables = []
        origins: list[TaintOrigin] = []
        for var in variables:
            origins.extend(taint[var].origins)
        if not origins and not self._source(hit.expression) and not config_like:
            return None
        origins = _dedupe(origins)
        origins.sort(key=lambda item: item.line)

        source_origin = None
        for origin in reversed(origins):
            if origin.kind and origin.name not in {"", "*"}:
                source_origin = origin
                break
        if source_origin is None:
            source_origin = next((origin for origin in origins if origin.kind), None)
        source_kind = source_origin.kind if source_origin else ("config" if config_like else "unknown")
        source_name = source_origin.name if source_origin else ("repository" if config_like else "*")
        if source_name in {"", "*"} and not config_like:
            method_text = "\n".join(self.lines[method.start_line - 1:method.end_line])
            if re.search(r"getParameterMap\s*\(|getParameterNames\s*\(", method_text):
                key = re.search(r"\.\s*get\s*\(\s*[\"']([^\"']+)[\"']", method_text)
                if key:
                    source_kind = "query"
                    source_name = key.group(1)
                elif re.search(r"getParameterNames\s*\(", method_text) and re.search(r"\b\w+\s*=\s*name\b", method_text):
                    source_kind = "query"
                    source_name = "__parameter_name__"

        chain: list[ChainStep] = []
        step = 1
        chain.append(ChainStep(
            step=step,
            location=f"{self.rel_path}:{method.start_line}",
            description=f"HTTP {endpoint.method} {endpoint.path} 进入 {method.name}()",
            data_state="外部请求到达入口方法",
        ))
        step += 1
        seen_lines: set[int] = set()
        for origin in origins:
            if origin.line in seen_lines:
                continue
            seen_lines.add(origin.line)
            if origin.kind:
                description = f"从 {origin.kind} `{origin.name}` 读取攻击者可控输入"
                data_state = f"污点进入变量 {origin.var}"
                bypass = "该输入未经过白名单或业务校验"
            else:
                description = f"{origin.var} = {origin.expression}"
                data_state = f"污点传播到 {origin.var}"
                bypass = ""
            if "URLDecoder" in origin.expression or "urldecode" in origin.expression.lower():
                bypass = "URL 解码只还原传输编码，不是安全过滤"
            chain.append(ChainStep(
                step=step,
                location=f"{self.rel_path}:{origin.line}",
                description=description[:500],
                data_state=data_state[:300],
                bypass_reason=bypass[:300],
            ))
            step += 1
        chain.append(ChainStep(
            step=step,
            location=f"{self.rel_path}:{hit.line}",
            description=f"危险汇点：{hit.sink_text}",
            data_state=f"污点表达式 `{hit.expression}` 进入 {hit.vuln_type} 汇点",
            bypass_reason=hit.note,
        ))

        meta_info = meta(hit.vuln_type)
        confidence = min(0.96, max(0.55, hit.confidence + (0.03 if len(origins) >= 2 else 0)))
        if not variables and self._source(hit.expression):
            confidence -= 0.05
        line_start = max(1, hit.line - 2)
        snippet_lines = self.raw_lines[line_start - 1:hit.line + 1]
        snippet = "\n".join(f"{line_start + offset}: {text}" for offset, text in enumerate(snippet_lines))
        title = f"{Path(self.rel_path).stem} {meta_info.label_zh}（{meta_info.cwe}）"
        candidate_id = "JAVA-" + hashlib.sha1(
            f"{self.rel_path}:{hit.line}:{hit.vuln_type}:{hit.rule_id}".encode("utf-8")
        ).hexdigest()[:12]
        return Candidate(
            candidate_id=candidate_id,
            vuln_type=hit.vuln_type,
            file=self.rel_path,
            line_start=line_start,
            line_end=hit.line,
            rule_id=hit.rule_id,
            sink=hit.sink_text,
            source_kind=source_kind,
            source_name=source_name,
            endpoint=endpoint.path,
            http_method=endpoint.method,
            code_snippet=snippet,
            tainted_expression=hit.expression,
            chain=chain,
            sanitized=False,
            severity=meta_info.default_severity,
            confidence=round(confidence, 2),
            origin="rule",
            notes=[f"入口 {method.name}()", f"汇点规则 {hit.rule_id}", "静态链闭合；未执行 POC"],
        )


def analyze_java_file(rel_path: str, text: str, endpoints: list[Endpoint],
                      properties: dict[str, str] | None = None) -> list[Candidate]:
    try:
        return JavaAnalyzer(rel_path, text, endpoints, properties=properties).analyze()
    except Exception:  # noqa: BLE001 - 单文件失败不阻塞整条管线
        return []
