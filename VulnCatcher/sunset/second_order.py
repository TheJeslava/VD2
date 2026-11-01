"""二次注入分析（SecondOrderAnalyzer）：二次注入的专属挖掘与静态验证流程。

二次注入的关键不是「输入立刻进 sink」，而是：
    请求 A 的恶意输入 → 被持久化（DB / Session / Cache / 文件）
    请求 B 读出持久化值 → 在另一个上下文拼进 SQL/命令/模板/路径 → 触发

因此这里的流程分成四步：
1. 找「存储写点」（INSERT/UPDATE、setAttribute、cache.set、文件写入）；
2. 找「存储读点」（SELECT 赋值、getAttribute、cache.get、文件读取）；
3. 用 storage+key/table 把写点和读点连起来；
4. 检查读出的变量是否在后续进入危险汇点，且没有被参数化/白名单阻断。

「验证」在本管线中是静态证据闭环（store→read→sink + 缺口说明），并生成两阶段
POC 回放脚本；不执行脚本、不搭沙箱。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .models import ChainStep, Endpoint, PocPlan, Project, SecondOrderChain
from .rules.common import extract_java_methods, strip_comments, var_reference_pattern
from .taxonomy import meta


@dataclass
class PersistRecord:
    file: str
    line: int
    storage: str
    key: str
    expression: str
    source_kind: str
    source_name: str
    endpoint: str
    http_method: str


@dataclass
class ReadRecord:
    file: str
    line: int
    storage: str
    key: str
    var: str
    expression: str
    endpoint: str
    http_method: str


@dataclass
class SinkRecord:
    file: str
    line: int
    vuln_type: str
    expression: str
    sink_text: str


_SOURCE_PATTERNS = [
    (re.compile(r"request\s*\.\s*getParameter\s*\(\s*[\"']([^\"']+)[\"']"), "query"),
    (re.compile(r"request\s*\.\s*getHeader\s*\(\s*[\"']([^\"']+)[\"']"), "header"),
    (re.compile(r"request\s*\.\s*getCookies\s*\(\s*\)"), "cookie"),
    (re.compile(r"getParameter\s*\(\s*[\"']([^\"']+)[\"']"), "query"),
    (re.compile(r"\$_ (?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]".replace(" ", "")), "query"),
    (re.compile(r"request\.(?:args|form|values|json)\.get\s*\(\s*['\"]([^'\"]+)['\"]"), "query"),
    (re.compile(r"req\.(?:query|body|params)\.([A-Za-z_]\w*)"), "query"),
]


def _source_of(line: str) -> tuple[str, str] | None:
    for pattern, kind in _SOURCE_PATTERNS:
        match = pattern.search(line)
        if match:
            name = match.group(1) if match.groups() else "*"
            return kind, name
    return None


def _param_sources(code: str) -> list[tuple[int, int, str, str, str]]:
    """Spring 注解参数 → (start_line, end_line, var, kind, name)。"""
    result: list[tuple[int, int, str, str, str]] = []
    methods = extract_java_methods(code)
    for method in methods:
        for param in method.params:
            annotation = re.search(
                r"@(RequestParam|PathVariable|RequestBody|RequestHeader|RequestPart)"
                r"\s*(?:\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'])?",
                param,
            )
            if not annotation:
                continue
            kind = {
                "RequestParam": "query", "PathVariable": "path", "RequestBody": "body",
                "RequestHeader": "header", "RequestPart": "upload",
            }.get(annotation.group(1), "query")
            var_match = re.search(r"([A-Za-z_]\w*)\s*$", re.sub(r"@\w+(?:\([^)]*\))?", " ", param).strip())
            if not var_match:
                continue
            var = var_match.group(1)
            name = annotation.group(2) or var
            result.append((method.start_line, method.end_line, var, kind, name))
    return result


def _tainted_map(code: str) -> tuple[dict[str, tuple[str, str, int]], dict[int, dict[str, tuple[str, str]]]]:
    """返回 (全局变量污点, 行号→该行有效污点)。简化版，足够覆盖常见写法。"""
    lines = code.splitlines()
    global_taint: dict[str, tuple[str, str, int]] = {}
    per_line: dict[int, dict[str, tuple[str, str]]] = {}
    param_sources = _param_sources(code)
    for line_no, line in enumerate(lines, 1):
        active = dict(global_taint)
        for start, end, var, kind, name in param_sources:
            if start <= line_no <= end:
                active[var] = (kind, name, start)
        source = _source_of(line)
        if source:
            kind, name = source
            # 找赋值目标
            prefix = line[:line.find(source[1]) if source[1] != "*" else len(line)]
            assign = re.search(r"(?:\$|@)?([A-Za-z_]\w*)\s*:?=\s*[^=]*$", prefix)
            target = assign.group(1) if assign else f"__inline_{line_no}"
            global_taint[target] = (kind, name, line_no)
            active[target] = (kind, name, line_no)
        # 传播
        assign = re.search(r"(?:\$|@)?([A-Za-z_]\w*)\s*:?=\s*([^;]+)", line)
        if assign:
            target, rhs = assign.group(1), assign.group(2)
            inherited = [value for var, value in active.items() if var_reference_pattern(var).search(rhs)]
            if inherited:
                kind, name, _ = inherited[0]
                global_taint[target] = (kind, name, line_no)
                active[target] = (kind, name)
        per_line[line_no] = {var: (value[0], value[1]) for var, value in active.items() if not var.startswith("__inline")}
    return global_taint, per_line


def _endpoint_for(project: Project, file: str, line: int | None = None,
                  method: str | None = None) -> Endpoint | None:
    matches = [item for item in project.endpoints if item.file == file]
    if method:
        matches = [item for item in matches if item.method == method] or matches
    if line is not None and matches:
        before = [item for item in matches if item.line <= line]
        if before:
            return max(before, key=lambda item: item.line)
    return matches[0] if matches else None


def _find_persists(rel: str, code: str, project: Project) -> list[PersistRecord]:
    lines = code.splitlines()
    global_taint, per_line = _tainted_map(code)
    persists: list[PersistRecord] = []
    for line_no, line in enumerate(lines, 1):
        active = per_line.get(line_no, {})
        tainted_vars = [var for var in active if var_reference_pattern(var).search(line)]
        source = _source_of(line)
        if not tainted_vars and not source:
            continue
        source_kind, source_name = (source if source else next(((active[var][0], active[var][1]) for var in tainted_vars), ("unknown", "*")))

        # SQL 写
        sql_match = re.search(r"(?i)\b(?:INSERT\s+INTO|REPLACE\s+INTO|UPDATE|MERGE\s+INTO)\s+[`\"\[]?([A-Za-z_][\w.]*)", line)
        if sql_match and re.search(r"(?i)\b(?:executeUpdate|execute|update|queryForList|queryForObject|jdbc|statement|stmt)\b", line):
            table = sql_match.group(1)
            persists.append(PersistRecord(rel, line_no, "sql", f"sql:{table}", line.strip()[:500],
                                          source_kind, source_name, "", ""))
            continue

        # Session 写
        session = re.search(r"setAttribute\s*\(\s*[\"']([^\"']+)[\"']", line)
        if session:
            persists.append(PersistRecord(rel, line_no, "session", f"session:{session.group(1)}", line.strip()[:500],
                                          source_kind, source_name, "", ""))
            continue

        # Cache 写
        cache = re.search(r"(?:redis|cache|memcache|memcached)\w*\s*\.\s*(?:set|put|add|setex)\s*\(\s*[\"']([^\"']+)[\"']", line, re.IGNORECASE)
        if cache:
            persists.append(PersistRecord(rel, line_no, "cache", f"cache:{cache.group(1)}", line.strip()[:500],
                                          source_kind, source_name, "", ""))

    # 绑定端点：按行号选择最近的、位于写点之前的映射
    for persist in persists:
        endpoint = _endpoint_for(project, rel, line=persist.line)
        if endpoint:
            persist.endpoint = endpoint.path
            persist.http_method = endpoint.method
    return persists


def _find_reads(rel: str, code: str, project: Project) -> list[ReadRecord]:
    lines = code.splitlines()
    reads: list[ReadRecord] = []
    for line_no, line in enumerate(lines, 1):
        assign = re.search(r"(?:\$|@)?([A-Za-z_]\w*)\s*:?=\s*(.+)", line)
        var = assign.group(1) if assign else ""
        # SQL 读
        if re.search(r"(?i)\bSELECT\b", line):
            table = re.search(r"(?i)\bFROM\s+[`\"\[]?([A-Za-z_][\w.]*)", line)
            if table and var:
                reads.append(ReadRecord(rel, line_no, "sql", f"sql:{table.group(1)}", var, line.strip()[:500], "", ""))
        # Session 读
        session = re.search(r"getAttribute\s*\(\s*[\"']([^\"']+)[\"']", line)
        if session and var:
            reads.append(ReadRecord(rel, line_no, "session", f"session:{session.group(1)}", var, line.strip()[:500], "", ""))
        # Cache 读
        cache = re.search(r"(?:redis|cache|memcache|memcached)\w*\s*\.\s*(?:get|mget)\s*\(\s*[\"']([^\"']+)[\"']", line, re.IGNORECASE)
        if cache and var:
            reads.append(ReadRecord(rel, line_no, "cache", f"cache:{cache.group(1)}", var, line.strip()[:500], "", ""))
        # 文件读
        file_read = re.search(r"(?:Files\s*\.\s*(?:readAllBytes|readString|newInputStream)|FileInputStream|file_get_contents|open)\s*\(", line)
        if file_read and var:
            reads.append(ReadRecord(rel, line_no, "file", "file:last", var, line.strip()[:500], "", ""))
    for read in reads:
        endpoint = _endpoint_for(project, rel, line=read.line)
        if endpoint:
            read.endpoint = endpoint.path
            read.http_method = endpoint.method
    return reads


def _find_sinks(rel: str, line_no: int, line: str, read_var: str) -> SinkRecord | None:
    if not var_reference_pattern(read_var).search(line):
        return None
    # 参数化/绑定：安全
    if re.search(r"\?\s*[,)]|\bset(?:String|Int|Long|Object)\s*\(", line):
        return None
    # 必须存在拼接/格式化迹象，否则只是把值当普通参数
    concat = bool(re.search(
        rf"(?:\+|%|\.format\s*\(|f[\"'][^\"']*\{{\s*{re.escape(read_var)}\s*\}}|\.join\s*\()",
        line,
    ))
    if not concat:
        return None
    for pattern, vuln in (
        (r"\.\s*(?:executeQuery|executeUpdate|execute|queryForList|queryForObject|query|update|batchUpdate)\s*\(", "second_order_injection"),
        (r"(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder|exec\.Command|os\.system|subprocess\.(?:run|Popen))\s*\(", "second_order_injection"),
        (r"(?:\.process\s*\(|render_template_string|Template\s*\()", "second_order_injection"),
        (r"(?:FileOutputStream|Files\s*\.\s*write|file_put_contents|open\s*\()", "second_order_injection"),
        (r"(?:getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println)|res\.send|innerHTML)", "second_order_injection"),
    ):
        if re.search(pattern, line):
            return SinkRecord(rel, line_no, vuln, line.strip()[:400], line.strip()[:500])
    return None


def _poc_plan(chain: SecondOrderChain, project: Project) -> PocPlan:
    store_ep = next((item for item in project.endpoints if item.path == chain.endpoint_store), None)
    trigger_ep = next((item for item in project.endpoints if item.path == chain.endpoint_trigger), None)
    store_method = (store_ep.method if store_ep else "POST").upper()
    trigger_method = (trigger_ep.method if trigger_ep else "GET").upper()
    param = chain.source_name if chain.source_name not in {"", "*"} else "name"
    payload = "x' OR '1'='1' -- SUNSET2O"
    encoded = quote(payload, safe="")
    base = "http://TARGET:8080"
    store_url = f"{base}{chain.endpoint_store or '/'}"
    trigger_url = f"{base}{chain.endpoint_trigger or chain.endpoint_store or '/'}"
    if store_method in {"POST", "PUT", "PATCH"}:
        store_request = (
            f"curl -sS -X {store_method} '{store_url}' \\\n"
            f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
            f"  --data '{param}={encoded}'"
        )
    else:
        store_request = f"curl -sS -X {store_method} '{store_url}?{param}={encoded}'"
    trigger_request = f"curl -sS -X {trigger_method} '{trigger_url}'"
    marker = "SUNSET2O"
    return PocPlan(
        description=(
            "两阶段二次注入：第一阶段把带标记的注入载荷写入持久化存储；"
            "第二阶段触发读取已存储值并拼接进危险汇点。"
        ),
        preconditions=[
            "第一阶段与第二阶段访问同一应用、同一数据库/session/cache 命名空间",
            "存储写点缺少参数化或上下文相关转义",
            "读取后的值在第二上下文未再次校验",
        ],
        steps=[
            {"step": 1, "action": f"写入载荷到 {chain.storage}（{chain.storage_key}）",
             "request": store_request, "expected_response": "写入成功（2xx/3xx），无参数化拒绝"},
            {"step": 2, "action": "触发读取已存储值",
             "request": trigger_request, "expected_response": f"响应出现 {marker} 标记、SQL 报错、全量数据或异常行为"},
            {"step": 3, "action": "确认持久化值在第二阶段进入 sink",
             "request": "（静态证据）见 exploit_chain 的 store→read→sink 三步",
             "expected_response": "无需动态验证；以响应差异/错误作为人工复核依据"},
        ],
        payload=payload,
        impact="攻击者可绕过第一阶段的净化，在第二阶段改变 SQL/命令/模板语义，造成数据泄露、越权或 RCE。",
        cve_justification=(
            f"符合 {meta(chain.vuln_type).cwe}。二次注入具有外部可达入口、跨请求持久化、"
            "读取后进入危险汇点三个要素；第一阶段的安全检查无法覆盖第二阶段上下文。"
        ),
        scripts={
            "poc_store.sh": "#!/usr/bin/env sh\nset -eu\n" + store_request + "\n",
            "poc_trigger.sh": "#!/usr/bin/env sh\nset -eu\n" + trigger_request + "\n",
            "poc_all.sh": "#!/usr/bin/env sh\nset -eu\n" + store_request + "\n" + trigger_request + "\n",
        },
        safety={
            "executed": False,
            "network_egress": False,
            "requires_authorization": True,
            "target_uses_placeholder": True,
            "warnings": [],
            "policy": "两阶段 POC 仅为文本工件；管线不执行、不联网。",
        },
    )


def analyze_second_order(project: Project, contents: dict[str, str], *, max_chains: int = 30) -> list[SecondOrderChain]:
    persists: list[PersistRecord] = []
    reads: list[ReadRecord] = []
    files = [file for file in project.files if file.is_text and file.language in {"java", "kotlin", "python", "php", "javascript", "typescript", "csharp", "ruby"}]
    for file in files:
        text = contents.get(file.rel_path, "")
        if not text:
            continue
        code = strip_comments(text, file.language)
        persists.extend(_find_persists(file.rel_path, code, project))
        reads.extend(_find_reads(file.rel_path, code, project))

    chains: list[SecondOrderChain] = []
    persist_by_key: dict[str, list[PersistRecord]] = {}
    for persist in persists:
        persist_by_key.setdefault(persist.key, []).append(persist)

    for read in reads:
        candidates = persist_by_key.get(read.key, [])
        if not candidates:
            continue
        # 同文件优先取读取点之前最近的写点；跨文件取最后一个
        same_file = [item for item in candidates if item.file == read.file and item.line <= read.line]
        persist = same_file[-1] if same_file else candidates[-1]
        # 在 read 之后找 sink
        code = strip_comments(contents.get(read.file, ""), "java") if read.file.endswith(".java") else contents.get(read.file, "")
        lines = code.splitlines()
        sink = None
        for line_no in range(read.line + 1, min(len(lines), read.line + 60) + 1):
            sink = _find_sinks(read.file, line_no, lines[line_no - 1], read.var)
            if sink:
                break
        if not sink:
            continue
        chain_id = "SO-" + hashlib.sha1(f"{persist.file}:{persist.line}:{read.file}:{read.line}:{sink.line}".encode()).hexdigest()[:12]
        steps = [
            ChainStep(step=1, location=f"{persist.file}:{persist.line}",
                      description=f"请求 A 的 {persist.source_kind} `{persist.source_name}` 被写入 {persist.storage}（{persist.key}）",
                      data_state="污点被持久化，跨请求仍存在",
                      bypass_reason="存储层不区分代码/数据，写入成功不代表安全"),
            ChainStep(step=2, location=f"{read.file}:{read.line}",
                      description=f"请求 B 从 {read.storage}（{read.key}）读出到变量 {read.var}",
                      data_state="持久化数据被重新加载为程序变量",
                      bypass_reason="读取路径通常不再做输入校验"),
            ChainStep(step=3, location=f"{read.file}:{sink.line}",
                      description=f"读出的 {read.var} 被拼接进危险汇点：{sink.sink_text}",
                      data_state="二次污点进入 sink",
                      bypass_reason="第一阶段净化与第二阶段上下文不匹配；未参数化/未白名单"),
        ]
        chain = SecondOrderChain(
            chain_id=chain_id,
            vuln_type=sink.vuln_type,
            file=read.file,
            store_line=persist.line,
            read_line=read.line,
            sink_line=sink.line,
            storage=persist.storage,
            storage_key=persist.key,
            source_kind=persist.source_kind,
            source_name=persist.source_name,
            endpoint_store=persist.endpoint or (read.endpoint or ""),
            endpoint_trigger=read.endpoint or "",
            chain=steps,
            confidence=0.88 if persist.file == read.file else 0.8,
            notes=[
                "静态验证：store→read→sink 三要素齐全",
                "未执行两阶段 POC；需要人工/授权环境复核",
                "存储时净化不等于读取时安全",
            ],
        )
        chain.poc = _poc_plan(chain, project)
        chains.append(chain)
        if len(chains) >= max_chains:
            break

    # 去重
    seen: set[tuple[str, int]] = set()
    unique: list[SecondOrderChain] = []
    for chain in chains:
        key = (chain.file, chain.sink_line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(chain)
    return unique


def second_order_finding(chain: SecondOrderChain) -> dict:
    """把 SecondOrderChain 转成与 Finding 兼容的 dict（供 PocWriter/报告使用）。"""
    item = meta(chain.vuln_type)
    return {
        "finding_id": chain.chain_id,
        "vulnerability_type": chain.vuln_type,
        "severity": item.default_severity,
        "title": f"{Path(chain.file).stem} 二次注入（{item.cwe}）",
        "description": "攻击者输入先被持久化，随后在另一个请求/上下文中被读出并拼接进危险汇点，形成跨请求二次注入。",
        "file_path": chain.file,
        "line_start": chain.store_line,
        "line_end": chain.sink_line,
        "source": f"{chain.source_kind} `{chain.source_name}` → {chain.storage} `{chain.storage_key}`",
        "sink": f"{chain.file}:{chain.sink_line}",
        "confidence": chain.confidence,
        "verdict": "candidate",
        "exploit_chain": [step.to_dict() for step in chain.chain],
        "poc": chain.poc.to_dict() if chain.poc else {},
        "notes": chain.notes,
    }
