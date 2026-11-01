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


def validate_poc_contract(finding: Finding, plan: PocPlan) -> dict:
    """Perform passive consistency checks between a finding and its POC.

    This deliberately never executes a generated artifact.  It catches the
    common failure mode where a generic request parameter is used for a
    finding whose source is a session value, header, or another non-request
    source.
    """
    errors: list[str] = []
    warnings: list[str] = []
    scripts = plan.scripts or {}
    text = "\n".join(str(value) for value in scripts.values())
    narrative = "\n".join([plan.description, plan.cve_justification,
                            finding.source, finding.sink])
    static_only = finding.vulnerability_type in {
        "hardcoded_secret", "weak_crypto", "weak_random", "insecure_cookie",
    } or not finding.endpoint

    if not scripts:
        errors.append("缺少 POC 文件")
    if PLACEHOLDER not in text and not static_only:
        errors.append("HTTP POC 未使用 TARGET 占位符")
    if finding.file_path and finding.file_path not in narrative and finding.file_path not in text:
        errors.append(f"POC 未引用 finding 文件 {finding.file_path}")
    if finding.line_start and str(finding.line_start) not in narrative and str(finding.line_end) not in narrative:
        warnings.append("POC 未明确引用 finding 行号")

    if static_only:
        if "poc_readme.md" not in scripts:
            errors.append("静态证据型 POC 缺少 poc_readme.md")
        status = "not_executable" if not errors else "static_inconsistent"
        return {"status": status, "errors": errors, "warnings": warnings,
                "checks": {"static_only": True, "executed": False}}

    endpoint = finding.endpoint or "/"
    if endpoint not in text:
        errors.append(f"请求未包含 finding 端点 {endpoint}")
    method = (finding.http_method or "GET").upper()
    if method not in text.upper():
        errors.append(f"请求未体现 HTTP 方法 {method}")

    source_lower = (finding.source or "").lower()
    text_lower = text.lower()
    if "session" in source_lower and ("?param=" in text_lower or "param=" in text_lower):
        errors.append("finding 来源为 session，但 POC 改用 param 请求参数")
    if "referer" in source_lower and "referer:" not in text_lower:
        errors.append("finding 来源为 Referer，但 POC 未发送 Referer 请求头")
    if ("cookie" in source_lower and finding.vulnerability_type != "weak_id"
            and "cookie:" not in text_lower):
        errors.append("finding 来源为 Cookie，但 POC 未发送 Cookie 请求头")
    if "authorization" in source_lower and "authorization:" not in text_lower:
        errors.append("finding 来源为 Authorization，但 POC 未发送 Authorization 请求头")
    if "source" in narrative.lower() and "injection point" not in narrative.lower():
        warnings.append("POC 叙述未明确标注 source→sink 注入点")

    payload = (plan.payload or "").strip()
    if payload and payload not in text and payload.replace("'", "%27") not in text:
        warnings.append("原始 payload 未直接出现在请求文本中，可能经过 URL 编码")
    status = "static_inconsistent" if errors else "static_consistent"
    return {"status": status, "errors": errors, "warnings": warnings,
            "checks": {"static_only": False, "executed": False,
                        "endpoint": endpoint, "method": method}}


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


def _actual_source_name(candidate: Candidate) -> str:
    """Recover the concrete PHP input name before falling back to a label."""
    text = "\n".join((candidate.code_snippet or "", candidate.tainted_expression or "",
                        candidate.source_name or ""))
    match = re.search(r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]", text, re.I)
    if match:
        return match.group(1)
    labels = {
        "request parameter": "name",
        "password change": "password_new",
        "login/password": "username",
        "captcha/step": "step",
        "external javascript": "include",
        "session cookie": "",
        "api version/user object": "",
    }
    return labels.get((candidate.source_name or "").lower(), candidate.source_name or "param")


def _actual_method(candidate: Candidate, vuln_type: str) -> str:
    method = (candidate.http_method or "GET").upper()
    text = "\n".join((candidate.code_snippet or "", candidate.tainted_expression or "",
                        candidate.source_name or ""))
    if method == "ANY":
        if re.search(r"\$_POST|POST\s*\[", text, re.I):
            return "POST"
        if re.search(r"\$_GET|GET\s*\[", text, re.I):
            return "GET"
    if vuln_type in {"brute_force", "captcha_bypass", "file_upload", "command_injection"} and method == "ANY":
        return "POST"
    return method


def _query_url(url: str, params: list[tuple[str, str]]) -> str:
    encoded = "&".join(f"{quote(str(key), safe='')}={quote(str(value), safe='')}" for key, value in params)
    return url + ("&" if "?" in url else "?") + encoded if encoded else url


def _form_curl(method: str, url: str, body: str) -> str:
    return (
        f"curl -sS -i -X {method} '{url}' \\\n"
        "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
        f"  --data '{body}'"
    )


def _form_raw(method: str, url: str, body: str) -> str:
    path = re.sub(r"^https?://[^/]+", "", url)
    return (f"{method} {path} HTTP/1.1\r\nHost: {PLACEHOLDER}:8080\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}")


def _request_for(candidate: Candidate, payload: str, finding_id: str) -> tuple[str, str, dict[str, str]]:
    """返回 (curl 命令, raw HTTP, 额外说明)。"""
    method = _actual_method(candidate, candidate.vuln_type)
    url = _url(candidate.endpoint)
    kind = (candidate.source_kind or "query").lower()
    name = _actual_source_name(candidate)
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
    elif candidate.vuln_type == "weak_id":
        method = "POST"
        body = ""
        curl = f"curl -sS -i -X POST '{url}' -H 'Content-Type: application/x-www-form-urlencoded'"
        notes["injection_point"] = "POST 会话建立请求；连续请求比较 dvwaSession Cookie"
    elif candidate.vuln_type == "api_info_disclosure":
        method = "GET"
        url = BASE_URL + "/vulnerabilities/api/v2/user/"
        body = ""
        curl = f"curl -sS -i -X GET '{url}'"
        notes["injection_point"] = "公开 API 用户对象响应"
    elif candidate.vuln_type == "idor":
        method = "GET"
        url = _query_url(url, [("action", "View Profile"), ("user_id", "2")])
        headers["Cookie"] = "user_id=1"
        body = ""
        curl = f"curl -sS -i -X GET '{url}' -H 'Cookie: user_id=1'"
        notes["injection_point"] = "查询 user_id=2 与 Cookie user_id=1 的对象归属对照"
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
    elif candidate.vuln_type == "file_upload" or kind == "upload":
        method = "POST"
        boundary = "SUNSET"
        headers["Content-Type"] = "multipart/form-data; boundary=SUNSET"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="Upload"\r\n\r\nUpload\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="uploaded"; filename="{payload}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "SUNSET_POC\r\n"
            f"--{boundary}--\r\n"
        )
        curl = (
            f"curl -sS -i -X {method} '{url}' \\\n"
            "  -F 'Upload=Upload' \\\n"
            f"  -F 'uploaded=@{payload};filename={payload}'"
        )
        notes["injection_point"] = "multipart filename"
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        pairs: list[tuple[str, str]] = [(name, payload)] if name else []
        if candidate.vuln_type == "brute_force":
            method = "GET"
            pairs = [("Login", "Login"), ("username", "admin"), ("password", "wrong")]
        elif candidate.vuln_type == "captcha_bypass":
            method = "POST"
            pairs = [("Change", "Change"), ("step", "2"), ("password_new", "SUNSET_NEW"), ("password_conf", "SUNSET_NEW"), ("g-recaptcha-response", "")]
        elif candidate.vuln_type == "csrf":
            method = "GET"
            pairs = [("Change", "Change"), ("password_new", "SUNSET_NEW"), ("password_conf", "SUNSET_NEW")]
        elif candidate.vuln_type in {"command_injection", "sql_injection"}:
            pairs.append(("Submit", "Submit"))
        body = "&".join(f"{quote(str(key), safe='')}={quote(str(value), safe='')}" for key, value in pairs)
        if method in {"POST", "PUT", "PATCH"}:
            curl = _form_curl(method, url, body)
        else:
            curl = f"curl -sS -i -X {method} '{_query_url(url, pairs)}'"
        notes["injection_point"] = f"{method} 参数 {name or '请求体'}"

    raw = [f"{method} {re.sub(r'^https?://[^/]+', '', url)} HTTP/1.1", f"Host: {PLACEHOLDER}:8080"]
    for key, value in headers.items():
        raw.append(f"{key}: {value}")
    if body and candidate.vuln_type != "file_upload":
        raw.append(f"Content-Length: {len(body.encode('utf-8'))}")
    elif candidate.vuln_type == "file_upload":
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
        "weak_id": "连续请求返回可预测/递增的会话 ID（如 dvwaSession=1,2,3），并可用于会话识别。",
        "csp": "响应包含 Content-Security-Policy，检查 script-src 是否允许过宽的外部脚本源。",
        "api_info_disclosure": "响应或 API 返回未授权的用户对象、版本或敏感字段。",
        "open_redirect": "响应为 30x 且 Location 指向攻击者控制的域名。",
        "idor": "使用与当前主体不匹配的对象 ID 返回另一用户资料。",
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
    if vuln_type == "weak_id":
        # This is an output-observation check: retain the same client cookie
        # jar across repeated POSTs and compare each Set-Cookie response.
        cookie_jar = '"${cookie_jar}"'
        curl_once = curl.replace("curl -sS -i", f"curl -sS -i -b {cookie_jar} -c {cookie_jar}", 1)
        repeated = curl_once.replace("curl -sS -i", "curl -sS -i", 1)
        steps[1] = {"step": 2, "action": "在保持同一会话的情况下第一次 POST，记录 Set-Cookie",
                    "request": curl_once, "expected_response": "返回 dvwaSession 等会话 Cookie，记录其值"}
        steps[2] = {"step": 3, "action": "保持同一会话再次 POST，并比较两次会话 Cookie",
                    "request": repeated, "expected_response": "Cookie 值出现连续递增/可预测序列"}
    elif vuln_type == "brute_force":
        steps[1] = {"step": 2, "action": "发送第一次错误登录请求并记录状态、延迟和响应",
                    "request": curl, "expected_response": "登录失败响应"}
        steps[2] = {"step": 3, "action": "在短时间内重复 5 次以上错误登录",
                    "request": curl, "expected_response": "无锁定、无速率限制、无递增延迟或验证码触发"}
    elif vuln_type in {"csrf", "captcha_bypass"}:
        steps[1]["expected_response"] = "状态改变请求被接受或进入下一步流程"
        steps[2] = {"step": 3, "action": "读取账户状态/重新登录确认状态确实改变",
                    "request": "", "expected_response": "密码或业务状态已改变；请求无需 CSRF token/有效验证码"}
    elif vuln_type == "idor":
        steps[1]["expected_response"] = "返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1"
        steps[2] = {"step": 3, "action": "将 user_id 改为当前用户 ID 做对照",
                    "request": f"curl -sS -i -X GET '{_query_url(_url(candidate.endpoint), [('action', 'View Profile'), ('user_id', '1')])}' -H 'Cookie: user_id=1'",
                    "expected_response": "对照响应只返回当前用户资料，攻击响应返回另一用户资料"}
    poc_script = "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\n"
    if vuln_type == "weak_id":
        poc_script += (
            'cookie_jar="$(mktemp)"\ntrap \'rm -f "$cookie_jar"\' EXIT HUP INT TERM\n'
            + curl_once + "\n" + repeated + "\n"
        )
    else:
        poc_script += curl + "\n"
    scripts = {"poc.sh": poc_script, "request.http": raw + "\n"}
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
