"""授权 / 越权 / 业务逻辑的启发式规则。

这类问题很难仅靠正则做到零误报，因此这里只产出「需要复核的候选」：
- auth_bypass：JWT 校验关闭、客户端角色参与权限判断、可信头伪造；
- idor：客户端对象 ID 直达数据访问且没有归属/租户校验；
- business_logic：金额/数量/折扣/状态等业务字段由客户端控制且缺少边界校验。
候选默认带较低置信度，最终由 CandidateScreener/VulnerabilityAnalyzer 与人工复核决定。
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..models import Candidate, ChainStep, Endpoint, TaintOrigin
from ..taxonomy import meta
from .common import extract_java_methods, strip_comments

_AUTH_TOKENS = (
    "preauthorize", "secured", "rolesallowed", "securitycontext", "getprincipal",
    "getuserid", "getownerid", "ownerid", "tenantid", "checkowner", "checkpermission",
    "authorize", "isadmin", "hasrole", "haspermission",
)
_IDOR_READ = re.compile(
    r"findById|getById|select\s+[^;]{0,200}?\bwhere\b[^;]{0,80}?\bid\s*=|"
    r"queryForObject\([^;]{0,200}?id|repository\.\w+\([^)]*\bid\b|"
    r"\.load\([^)]*\bid\b",
    re.IGNORECASE,
)
_IDOR_ID_PARAM = re.compile(
    r"@(PathVariable|RequestParam|RequestHeader)\s*(?:\([^)]*\))?\s+[\w<>\[\],.?]+\s+(\w*[Ii]d)\b"
)
_IDOR_PATH = re.compile(r"\{[^}]*[Ii]d[^}]*\}|:[A-Za-z_]*[Ii]d\b")
_BUSINESS_PARAM = re.compile(
    r"@(RequestParam|RequestBody|PathVariable)\s*(?:\([^)]*\))?\s+[\w<>\[\],.?]+\s+"
    r"(amount|price|quantity|discount|coupon|balance|credit|role|status|level)\b",
    re.IGNORECASE,
)
_BUSINESS_WRITE = re.compile(
    r"set(?:Amount|Price|Quantity|Discount|Balance|Credit|Role|Status|Level)\s*\(|"
    r"(?:update|insert|save)\b[^;]{0,120}?(?:amount|price|quantity|discount|balance|credit|role|status)|"
    r"\b(?:pay|transfer|withdraw|redeem|refund)\b",
    re.IGNORECASE,
)
_VALIDATION = re.compile(
    r"compareTo|signum|BigDecimal\.ZERO|@Min|@Max|@Positive|@DecimalMin|@DecimalMax|"
    r"validate|checkAmount|isValid|hasRole|hasPermission|preauthorize|secured",
    re.IGNORECASE,
)
_RACE = re.compile(r"\b(?:exists|count|findBy\w+)\b[\s\S]{0,200}?\b(?:save|insert|create|update)\b", re.IGNORECASE)
# 字符串字面量里的 SQL/DDL 不是 check-then-act：初始化脚本（DROP TABLE IF EXISTS / CREATE TABLE）
# 会被 _RACE 误命中，因此竞态判断只在剥离字面量后的代码上做。
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
# 匹配窗口里必须至少出现一个标识符引用（变量 / 方法调用），避免纯注释或纯标点命中。
_RACE_IDENT = re.compile(r"[A-Za-z_$][\w$]*\s*(?:\(|\.|\[|;|\)|\s*[=<>!+\-])")


def _strip_literals(text: str) -> str:
    return _STRING_LITERAL.sub('""', text)


def _endpoint_for(endpoints: list[Endpoint], rel: str, method) -> Endpoint | None:
    for endpoint in endpoints:
        if endpoint.file == rel and endpoint.handler == method.name:
            return endpoint
    for endpoint in endpoints:
        if endpoint.file == rel:
            return endpoint
    return None


def _candidate(vuln_type: str, rel: str, line: int, sink: str, source_kind: str,
               source_name: str, endpoint: str, http_method: str, chain: list[ChainStep],
               confidence: float, note: str) -> Candidate:
    item = meta(vuln_type)
    return Candidate(
        candidate_id="LOGIC-" + hashlib.sha1(f"{rel}:{line}:{vuln_type}:{source_name}".encode()).hexdigest()[:12],
        vuln_type=vuln_type,
        file=rel,
        line_start=max(1, line - 2),
        line_end=line,
        rule_id=f"logic-{vuln_type}",
        sink=sink[:500],
        source_kind=source_kind,
        source_name=source_name,
        endpoint=endpoint,
        http_method=http_method,
        code_snippet=f"{line}: {sink[:400]}",
        tainted_expression=sink[:400],
        chain=chain,
        severity=item.default_severity,
        confidence=confidence,
        origin="rule",
        notes=[note, "启发式候选；需人工确认授权/业务边界"],
    )


def analyze_logic(rel: str, text: str, endpoints: list[Endpoint]) -> list[Candidate]:
    code = strip_comments(text, "java")
    methods = extract_java_methods(code)
    results: list[Candidate] = []
    lines = code.splitlines()
    for method in methods:
        body = "\n".join(lines[method.start_line - 1:method.end_line])
        endpoint = _endpoint_for(endpoints, rel, method)
        endpoint_path = endpoint.path if endpoint else f"/{Path(rel).stem}"
        http_method = endpoint.method if endpoint else "ANY"
        body_lower = body.lower()

        # ---- auth_bypass ----
        jwt = re.search(r"(?i)\b(?:jwt|jsonwebtoken|jjwt)\b[^\n]{0,160}", body)
        if jwt and re.search(r"(?i)verify\s*\(\s*false|algorithms?\s*[:=]\s*['\"]none|setSigningKey\s*\(\s*['\"]", body):
            line = method.start_line + body_lower[:body_lower.find(jwt.group(0).lower())].count("\n")
            chain = [
                ChainStep(step=1, location=f"{rel}:{method.start_line}", description="JWT 校验逻辑"),
                ChainStep(step=2, location=f"{rel}:{line}", description="校验被关闭/使用 none 算法/固定密钥",
                          bypass_reason="攻击者可伪造任意 claims"),
            ]
            results.append(_candidate("auth_bypass", rel, line, jwt.group(0), "token", "JWT",
                                      endpoint_path, http_method, chain, 0.8, "JWT 校验缺陷"))
        role = re.search(r"getParameter\s*\(\s*[\"'](role|isAdmin|admin)[\"']", body, re.IGNORECASE)
        if role and re.search(r"if\s*\([^)]*(?:role|admin)", body, re.IGNORECASE):
            line = method.start_line + body_lower[:body_lower.find(role.group(0).lower())].count("\n")
            chain = [
                ChainStep(step=1, location=f"{rel}:{line}", description="从请求参数读取角色/管理员标志"),
                ChainStep(step=2, location=f"{rel}:{line}", description="该值直接参与权限判断",
                          bypass_reason="客户端可自行设置 role/admin"),
            ]
            results.append(_candidate("auth_bypass", rel, line, role.group(0), "query", role.group(1),
                                      endpoint_path, http_method, chain, 0.72, "客户端角色参与鉴权"))
        xff = re.search(r"getHeader\s*\(\s*[\"']X-Forwarded-For[\"']", body, re.IGNORECASE)
        if xff and re.search(r"internal|trusted|admin|allow", body, re.IGNORECASE):
            line = method.start_line + body_lower[:body_lower.find(xff.group(0).lower())].count("\n")
            chain = [ChainStep(step=1, location=f"{rel}:{line}", description="使用可伪造的 X-Forwarded-For 判断来源可信")]
            results.append(_candidate("auth_bypass", rel, line, xff.group(0), "header", "X-Forwarded-For",
                                      endpoint_path, http_method, chain, 0.68, "可信头可被客户端伪造"))

        # ---- idor ----
        id_param = _IDOR_ID_PARAM.search(body)
        has_id_path = bool(_IDOR_PATH.search(endpoint_path or ""))
        if (id_param or has_id_path) and _IDOR_READ.search(body):
            source_name = id_param.group(2) if id_param else "id"
            source_kind = "path" if (has_id_path or (id_param and id_param.group(1) == "PathVariable")) else "query"
            read = _IDOR_READ.search(body)
            line = method.start_line + body[:read.start()].count("\n")
            if not any(token in body_lower for token in _AUTH_TOKENS):
                chain = [
                    ChainStep(step=1, location=f"{rel}:{method.start_line}",
                              description=f"入口 {http_method} {endpoint_path} 接受客户端对象 ID `{source_name}`"),
                    ChainStep(step=2, location=f"{rel}:{line}",
                              description="对象 ID 直接用于数据访问，方法体内未发现归属/租户/角色校验",
                              bypass_reason="替换 ID 即可访问他人对象"),
                ]
                results.append(_candidate("idor", rel, line, read.group(0), source_kind, source_name,
                                          endpoint_path, http_method, chain, 0.64, "疑似 IDOR/越权"))

        # ---- business_logic ----
        biz = _BUSINESS_PARAM.search(body)
        if biz and _BUSINESS_WRITE.search(body) and not _VALIDATION.search(body):
            name = biz.group(2)
            line = method.start_line + body[:biz.start()].count("\n")
            chain = [
                ChainStep(step=1, location=f"{rel}:{line}", description=f"业务字段 `{name}` 来自客户端"),
                ChainStep(step=2, location=f"{rel}:{method.end_line}", description="该字段直接进入金额/库存/角色/状态写入，未见边界校验",
                          bypass_reason="可提交负数、超大值或越权状态"),
            ]
            results.append(_candidate("business_logic", rel, line, biz.group(0), "query", name,
                                      endpoint_path, http_method, chain, 0.6, "业务字段缺少边界校验"))

        # ---- race_condition（仅低优先级） ----
        code_body = _strip_literals(body)
        race = _RACE.search(code_body)
        if race and _RACE_IDENT.search(race.group(0)) and not re.search(
                r"synchronized|ReentrantLock|@Lock|SELECT\s+FOR\s+UPDATE", code_body, re.IGNORECASE):
            line = method.start_line + code_body[:race.start()].count("\n")
            chain = [ChainStep(step=1, location=f"{rel}:{line}", description="check-then-act 缺少锁/原子性")]
            results.append(_candidate("race_condition", rel, line, race.group(0), "query", "race",
                                      endpoint_path, http_method, chain, 0.55, "疑似 TOCTOU 竞态"))

    # 去重
    seen: set[tuple[str, int]] = set()
    unique: list[Candidate] = []
    for item in results:
        key = (item.vuln_type, item.line_end)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
