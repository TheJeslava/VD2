"""URL/AWVS finding adapters for the VulnCatcher URL pipeline.

AWVS is a dynamic scanner: its findings have a URL, a request, and runtime
evidence, but no source file/line.  These adapters keep that contract intact
(``file_path=""``), preserve the raw request as a replayable POC, and build the
same ``Finding`` shape used by the zip pipeline so the report/POC writers work
unchanged.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Any

from .awvs import AwvsVulnerability, _map_type, _normalize_severity, _path_of
from .models import Candidate, ChainStep, Finding, PocPlan
from .security.guard import inspect_poc_safety
from .taxonomy import canonical, meta

_SAFE_VALUE = {
    "command_injection": "ECHOOO",
    "sql_injection": "test",
    "blind_sql_injection": "1",
    "xss": "SafeText",
    "path_traversal": "FileName",
    "ldap_injection": "Ms Bar",
    "xpath_injection": "SafeText",
    "insecure_cookie": "whatever",
}

_SUGGESTION = {
    "command_injection": "Do not pass request data to a shell; use an argument-vector process API and an allowlist.",
    "sql_injection": "Use parameterized statements; never concatenate request data into SQL.",
    "xss": "Encode output for the correct context and add a restrictive CSP.",
    "path_traversal": "Canonicalize the path and require it to stay under the allowed directory.",
    "ldap_injection": "Escape LDAP filter metacharacters and use a fixed filter template.",
    "xpath_injection": "Use a fixed XPath expression with variable binding; never concatenate input.",
    "insecure_cookie": "Set Secure and HttpOnly on session cookies; use a narrow Path and SameSite.",
}


def parse_raw_request(raw: str) -> dict[str, Any]:
    text = (raw or "").replace("\r\n", "\n").strip("\n")
    if not text:
        return {}
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    first = lines[0].split()
    method = first[0].upper() if first else "GET"
    path = first[1] if len(first) > 1 else "/"
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.append((key.strip(), value.strip()))
    return {"method": method, "path": path, "headers": headers, "body": body}


def _safe_value_for(vuln_type: str) -> str:
    return _SAFE_VALUE.get(vuln_type, "SafeText")


def _infer_channel(vuln: AwvsVulnerability, parsed: dict[str, Any]) -> tuple[str, str]:
    if vuln.channel:
        return vuln.channel, vuln.parameter
    headers = {key.lower(): value for key, value in parsed.get("headers", [])}
    if "cookie" in headers:
        cookie = headers["cookie"].split(";", 1)[0]
        name = cookie.split("=", 1)[0].strip()
        return "cookie", name
    body = parsed.get("body", "")
    if body and "=" in body:
        name = body.split("=", 1)[0]
        return "body", name
    # A custom header is a common AWVS insertion point; report the first
    # non-standard one if present.
    standard = {"host", "user-agent", "accept", "accept-encoding", "connection",
                "content-type", "content-length", "referer", "origin"}
    for key, _ in parsed.get("headers", []):
        if key.lower() not in standard:
            return "header", key
    if "referer" in headers:
        return "header", "Referer"
    return "query", "param"


def _request_path(vuln: AwvsVulnerability, parsed: dict[str, Any]) -> str:
    path = str(parsed.get("path") or "")
    if path:
        return path
    return _path_of(vuln.url) or "/"


def _curl_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _raw_to_curl(raw: str, target_host: str = "TARGET:8080") -> str:
    parsed = parse_raw_request(raw)
    if not parsed:
        return ""
    method = parsed["method"]
    path = parsed["path"]
    url = f"http://{target_host}{path}"
    parts = [f"curl -sS -i -X {method} {_curl_quote(url)}"]
    skip = {"host", "content-length", "connection", "accept-encoding"}
    for key, value in parsed["headers"]:
        if key.lower() in skip:
            continue
        parts.append(f"  -H {_curl_quote(f'{key}: {value}')}")
    body = parsed["body"]
    if body:
        parts.append(f"  --data-binary {_curl_quote(body)}")
    return " \\\n".join(parts)


def _raw_with_target(raw: str, target_host: str = "TARGET") -> str:
    parsed = parse_raw_request(raw)
    if not parsed:
        return raw
    lines = [f"{parsed['method']} {parsed['path']} HTTP/1.1", f"Host: {target_host}"]
    skip = {"host", "content-length"}
    for key, value in parsed["headers"]:
        if key.lower() in skip:
            continue
        lines.append(f"{key}: {value}")
    body = parsed["body"]
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def _fallback_request(vuln: AwvsVulnerability, channel: str, parameter: str) -> str:
    method = (vuln.method or "POST").upper()
    path = _path_of(vuln.url) or "/"
    payload = vuln.payload or "SUNSET_PROBE"
    encoded = urllib.parse.quote(payload, safe="")
    lines = [f"{method} {path} HTTP/1.1", "Host: TARGET"]
    if channel == "cookie":
        lines.append(f"Cookie: {parameter}={encoded}")
    elif channel == "header":
        lines.append(f"{parameter}: {encoded}")
    elif channel == "body":
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(f'{parameter}={encoded}')}")
        lines.append("")
        lines.append(f"{parameter}={encoded}")
    else:
        lines[0] = f"{method} {path}{'&' if '?' in path else '?'}{parameter}={encoded} HTTP/1.1"
    lines.append("")
    return "\r\n".join(lines)


def _extract_payload(parsed: dict[str, Any], channel: str, parameter: str) -> str:
    headers = {key.lower(): value for key, value in parsed.get("headers", [])}
    if channel == "cookie" and "cookie" in headers:
        for part in headers["cookie"].split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip() == parameter:
                    return urllib.parse.unquote(value.strip())
    if channel == "header":
        for key, value in parsed.get("headers", []):
            if key == parameter:
                return urllib.parse.unquote(value)
    body = parsed.get("body", "")
    if body:
        for part in body.split("&"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key == parameter or not parameter:
                    return urllib.parse.unquote(value)
    path = parsed.get("path", "")
    if "?" in path:
        query = urllib.parse.parse_qs(path.split("?", 1)[1])
        if parameter in query and query[parameter]:
            return query[parameter][0]
    return ""


def build_url_poc(vuln: AwvsVulnerability, target_url: str) -> PocPlan:
    vuln_type = _map_type(vuln.vt_name, vuln.cwe)
    item = meta(vuln_type)
    parsed = parse_raw_request(vuln.request)
    channel, parameter = _infer_channel(vuln, parsed)
    raw = vuln.request.strip()
    if not raw:
        raw = _fallback_request(vuln, channel, parameter)
    raw = _raw_with_target(raw, "TARGET")
    curl = _raw_to_curl(raw, "TARGET:8080")
    if not curl:
        curl = f"curl -sS -i -X {vuln.method or 'POST'} 'http://TARGET:8080{_path_of(vuln.url)}'"

    payload = vuln.payload or _extract_payload(parsed, channel, parameter)
    safe = _safe_value_for(vuln_type)
    baseline_raw = raw
    if payload:
        baseline_raw = raw.replace(urllib.parse.quote(payload, safe=""), urllib.parse.quote(safe, safe=""))
        baseline_raw = baseline_raw.replace(payload, safe)
    baseline_curl = _raw_to_curl(baseline_raw, "TARGET:8080")
    if not baseline_curl:
        method = (vuln.method or "POST").upper()
        baseline_curl = f"curl -sS -i -X {method} 'http://TARGET:8080{_path_of(vuln.url)}'"

    expected = {
        "command_injection": "The response contains command output (uid=/gid=) or the probe marker.",
        "sql_injection": "The response contains a SQL error or a different row set than the baseline.",
        "blind_sql_injection": "The boolean/time response differs from the baseline without direct data disclosure.",
        "xss": "The response contains the raw script payload without HTML encoding.",
        "path_traversal": "The response reflects/contains a traversal path or the content of a file outside testfiles/.",
        "ldap_injection": "The response differs from the baseline (authentication bypass, LDAP error, or extra entries).",
        "xpath_injection": "The response contains a different result set or an XPath error.",
        "insecure_cookie": "The Set-Cookie header for the sensitive cookie lacks the Secure flag.",
    }.get(vuln_type, "The attack response differs from the baseline in status, length, or a security-relevant marker.")

    description = (
        f"AWVS candidate on {vuln.url} ({vuln.vt_name}). "
        f"Injection channel: {channel} `{parameter}`. "
        f"Raw request is preserved; the verifier resolves TARGET and replays it."
    )
    scripts = {
        "poc.sh": (
            "#!/usr/bin/env sh\n"
            "set -eu\n"
            "# Authorized testing only. Replace TARGET after review.\n"
            f"{curl}\n"
        ),
        "request.http": raw + "\n",
    }
    plan = PocPlan(
        description=description,
        preconditions=[
            "Target is running and the endpoint is reachable.",
            f"Input channel: {channel} `{parameter}`.",
            "The POC is passive text; 落日验证 owns execution against an allowlisted local target.",
        ],
        steps=[
            {"step": 1, "action": "Baseline request", "request": baseline_curl,
             "expected_response": "HTTP 200 and the normal application response."},
            {"step": 2, "action": f"Replay the AWVS attack request ({item.label_zh})", "request": curl,
             "expected_response": expected},
            {"step": 3, "action": "Compare baseline and attack responses",
             "request": "", "expected_response": "A security-relevant differential appears."},
        ],
        payload=payload,
        impact=f"AWVS reported {item.label_zh} at {vuln.url}; this can lead to unauthorized data access or execution depending on the endpoint.",
        cve_justification=(
            f"AWVS candidate: {vuln.vt_name}; CWE={item.cwe}. "
            "Dynamic evidence came from the scanner/local probe; source mapping is unavailable in URL mode."
        ),
        scripts=scripts,
    )
    plan.safety = inspect_poc_safety(scripts, payload)
    plan.safety.update({
        "target_url": target_url,
        "target_uses_placeholder": True,
        "source_tool": vuln.source or "awvs",
        "channel": channel,
        "parameter": parameter,
        "evidence": vuln.evidence,
    })
    return plan


def candidate_from_vuln(vuln: AwvsVulnerability, target_url: str) -> Candidate:
    vuln_type = _map_type(vuln.vt_name, vuln.cwe)
    if vuln_type == "other":
        vuln_type = canonical(vuln.vt_name)
    item = meta(vuln_type)
    parsed = parse_raw_request(vuln.request)
    channel, parameter = _infer_channel(vuln, parsed)
    method = (vuln.method or parsed.get("method") or "GET").upper()
    endpoint = _request_path(vuln, parsed)
    if "?" in endpoint:
        endpoint = endpoint.split("?", 1)[0]
    digest = hashlib.sha1(f"{vuln.vt_name}:{vuln.url}:{vuln.request}".encode("utf-8", errors="replace")).hexdigest()[:12]
    return Candidate(
        candidate_id=f"URL-{digest}",
        vuln_type=vuln_type,
        file="",
        line_start=0,
        line_end=0,
        rule_id=f"awvs:{vuln.vt_name}",
        sink=f"{method} {endpoint}",
        source_kind=channel,
        source_name=parameter,
        endpoint=endpoint,
        http_method=method,
        code_snippet=(vuln.request or "")[:3000],
        tainted_expression=vuln.payload,
        chain=[
            ChainStep(step=1, location=vuln.url, description=f"AWVS identified {vuln.vt_name}"),
            ChainStep(step=2, location=f"{method} {endpoint}", description=f"Replay request via {channel} `{parameter}`"),
        ],
        severity=_normalize_severity(vuln.severity),
        confidence=0.78,
        origin="awvs",
        notes=[vuln.details[:800]] if vuln.details else [],
    )


def finding_from_url_candidate(candidate: Candidate, vuln: AwvsVulnerability, target_url: str) -> Finding:
    item = meta(candidate.vuln_type)
    poc = build_url_poc(vuln, target_url)
    title = f"AWVS: {vuln.vt_name}"
    description = (
        f"AWVS reported `{vuln.vt_name}` at `{vuln.url}`. "
        f"Evidence: {vuln.details[:1500] or vuln.evidence or 'scanner result'}. "
        "This URL-mode finding has no source file/line; it must be validated dynamically."
    )
    source = f"{candidate.source_kind} `{candidate.source_name}` @ {vuln.url}"
    sink = f"{candidate.http_method} {candidate.endpoint}"
    finding = Finding(
        finding_id=candidate.candidate_id,
        vulnerability_type=candidate.vuln_type,
        severity=candidate.severity,
        title=title,
        description=description,
        file_path="",
        line_start=0,
        line_end=0,
        code_snippet=candidate.code_snippet,
        source=source,
        sink=sink,
        suggestion=_SUGGESTION.get(candidate.vuln_type, "Replay the reported request, confirm the impact, and fix the underlying sink."),
        confidence=candidate.confidence,
        needs_verification=True,
        verdict="candidate",
        exploit_chain=candidate.chain,
        poc=poc,
        impact=f"AWVS dynamic candidate; impact depends on the endpoint and payload. CWE={item.cwe}.",
        cve_justification=(
            f"AWVS dynamic candidate `{vuln.vt_name}` (CWE={item.cwe}) at `{vuln.url}`. "
            "No source mapping is claimed in URL mode; dynamic replay is the evidence path."
        ),
        verification_notes=(
            "AWVS candidate from URL mode. Not verified by this pipeline; "
            "落日验证 should replay the preserved request against the allowlisted target."
        ),
        endpoint=candidate.endpoint,
        http_method=candidate.http_method,
        origin="awvs",
        evidence_level="external_only",
        external_evidence=[{
            "source": vuln.source or "awvs",
            "vt_name": vuln.vt_name,
            "url": vuln.url,
            "severity": vuln.severity,
            "cwe": vuln.cwe,
            "details": vuln.details[:1200],
            "evidence": vuln.evidence,
        }],
        safety={
            "executed": False,
            "network_egress": False,
            "requires_authorization": True,
            "target_url": target_url,
            "external_scanner": vuln.source or "awvs",
        },
        score=round(candidate.confidence * 10 + {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(candidate.severity, 20), 2),
    )
    return finding
