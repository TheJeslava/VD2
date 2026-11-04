"""AWVS-compatible local probe for the ver5 URL pipeline."""
from __future__ import annotations

import html
import http.client
import json
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .awvs import AwvsVulnerability
from .taxonomy import meta

OBSERVABLE = {
    "command_injection", "sql_injection", "blind_sql_injection", "xss",
    "path_traversal", "ldap_injection", "xpath_injection", "insecure_cookie",
    "open_redirect", "csp", "csrf", "file_upload", "api_info_disclosure",
    "auth_bypass", "idor", "brute_force", "captcha_bypass", "weak_id",
    "client_side_validation",
    # ver4 manifest aliases kept for compatibility with existing fixtures.
    "cmdi", "sqli", "sqli_blind", "pathtraver", "ldapi", "xpathi", "securecookie",
}

_TYPE_NAME = {
    "command_injection": "OS Command Injection", "sql_injection": "SQL Injection",
    "blind_sql_injection": "Blind SQL Injection", "xss": "Cross-site Scripting (XSS)",
    "path_traversal": "Path Traversal", "ldap_injection": "LDAP Injection",
    "xpath_injection": "XPath Injection", "insecure_cookie": "Cookie Not Marked as Secure",
    "open_redirect": "Open Redirect", "csp": "Content Security Policy Misconfiguration",
    "csrf": "Cross-Site Request Forgery", "file_upload": "Unrestricted File Upload",
    "api_info_disclosure": "API Information Disclosure", "auth_bypass": "Authentication Bypass",
    "idor": "Insecure Direct Object Reference", "brute_force": "Brute Force Protection Missing",
    "captcha_bypass": "CAPTCHA Bypass", "weak_crypto": "Weak Cryptography",
    "weak_id": "Predictable Session Identifier", "client_side_validation": "Client-side Validation Bypass",
    "second_order_injection": "Second-order SQL Injection",
}

_PAYLOADS = {
    "command_injection": [";echo SUNSET_CMD_MARKER", ";id", "&& id"],
    "sql_injection": ["' OR '1'='1", "'", "1' OR '1'='1' -- "],
    "blind_sql_injection": ["1' AND '1'='1", "1' AND '1'='2", "1' OR SLEEP(2)-- "],
    "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"] ,
    "path_traversal": ["../../../../tmp/sunset_probe.txt", "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    "ldap_injection": ["*)(uid=*))(|(uid=*", "*", "admin)(&)"],
    "xpath_injection": ["' or '1'='1", "' or 1=1 or 'x'='x"],
    "open_redirect": ["https://example.com", "//example.com"],
    "auth_bypass": ["admin", "true", "X-Role: admin"],
    "idor": ["1", "2", "999999"], "brute_force": ["bad-password-1", "bad-password-2", "bad-password-3"],
    "captcha_bypass": ["", "hidd3n_valu3", "0"], "client_side_validation": ["", "invalid", "<invalid>"],
    "csrf": ["Change", "1"], "file_upload": ["sunset.txt", "sunset.jpg"], "weak_id": ["1", "2"],
}
_DEFAULT_VALUE = {
    "command_injection": "127.0.0.1", "sql_injection": "1", "blind_sql_injection": "1", "xss": "SafeText",
    "path_traversal": "include.php", "ldap_injection": "Ms Bar", "xpath_injection": "SafeText",
    "open_redirect": "info.php", "auth_bypass": "guest", "idor": "1", "brute_force": "admin",
    "captcha_bypass": "invalid", "client_side_validation": "English", "csrf": "Change",
    "file_upload": "sunset.txt", "weak_id": "1", "api_info_disclosure": "1", "csp": "1",
}
_PAYLOADS.update({
    "cmdi": _PAYLOADS["command_injection"], "sqli": _PAYLOADS["sql_injection"],
    "sqli_blind": _PAYLOADS["blind_sql_injection"], "pathtraver": _PAYLOADS["path_traversal"],
    "ldapi": _PAYLOADS["ldap_injection"], "xpathi": _PAYLOADS["xpath_injection"],
})
_DEFAULT_VALUE.update({
    "cmdi": _DEFAULT_VALUE["command_injection"], "sqli": _DEFAULT_VALUE["sql_injection"],
    "sqli_blind": _DEFAULT_VALUE["blind_sql_injection"], "pathtraver": _DEFAULT_VALUE["path_traversal"],
    "ldapi": _DEFAULT_VALUE["ldap_injection"], "xpathi": _DEFAULT_VALUE["xpath_injection"],
})

@dataclass
class HttpResponse:
    status: int
    headers: list[tuple[str, str]]
    body: str
    raw_request: str
    elapsed_ms: float = 0.0

def _headers_dict(headers):
    out = {}
    for key, value in headers:
        out.setdefault(key.lower(), value)
    return out

def _connection(url, insecure=True, timeout=15.0):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)

def _send(url, method, path, headers, body, insecure=True, timeout=15.0):
    started = time.perf_counter()
    conn = _connection(url, insecure, timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw_body = response.read(2 * 1024 * 1024)
        body_text = raw_body.decode("utf-8", errors="replace")
        response_headers = list(response.getheaders())
        parsed = urllib.parse.urlsplit(url)
        host = parsed.netloc or (parsed.hostname or "localhost")
        request_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
        if body:
            request_lines.append(f"Content-Length: {len(body)}")
        request_lines.append("")
        if body:
            request_lines.append(body.decode("utf-8", errors="replace"))
        return HttpResponse(response.status, response_headers, body_text, "\r\n".join(request_lines),
                            round((time.perf_counter() - started) * 1000, 2))
    finally:
        conn.close()

def _channel_value(target, value):
    channel = str(target.get("channel") or "query").lower()
    headers = {"User-Agent": "Sunset-AWVS-Probe/2.0", "Accept": "*/*", "Connection": "close"}
    body = b""
    parameter = str(target.get("param_name") or target.get("name") or "test")
    if channel == "cookie":
        headers["Cookie"] = f"{parameter}={urllib.parse.quote(value, safe='')}"
    elif channel == "header":
        headers[parameter] = value
    elif channel == "multipart":
        boundary = "----SunsetAWVSProbeBoundary"
        filename = value or "sunset.txt"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{parameter}\"; filename=\"{filename}\"\r\n"
                "Content-Type: text/plain\r\n\r\nSUNSET_SAFE_UPLOAD\r\n" f"--{boundary}--\r\n").encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(body))
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode({parameter: value}).encode()
        headers["Content-Length"] = str(len(body))
    return headers, body, channel, parameter

def _request(url, target, value, insecure=True):
    method = str(target.get("method") or "GET").upper()
    headers, body, channel, parameter = _channel_value(target, value)
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if channel in {"query", "form"} and method in {"GET", "HEAD", "DELETE"}:
        query.append((parameter, value))
        path += "?" + urllib.parse.urlencode(query)
        body = b""
        headers.pop("Content-Type", None)
        headers.pop("Content-Length", None)
    elif parsed.query:
        path += "?" + parsed.query
    return _send(url, method, path, headers, body, insecure, float(target.get("timeout", 15.0)))

def _markers(category, attack, baseline):
    body = html.unescape(attack.body or "")
    base = html.unescape(baseline.body or "")
    lowered = body.lower()
    headers = _headers_dict(attack.headers)
    if category == "command_injection":
        match = re.search(r"uid=\d+\([^)]*\)|gid=\d+\([^)]*\)|SUNSET_CMD_MARKER", body)
        return (True, match.group(0)[:300], "command output marker") if match else (False, "", "")
    if category in {"sql_injection", "blind_sql_injection"}:
        for marker in ("sqlexception", "sql syntax", "syntax error", "jdbc", "hsqldb", "org.h2", "ora-", "quoted string"):
            if marker in lowered and marker not in base.lower():
                return True, marker, "SQL error marker"
        rows = len(re.findall(r"(?m)^\s*\d+,\s+\S+,\s+\S+", body)); base_rows = len(re.findall(r"(?m)^\s*\d+,\s+\S+,\s+\S+", base))
        if rows > base_rows:
            return True, f"rows {base_rows}->{rows}", "row-set expansion"
        if category == "blind_sql_injection" and (attack.status != baseline.status or abs(len(body) - len(base)) > max(80, len(base) // 2)):
            return True, f"status/length {baseline.status}/{len(base)}->{attack.status}/{len(body)}", "boolean or time differential"
        return (True, f"status {baseline.status}->{attack.status}", "server error") if attack.status >= 500 > baseline.status else (False, "", "")
    if category == "xss":
        for payload in _PAYLOADS["xss"]:
            if payload in attack.body and payload not in baseline.body:
                return True, payload, "unencoded script reflection"
        return False, "", ""
    if category == "path_traversal":
        for marker in ("root:x:0:0", "[extensions]", "for 16-bit app support", "/tmp/sunset_probe", "../", "..\\"):
            if marker.lower() in lowered and marker.lower() not in base.lower():
                return True, marker, "path traversal response"
        return False, "", ""
    if category in {"ldap_injection", "xpath_injection"}:
        for marker in ("exception", "invalid dn", "ldap", "xpath", "could not evaluate"):
            if marker in lowered and marker not in base.lower():
                return True, marker, "parser/error differential"
        return (True, f"length {len(base)}->{len(body)}", "result-set expansion") if len(body) > max(200, len(base) * 1.5) else (False, "", "")
    if category == "insecure_cookie":
        for cookie in [value for key, value in attack.headers if key.lower() == "set-cookie"]:
            parts = [part.strip().lower() for part in cookie.split(";")]
            if parts and "secure" not in parts and re.search(r"session|dvwa|somecookie", parts[0]):
                return True, cookie[:300], "cookie without Secure flag"
        return False, "", ""
    if category == "open_redirect":
        location = headers.get("location", "")
        return (True, location[:300], "external Location header") if attack.status in {301,302,303,307,308} and re.match(r"https?://|//", location, re.I) else (False, "", "")
    if category == "csp":
        policy = headers.get("content-security-policy", "")
        return (True, policy or "missing", "missing or weak CSP") if not policy or "unsafe-inline" in policy.lower() or "*" in policy else (False, "", "")
    if category == "csrf":
        token = re.search(r"csrf|user_token|xsrf|nonce", lowered)
        return (True, "POST form without CSRF token", "state-changing form lacks token") if "<form" in lowered and not token else (False, "", "")
    if category == "file_upload":
        return (True, "upload response", "unrestricted upload response") if re.search(r"uploaded|file was uploaded", lowered) and attack.status < 500 else (False, "", "")
    if category == "api_info_disclosure":
        sensitive = re.search(r"(?:password|passwd|secret|token|api[_-]?key|swagger|openapi|health)\s*[:=]", lowered)
        return (True, sensitive.group(0)[:100] if sensitive else "JSON 200", "API data disclosure") if sensitive or ("application/json" in headers.get("content-type", "") and attack.status == 200) else (False, "", "")
    if category == "auth_bypass":
        privileged = re.search(r"admin|authorized|welcome|dashboard|role", lowered)
        return (True, privileged.group(0) if privileged else f"status {baseline.status}->{attack.status}", "privileged response differential") if attack.status < 400 and (privileged or attack.status != baseline.status) else (False, "", "")
    if category == "idor":
        return (True, f"response length {len(base)}->{len(body)}", "object response changed for alternate ID") if attack.status == 200 and attack.body != baseline.body and len(body) > 20 else (False, "", "")
    if category == "brute_force":
        # A missing route (404/405) is not evidence of a brute-force flaw.
        # Require a live, non-error authentication response before considering
        # the absence of lockout/rate-limit markers.
        live_status = {200, 301, 302, 303, 307, 308}
        return (True, f"status {attack.status}", "no lockout/rate-limit signal") if (
            baseline.status in live_status
            and attack.status in live_status
            and not re.search(r"locked|rate.?limit|too many|captcha", lowered)
        ) else (False, "", "")
    if category == "captcha_bypass":
        return (True, "success after invalid CAPTCHA", "CAPTCHA bypass response") if re.search(r"password changed|success|welcome|authorized", lowered) and not re.search(r"captcha incorrect|invalid captcha", lowered) else (False, "", "")
    if category == "client_side_validation":
        return (True, "client validation markers", "response relies on client validation") if re.search(r"<script|oninput|onchange|pattern=|required", lowered) and attack.status < 400 else (False, "", "")
    if category == "weak_id":
        for cookie in [value for key, value in attack.headers if key.lower() == "set-cookie"]:
            if re.search(r"dvwa(session)?=\d+|session[^=]*=\d+", cookie, re.I):
                return True, cookie[:200], "predictable numeric session value"
        return False, "", ""
    return False, "", ""

def _finding(category, target, url, *, details, request="", channel="", parameter="", payload="", evidence="", evidence_mode="dynamic"):
    return AwvsVulnerability(vt_name=_TYPE_NAME.get(category, category), url=url,
        severity=str(target.get("severity") or meta(category).default_severity), details=details,
        request=request, cwe=str(target.get("cwe") or meta(category).cwe.replace("CWE-", "")),
        raw={"source_tool": "AWVS-LOCAL-PROBE", "category": category, "dataset_category": target.get("dataset_category", ""), "evidence_mode": evidence_mode, "evidence": evidence},
        source="AWVS-LOCAL-PROBE", channel=channel, parameter=parameter, payload=payload, evidence=evidence,
        method=str(target.get("method") or "GET").upper())

def scan_target(target, insecure=True, timeout=15.0):
    category = str(target.get("category") or "").lower()
    aliases = {"cmdi":"command_injection", "exec":"command_injection", "sqli":"sql_injection", "sqli_blind":"blind_sql_injection", "blind_sqli":"blind_sql_injection", "pathtraver":"path_traversal", "fi":"path_traversal", "lfi":"path_traversal", "xss_d":"xss", "xss_r":"xss", "xss_s":"xss", "securecookie":"insecure_cookie"}
    category = aliases.get(category, category)
    url = str(target.get("url") or "")
    # The manifest selects a probe profile; it is not evidence.  Unknown or
    # non-observable categories therefore produce no finding in local-probe
    # mode instead of falling back to a predeclared candidate.
    if not url or category not in OBSERVABLE:
        return []
    baseline_value = str(target.get("param_value") or target.get("cookie_value") or target.get("header_value") or _DEFAULT_VALUE.get(category, "test"))
    baseline = None
    try:
        baseline = _request(url, target, baseline_value, insecure)
    except Exception:
        return []
    findings = []
    for payload in _PAYLOADS.get(category, []):
        if baseline is None:
            break
        try:
            attack = _request(url, target, payload, insecure)
        except Exception:
            continue
        hit, marker, reason = _markers(category, attack, baseline)
        if hit:
            _, _, channel, parameter = _channel_value(target, payload)
            details = f"Local AWVS-compatible probe observed {reason}. baseline HTTP {baseline.status} ({len(baseline.body)} bytes); attack HTTP {attack.status} ({len(attack.body)} bytes); marker={marker!r}."
            finding = _finding(category, target, url, details=details, request=attack.raw_request,
                               channel=channel, parameter=parameter, payload=payload, evidence=marker)
            finding.baseline_request = baseline.raw_request
            findings.append(finding)
            break
    # Manifest metadata describes the probe channel and expected test family;
    # it must never fabricate a vulnerability when the live response provides
    # no supporting signal.  Static/source evidence belongs to ZIP analysis or
    # an explicitly imported external report.
    return findings

def scan_manifest(manifest_path: str | Path, *, target_url: str = "", insecure=True, timeout=15.0):
    path = Path(manifest_path)
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    targets = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(targets, list):
        return []
    wanted = target_url.rstrip("/") if target_url else ""
    selected = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").rstrip("/")
        if wanted and url != wanted and not wanted.endswith("/" + str(item.get("name") or "")):
            continue
        selected.append(dict(item))
    if not selected and wanted:
        selected = [{"name": wanted.rstrip("/").split("/")[-1], "category": "other", "url": wanted, "method": "GET", "channel": "query", "param_name": "probe", "param_value": "test"}]
    results = []
    for item in selected:
        item["url"] = wanted or str(item.get("url") or "")
        item.setdefault("timeout", timeout)
        results.extend(scan_target(item, insecure=insecure, timeout=timeout))
    return results
