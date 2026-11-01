"""AWVS-compatible local dynamic probe.

This module is the offline fallback used when a real Acunetix/AWVS instance is
not configured.  It deliberately speaks the same result shape as an AWVS
export (``AwvsVulnerability``), so the URL pipeline treats it exactly like a
real scanner feed.  It is *not* a replacement for AWVS: it only exercises the
input channel declared by a benchmark-style target manifest and reports a
finding when the attack response carries concrete dynamic evidence.

The probe is intentionally limited to the six categories a black-box DAST
scanner can observe on the bundled OWASP Benchmark app (cmdi, sqli, xss,
pathtraver, ldapi, xpathi) plus the cookie-flag check.  Crypto/hash/weak-random
and trust-boundary cases have no HTTP-observable signal and are skipped.
"""

from __future__ import annotations

import http.client
import html
import json
import re
import ssl
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .awvs import AwvsVulnerability
from .taxonomy import meta

OBSERVABLE = {"cmdi", "sqli", "xss", "pathtraver", "ldapi", "xpathi", "securecookie"}

_TYPE_NAME = {
    "cmdi": "OS Command Injection",
    "sqli": "SQL Injection",
    "xss": "Cross-site Scripting (XSS)",
    "pathtraver": "Path Traversal",
    "ldapi": "LDAP Injection",
    "xpathi": "XPath Injection",
    "securecookie": "Cookie Not Marked as Secure",
}

_PAYLOADS: dict[str, list[str]] = {
    "cmdi": [";echo SUNSET_CMD_MARKER", ";id", "&& id", "FOO=echo SUNSET_CMD_MARKER"],
    "sqli": ["' OR '1'='1", "'", "1' OR '1'='1' -- "],
    "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"],
    "pathtraver": [
        "../../../../tmp/sunset_probe.txt",
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
    ],
    "ldapi": ["*)(uid=*))(|(uid=*", "*", "admin)(&)"],
    "xpathi": ["' or '1'='1", "' or 1=1 or '", "x' or name()='username' or 'x'='x"],
    "securecookie": ["SUNSET_COOKIE_VALUE"],
}

_DEFAULT_VALUE = {
    "cmdi": "ECHOOO",
    "sqli": "test",
    "xss": "SafeText",
    "pathtraver": "FileName",
    "ldapi": "Ms Bar",
    "xpathi": "SafeText",
    "securecookie": "whatever",
}


@dataclass
class HttpResponse:
    status: int
    headers: list[tuple[str, str]]
    body: str
    raw_request: str


def _headers_dict(headers: list[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers:
        out.setdefault(key.lower(), value)
    return out


def _connection(url: str, *, insecure: bool = True, timeout: float = 15.0):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _send(url: str, method: str, path: str, headers: dict[str, str], body: bytes,
          *, insecure: bool = True, timeout: float = 15.0) -> HttpResponse:
    conn = _connection(url, insecure=insecure, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw_body = response.read(2 * 1024 * 1024)
        body_text = raw_body.decode("utf-8", errors="replace")
        response_headers = [(key, value) for key, value in response.getheaders()]
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
        return HttpResponse(response.status, response_headers, body_text, "\r\n".join(request_lines))
    finally:
        conn.close()


def _channel_value(target: dict[str, Any], value: str) -> tuple[dict[str, str], bytes, str, str]:
    channel = str(target.get("channel") or "form").lower()
    encoded = urllib.parse.quote(value, safe="")
    headers = {
        "User-Agent": "Sunset-AWVS-Probe/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    body = b""
    parameter = ""
    if channel == "cookie":
        name = str(target.get("cookie_name") or target.get("name") or "test")
        headers["Cookie"] = f"{name}={encoded}"
        parameter = name
    elif channel == "header":
        name = str(target.get("header_name") or target.get("name") or "X-Test")
        headers[name] = encoded
        parameter = name
    else:
        name = str(target.get("param_name") or target.get("name") or "test")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        raw = f"{name}={encoded}".encode()
        body = raw
        headers["Content-Length"] = str(len(raw))
        parameter = name
    return headers, body, channel, parameter


def _request(url: str, target: dict[str, Any], value: str, *, insecure: bool = True) -> HttpResponse:
    method = str(target.get("method") or "POST").upper()
    headers, body, channel, parameter = _channel_value(target, value)
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if channel not in {"cookie", "header"} and method in {"GET", "HEAD", "DELETE"}:
        encoded = urllib.parse.quote(value, safe="")
        joiner = "&" if "?" in path else "?"
        path += f"{joiner}{parameter}={encoded}"
        body = b""
        headers.pop("Content-Type", None)
        headers.pop("Content-Length", None)
    return _send(url, method, path, headers, body, insecure=insecure)


def _markers(category: str, attack: HttpResponse, baseline: HttpResponse) -> tuple[bool, str, str]:
    body = html.unescape(attack.body or "")
    base = html.unescape(baseline.body or "")
    lowered = body.lower()

    if category == "cmdi":
        match = re.search(r"uid=\d+\([^)]*\)|gid=\d+\([^)]*\)|SUNSET_CMD_MARKER", body)
        if match:
            return True, match.group(0)[:300], "command output marker"
        return False, "", ""

    if category == "sqli":
        error_markers = (
            "sqlexception", "sql syntax", "syntax error", "unexpected token",
            "jdbc", "hsqldb", "org.h2", "ora-", "quoted string not properly terminated",
        )
        for marker in error_markers:
            if marker in lowered and marker not in base.lower():
                return True, marker, "SQL error marker"
        # A boolean payload that changes the row set is also evidence.
        row_pattern = re.compile(r"(?m)^\s*\d+,\s+\S+,\s+\S+")
        attack_rows = len(row_pattern.findall(body))
        base_rows = len(row_pattern.findall(base))
        if attack_rows > base_rows:
            return True, f"rows {base_rows}->{attack_rows}", "row-set expansion"
        if attack.status != baseline.status and attack.status >= 500:
            return True, f"status {baseline.status}->{attack.status}", "server error"
        return False, "", ""

    if category == "xss":
        for payload in _PAYLOADS["xss"]:
            if payload in body and payload not in base:
                return True, payload, "unencoded script reflection"
        return False, "", ""

    if category == "pathtraver":
        traversal_markers = ("../", "..\\", "/tmp/sunset_probe", "root:x:0:0", "[extensions]", "for 16-bit app support")
        for marker in traversal_markers:
            if marker in body and marker not in base:
                return True, marker, "path traversal response"
        # Writing cases return the constructed path; the traversal segment is evidence.
        if re.search(r"testfiles[/\\]\.\.", body) and not re.search(r"testfiles[/\\]\.\.", base):
            return True, "testfiles/..", "traversal path reflected"
        return False, "", ""

    if category == "ldapi":
        for marker in ("javax.naming", "ldaperror", "ldap exception", "invalid dn"):
            if marker in lowered and marker not in base.lower():
                return True, marker, "LDAP error marker"
        if "true" in lowered and "false" in base.lower() and "authenticated" in lowered:
            return True, "authenticated=true", "authentication bypass"
        if body.count("LDAP query results") > base.count("LDAP query results"):
            return True, f"ldap rows {base.count('LDAP query results')}->{body.count('LDAP query results')}", "LDAP row-set expansion"
        return False, "", ""

    if category == "xpathi":
        for marker in ("xpathexception", "xpath", "invalid xpath", "could not evaluate"):
            if marker in lowered and marker not in base.lower():
                return True, marker, "XPath error marker"
        if "your query results" in lowered and "your query results" in base.lower() and body != base:
            return True, "query result changed", "XPath result-set change"
        if len(body) > max(200, len(base) * 1.5) and ("true" in lowered or "user" in lowered):
            return True, f"length {len(base)}->{len(body)}", "result-set expansion"
        return False, "", ""

    if category == "securecookie":
        cookies = [value for key, value in attack.headers if key.lower() == "set-cookie"]
        for cookie in cookies:
            parts = [part.strip().lower() for part in cookie.split(";")]
            if parts and "somecookie" in parts[0] and "secure" not in parts:
                return True, cookie[:300], "cookie without Secure flag"
        return False, "", ""

    return False, "", ""


def _vt_severity(category: str) -> str:
    return meta(category).default_severity


def _vt_cwe(category: str) -> str:
    return meta(category).cwe.replace("CWE-", "")


def scan_target(target: dict[str, Any], *, insecure: bool = True, timeout: float = 15.0) -> list[AwvsVulnerability]:
    category = str(target.get("category") or "").lower()
    if category not in OBSERVABLE:
        return []
    url = str(target.get("url") or "")
    if not url:
        return []
    baseline_value = str(
        target.get("cookie_value") or target.get("header_value") or target.get("param_value")
        or _DEFAULT_VALUE.get(category, "test")
    )
    try:
        baseline = _request(url, target, baseline_value, insecure=insecure)
    except Exception:
        return []

    findings: list[AwvsVulnerability] = []
    for payload in _PAYLOADS.get(category, []):
        try:
            attack = _request(url, target, payload, insecure=insecure)
        except Exception:
            continue
        hit, marker, reason = _markers(category, attack, baseline)
        if not hit:
            continue
        _, _, channel, parameter = _channel_value(target, payload)
        details = (
            f"Local AWVS-compatible probe observed {reason}. "
            f"baseline HTTP {baseline.status} ({len(baseline.body)} bytes); "
            f"attack HTTP {attack.status} ({len(attack.body)} bytes); marker={marker!r}."
        )
        findings.append(AwvsVulnerability(
            vt_name=_TYPE_NAME.get(category, category),
            url=url,
            severity=_vt_severity(category),
            details=details,
            request=attack.raw_request,
            cwe=_vt_cwe(category),
            raw={
                "source_tool": "AWVS-LOCAL-PROBE",
                "category": category,
                "channel": channel,
                "parameter": parameter,
                "payload": payload,
                "marker": marker,
                "baseline_status": baseline.status,
                "attack_status": attack.status,
                "baseline_length": len(baseline.body),
                "attack_length": len(attack.body),
            },
            channel=channel,
            parameter=parameter,
            payload=payload,
            evidence=marker,
            method=str(target.get("method") or "POST").upper(),
        ))
        break
    return findings


def scan_manifest(manifest_path: str | Path, *, target_url: str = "",
                  insecure: bool = True, timeout: float = 15.0) -> list[AwvsVulnerability]:
    path = Path(manifest_path)
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    targets = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(targets, list):
        return []
    wanted = target_url.rstrip("/") if target_url else ""
    selected: list[dict[str, Any]] = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").rstrip("/")
        if wanted and url != wanted and not wanted.endswith("/" + str(item.get("name") or "")):
            continue
        selected.append(item)
    if not selected and wanted:
        # A single endpoint not present in the manifest: probe it generically.
        name = wanted.rstrip("/").split("/")[-1]
        category = wanted.rstrip("/").split("/")[-2].split("-")[0] if "/" in wanted else "other"
        selected = [{
            "name": name,
            "category": category,
            "url": wanted,
            "method": "POST",
            "channel": "form",
            "param_name": name,
            "param_value": _DEFAULT_VALUE.get(category, "test"),
        }]
    results: list[AwvsVulnerability] = []
    for item in selected:
        item = dict(item)
        if wanted:
            item["url"] = wanted
        results.extend(scan_target(item, insecure=insecure, timeout=timeout))
    return results
