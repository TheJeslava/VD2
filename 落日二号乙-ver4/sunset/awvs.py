"""AWVS（Acunetix）联动。

双向：
1. source → AWVS：把 SurfaceMapper 识别出的端点导出成 AWVS 可导入的目标种子；
2. AWVS → source：导入 AWVS JSON/XML 报告，与静态 finding 按「同类型 + 同端点」
   关联，作为外部佐证；AWVS 独有的问题作为 external finding 保留。
3. 可选：通过 AWVS REST API 创建 target、启动 scan、轮询、拉取漏洞。

注意：本管线不内嵌 AWVS，也不在测试中自动发起扫描；只有显式提供 URL/KEY/TARGET
时才会联网。所有扫描动作都发生在外部 AWVS，管线只消费结果。
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ChainStep, Finding, PocPlan, Project
from .security.guard import inspect_poc_safety
from .taxonomy import canonical, meta


@dataclass
class AwvsVulnerability:
    vt_name: str
    url: str
    severity: str = "high"
    details: str = ""
    request: str = ""
    cwe: str = ""
    confidence: str = ""
    source: str = "awvs"
    raw: dict[str, Any] = field(default_factory=dict)
    channel: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    method: str = ""


_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "informational": "low", "info": "low",
}


def _map_type(name: str, cwe: str = "") -> str:
    text = f"{name} {cwe}".lower()
    cwe_map = {
        "cwe-78": "command_injection", "cwe-89": "sql_injection", "cwe-918": "ssrf",
        "cwe-22": "path_traversal", "cwe-502": "deserialization", "cwe-1336": "ssti",
        "cwe-287": "auth_bypass", "cwe-639": "idor", "cwe-611": "xxe", "cwe-79": "xss",
        "cwe-601": "open_redirect", "cwe-352": "csrf", "cwe-434": "file_upload",
        "cwe-90": "ldap_injection", "cwe-643": "xpath_injection", "cwe-798": "hardcoded_secret",
    }
    for key, value in cwe_map.items():
        if key in text:
            return value
    patterns = [
        (r"sql injection|sqli", "sql_injection"),
        (r"command injection|os command|shell injection|rce", "command_injection"),
        (r"path traversal|directory traversal|arbitrary file|file path", "path_traversal"),
        (r"ssrf|server.side request", "ssrf"),
        (r"xxe|xml external", "xxe"),
        (r"deserial", "deserialization"),
        (r"template injection|ssti", "ssti"),
        (r"ldap", "ldap_injection"),
        (r"xpath", "xpath_injection"),
        (r"open redirect", "open_redirect"),
        (r"csrf|cross.site request", "csrf"),
        (r"file upload|unrestricted upload", "file_upload"),
        (r"cross.site scripting|xss", "xss"),
        (r"cookie", "insecure_cookie"),
        (r"idor|insecure direct object|access control", "idor"),
        (r"authentication|auth bypass|weak password", "auth_bypass"),
    ]
    for pattern, value in patterns:
        if re.search(pattern, text):
            return value
    return "other"


def _normalize_severity(value: str) -> str:
    return _SEVERITY.get((value or "").strip().lower(), "high")


def _as_dict_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "vulns", "issues", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []


def parse_report(path: Path) -> list[AwvsVulnerability]:
    """支持 AWVS JSON 导出与 XML 报告。"""
    if not path.is_file():
        raise FileNotFoundError(f"AWVS 报告不存在: {path}")
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return _parse_xml(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        # 有些导出是 JSONL
        items = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        payload = items
    results: list[AwvsVulnerability] = []
    for item in _as_dict_list(payload):
        name = str(item.get("vt_name") or item.get("name") or item.get("title") or item.get("type") or "AWVS Finding")
        url = str(item.get("affects_url") or item.get("url") or item.get("target") or item.get("location") or "")
        severity = str(item.get("severity") or item.get("risk") or "high")
        details = str(item.get("details") or item.get("description") or item.get("detail") or item.get("info") or "")
        request = str(item.get("request") or item.get("http_request") or item.get("raw_request") or "")
        cwe = str(item.get("cwe") or item.get("cwe_id") or "")
        results.append(AwvsVulnerability(name, url, severity, details, request, cwe, raw=item))
    return results


def _parse_xml(path: Path) -> list[AwvsVulnerability]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"AWVS XML 解析失败: {exc}") from exc
    results: list[AwvsVulnerability] = []
    for node in root.iter():
        tag = node.tag.lower()
        if "vulnerability" not in tag and "issue" not in tag:
            continue
        values: dict[str, str] = {}
        for child in node:
            key = child.tag.lower()
            values[key] = (child.text or "").strip()
        name = values.get("name") or values.get("vt_name") or values.get("title") or "AWVS Finding"
        url = values.get("url") or values.get("affects_url") or values.get("target") or ""
        severity = values.get("severity") or values.get("risk") or "high"
        details = values.get("details") or values.get("description") or values.get("detail") or ""
        request = values.get("request") or values.get("http_request") or ""
        cwe = values.get("cwe") or ""
        results.append(AwvsVulnerability(name, url, severity, details, request, cwe))
    return results


def _path_of(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or url
    except ValueError:
        path = url
    return path.rstrip("/") or "/"


def _endpoint_of_finding(finding: Finding) -> str:
    match = re.search(
        r"(?:GET|POST|PUT|DELETE|PATCH|ANY)\b[^\n]{0,40}?(/[A-Za-z0-9_./{}:+-]+)",
        finding.cve_justification or "",
    )
    if match:
        return match.group(1).rstrip("，,。.")
    for step in finding.exploit_chain:
        if step.location and ":" in step.location:
            continue
    return ""


def _same_endpoint(left: str, right: str) -> bool:
    left_path = _path_of(left)
    right_path = _path_of(right)
    if left_path == right_path:
        return True
    left_tail = left_path.split("/")[-1].lower()
    right_tail = right_path.split("/")[-1].lower()
    return bool(left_tail) and left_tail == right_tail


def _poc_from_awvs(vuln: AwvsVulnerability) -> PocPlan:
    request = vuln.request.strip() or (
        f"GET {_path_of(vuln.url)} HTTP/1.1\r\nHost: TARGET\r\n\r\n"
    )
    scripts = {
        "awvs_request.http": request + ("\n" if not request.endswith("\n") else ""),
        "poc_readme.md": (
            f"# AWVS 外部发现\n\n- 名称: {vuln.vt_name}\n- URL: {vuln.url}\n"
            f"- 严重度: {vuln.severity}\n- CWE: {vuln.cwe}\n\n"
            "该 POC 来自 AWVS 报告回灌，本管线未执行。\n"
        ),
    }
    plan = PocPlan(
        description=f"AWVS 外部扫描发现：{vuln.vt_name} @ {vuln.url}",
        preconditions=["AWVS 扫描已完成", "目标可达", "已获得授权"],
        steps=[
            {"step": 1, "action": "重放 AWVS 记录的请求", "request": request,
             "expected_response": "复现 AWVS 报告中的问题"},
        ],
        payload="",
        impact=vuln.details[:1000] or "外部扫描器报告的安全问题，需人工复核。",
        cve_justification=f"AWVS 报告：{vuln.vt_name}；CWE={vuln.cwe or 'unknown'}。外部扫描结果仅作为佐证。",
        scripts=scripts,
    )
    plan.safety = inspect_poc_safety(scripts, plan.payload)
    return plan


def correlate(findings: list[Finding], vulns: list[AwvsVulnerability],
              project: Project) -> tuple[list[Finding], list[dict[str, Any]]]:
    """把 AWVS 结果与静态 finding 关联；返回 (更新后的 findings, 关联明细)。"""
    used: set[int] = set()
    correlations: list[dict[str, Any]] = []
    for finding in findings:
        endpoint = _endpoint_of_finding(finding)
        for index, vuln in enumerate(vulns):
            if index in used:
                continue
            if _map_type(vuln.vt_name, vuln.cwe) != finding.vulnerability_type:
                continue
            if endpoint and not _same_endpoint(endpoint, vuln.url):
                continue
            used.add(index)
            finding.external_evidence.append({
                "source": "awvs",
                "vt_name": vuln.vt_name,
                "url": vuln.url,
                "severity": vuln.severity,
                "cwe": vuln.cwe,
                "details": vuln.details[:1200],
            })
            finding.confidence = round(min(0.98, finding.confidence + 0.03), 2)
            finding.evidence_level = "externally_corroborated"
            finding.verification_notes = (
                finding.verification_notes
                + f"\nAWVS 外部佐证：{vuln.vt_name} @ {vuln.url}（未在本管线执行扫描）。"
            )[:6000]
            correlations.append({
                "finding_id": finding.finding_id,
                "awvs": vuln.vt_name,
                "url": vuln.url,
                "verdict": "corroborated",
            })
            break

    for index, vuln in enumerate(vulns):
        if index in used:
            continue
        vuln_type = _map_type(vuln.vt_name, vuln.cwe)
        severity = _normalize_severity(vuln.severity)
        item = meta(vuln_type)
        poc = _poc_from_awvs(vuln)
        finding = Finding(
            finding_id="AWVS-" + hashlib.sha1(f"{vuln.vt_name}:{vuln.url}:{index}".encode()).hexdigest()[:12],
            vulnerability_type=vuln_type,
            severity=severity,
            title=f"AWVS: {vuln.vt_name}",
            description=vuln.details[:3000] or f"AWVS 在 {vuln.url} 报告 {vuln.vt_name}。",
            file_path="",
            line_start=0,
            line_end=0,
            code_snippet="",
            source=f"外部扫描目标 {vuln.url}",
            sink="AWVS 报告端点",
            suggestion="按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。",
            confidence=0.75,
            needs_verification=True,
            verdict="external",
            exploit_chain=[ChainStep(step=1, location=vuln.url, description=f"AWVS 报告 {vuln.vt_name}")],
            poc=poc,
            impact=vuln.details[:1000] or "外部扫描器报告的问题。",
            cve_justification=f"AWVS 外部报告；{item.cwe}；未在本管线内动态验证。",
            verification_notes="来源：AWVS 报告回灌。无源码证据，需人工定位。",
            endpoint=_path_of(vuln.url),
            http_method=(vuln.request.split(" ", 1)[0] if vuln.request else "GET").upper(),
            origin="awvs",
            evidence_level="external_only",
            safety={"executed": False, "requires_authorization": True, "external_scanner": "awvs"},
            score=round({"critical": 40, "high": 30, "medium": 20, "low": 10}.get(severity, 20) + 7.5, 2),
        )
        findings.append(finding)
        correlations.append({
            "finding_id": finding.finding_id,
            "awvs": vuln.vt_name,
            "url": vuln.url,
            "verdict": "external_only",
        })
    return findings, correlations


def export_targets(project: Project, path: Path) -> dict[str, Any]:
    """把源码识别的端点导出为 AWVS 目标种子。"""
    targets = []
    for endpoint in project.endpoints:
        targets.append({
            "url": f"http://TARGET:8080{endpoint.path}",
            "method": endpoint.method,
            "source_file": endpoint.file,
            "source_line": endpoint.line,
            "params": endpoint.params,
            "framework": endpoint.framework,
        })
    payload = {
        "generated_by": "落日二号乙 / SurfaceMapper",
        "note": "将 TARGET 替换为实际授权目标后导入 AWVS；结果可用 --awvs-report 回灌。",
        "targets": targets,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


# ---------------------------------------------------------------------------
# AWVS REST API 客户端（可选；只有显式配置才联网）
# ---------------------------------------------------------------------------

class AwvsClient:
    def __init__(self, base_url: str, api_key: str, *, verify_tls: bool = True, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.context = None if verify_tls else ssl._create_unverified_context()

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        url = self.base_url + path
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "X-Auth": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"AWVS {method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AWVS {method} {path} -> 网络错误: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"raw": raw.decode("utf-8", errors="replace")[:2000]}

    def test_connection(self) -> Any:
        return self._request("GET", "/api/v1/me")

    def create_target(self, address: str, description: str = "sunset-one") -> dict:
        return self._request("POST", "/api/v1/targets", {"address": address, "description": description})

    def start_scan(self, target_id: str, profile_id: str) -> dict:
        return self._request("POST", "/api/v1/scans", {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        })

    def scan_status(self, scan_id: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def list_vulnerabilities(self, scan_id: str) -> list[dict]:
        payload = self._request("GET", f"/api/v1/vulnerabilities?q={urllib.parse.quote('scan_id:' + scan_id)}")
        return _as_dict_list(payload)

    def wait_scan(self, scan_id: str, timeout_sec: int = 1800, interval: int = 15) -> dict:
        deadline = time.time() + timeout_sec
        last: dict = {}
        while time.time() < deadline:
            last = self.scan_status(scan_id)
            status = str(last.get("status") or last.get("current_session") or "").lower()
            if status in {"completed", "failed", "aborted"}:
                return last
            time.sleep(interval)
        return last

    def trigger_and_fetch(self, target_url: str, profile_id: str,
                          wait_sec: int = 1800) -> list[AwvsVulnerability]:
        target = self.create_target(target_url)
        target_id = str(target.get("target_id") or target.get("id") or "")
        if not target_id:
            raise RuntimeError(f"AWVS 创建 target 失败: {target}")
        scan = self.start_scan(target_id, profile_id)
        scan_id = str(scan.get("scan_id") or scan.get("id") or "")
        if not scan_id:
            raise RuntimeError(f"AWVS 启动扫描失败: {scan}")
        self.wait_scan(scan_id, timeout_sec=wait_sec)
        raw = self.list_vulnerabilities(scan_id)
        results = []
        for item in raw:
            name = str(item.get("vt_name") or item.get("name") or "AWVS Finding")
            url = str(item.get("affects_url") or item.get("url") or target_url)
            results.append(AwvsVulnerability(
                name, url, str(item.get("severity") or "high"),
                str(item.get("details") or ""), str(item.get("request") or ""), str(item.get("cwe") or ""),
                raw=item,
            ))
        return results
