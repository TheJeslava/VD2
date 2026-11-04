"""POC collection and request parsing for VulnCatcher-Verify."""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from pathlib import Path
from typing import Any

from .models import HttpRequest, PocCase


def parse_raw_request(raw: str) -> HttpRequest | None:
    text = (raw or "").replace("\r\n", "\n").strip("\n")
    if not text:
        return None
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    first = lines[0].split()
    if len(first) < 2:
        return None
    method = first[0].upper()
    path = first[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return HttpRequest(method=method, url=path, headers=headers, body=body.encode("utf-8"), raw=text)


def parse_curl(text: str) -> HttpRequest | None:
    text = (text or "").replace("\\\r\n", " ").replace("\\\n", " ").strip()
    if not text:
        return None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0].lower() not in {"curl", "curl.exe"}:
        return None
    method = ""
    url = ""
    headers: dict[str, str] = {}
    body = ""
    forms: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-X", "--request"} and index + 1 < len(tokens):
            method = tokens[index + 1].upper()
            index += 2
        elif token in {"-H", "--header"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            if ":" in value:
                key, header_value = value.split(":", 1)
                headers[key.strip()] = header_value.strip()
            index += 2
        elif token in {"--data", "--data-binary", "--data-raw", "-d"} and index + 1 < len(tokens):
            body = tokens[index + 1]
            index += 2
        elif token in {"-F", "--form"} and index + 1 < len(tokens):
            forms.append(tokens[index + 1])
            index += 2
        elif token in {"--url"} and index + 1 < len(tokens):
            url = tokens[index + 1]
            index += 2
        elif token in {"-i", "-s", "-S", "-sS", "--insecure", "-k", "-L", "--location"}:
            index += 1
        elif token.startswith("-"):
            index += 1
        else:
            if not url:
                url = token
            index += 1
    if not url:
        return None
    if forms:
        boundary = "SUNSET-VERIFY-BOUNDARY"
        parts: list[str] = []
        for form in forms:
            name, sep, value = form.partition("=")
            if not sep:
                continue
            file_match = re.fullmatch(r"@([^;]+)(?:;filename=(.*))?", value)
            if file_match:
                filename = file_match.group(2) or Path(file_match.group(1)).name
                parts.extend([
                    f"--{boundary}",
                    f'Content-Disposition: form-data; name="{name}"; filename="{filename}"',
                    "Content-Type: application/octet-stream",
                    "",
                    "SUNSET_POC_TEST_FILE",
                ])
            else:
                parts.extend([f"--{boundary}", f'Content-Disposition: form-data; name="{name}"', "", value])
        parts.append(f"--{boundary}--")
        body = "\r\n".join(parts)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    # Some generated POCs use human-readable query keys such as
    # ``session cookie``.  Normalize only URL syntax so the request can be
    # replayed; the adapter/judge still decides whether the payload works.
    url = urllib.parse.quote(url, safe=":/?&=%'@+,-._~[]")
    if not method:
        method = "POST" if body or forms else "GET"
    return HttpRequest(method=method, url=url, headers=headers, body=body.encode("utf-8"), raw=text)


def _step_request(step: dict[str, Any]) -> HttpRequest | None:
    value = str(step.get("request") or "").strip()
    if not value:
        return None
    if value.lower().startswith("curl"):
        return parse_curl(value)
    if re.match(r"^[A-Z]+\s+\S+\s+HTTP/", value):
        return parse_raw_request(value)
    return None


def _resolve_url(value: str, base: str, endpoint: str) -> str:
    value = (value or "").strip()
    if value.startswith(("http://", "https://")):
        if urllib.parse.urlsplit(value).hostname != "target":
            return value
    if not base:
        return value
    parsed_base = urllib.parse.urlsplit(base)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    path = value
    if not path.startswith("/"):
        if "://" in path:
            split = urllib.parse.urlsplit(path)
            path = split.path or "/"
            if split.query:
                path += "?" + split.query
        else:
            path = endpoint or "/" + path
    prefix = parsed_base.path.rstrip("/")
    request_path = path.partition("?")[0]
    if prefix and (request_path == prefix or request_path.startswith(prefix + "/")):
        return origin + path
    segments = [part for part in prefix.split("/") if part]
    if path.startswith("/") and len(segments) >= 2 and path.startswith("/" + segments[0] + "/"):
        # The base is already a full endpoint (URL mode); the request path
        # includes the same context prefix, so do not prepend it again.
        return origin + path
    if prefix:
        path = prefix + "/" + path.lstrip("/")
    return origin + (path if path.startswith("/") else "/" + path)


def _finding_target(finding: dict[str, Any], run: dict[str, Any], mode: str, base: str) -> str:
    endpoint = str((finding.get("location", {}) or {}).get("endpoint", "") or "")
    if mode == "zip" and base:
        return base
    safety = finding.get("poc", {}).get("safety", {}) or {}
    candidates = [
        safety.get("target_url"),
        run.get("target_url"),
        finding.get("target_url"),
    ]
    for value in candidates:
        if value:
            return str(value)
    if base and endpoint:
        return base.rstrip("/") + "/" + endpoint.lstrip("/")
    return ""


def collect_from_result(result_dir: Path, *, mode: str, base: str) -> list[PocCase]:
    report_path = result_dir / "report.json"
    if not report_path.is_file():
        raise FileNotFoundError(f"result report not found: {report_path}")
    report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    run = report.get("run", {}) or {}
    cases: list[PocCase] = []
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        poc = finding.get("poc", {}) or {}
        if not poc:
            continue
        steps = poc.get("steps", []) or []
        attack = None
        baseline = None
        attack_sequence: list[HttpRequest] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            parsed = _step_request(step)
            if parsed is None:
                continue
            if step.get("step") == 1 and baseline is None:
                baseline = parsed
            elif step.get("step") != 1:
                attack_sequence.append(parsed)
        attack = attack_sequence[0] if attack_sequence else None
        scripts = poc.get("scripts", {}) or {}
        if attack is None and scripts.get("request.http"):
            attack = parse_raw_request(str(scripts["request.http"]))
        # AWVS report reimports use a distinct artifact name so that the
        # preserved scanner request is not confused with a generated POC.
        legacy_awvs = attack is None and bool(scripts.get("awvs_request.http"))
        if legacy_awvs:
            attack = parse_raw_request(str(scripts["awvs_request.http"]))
        if attack is None and scripts.get("poc.sh"):
            attack = parse_curl(str(scripts["poc.sh"]))
        if attack is None:
            continue
        endpoint = str((finding.get("location", {}) or {}).get("endpoint") or finding.get("endpoint") or "")
        target_url = _finding_target(finding, run, mode, base)
        missing_control = legacy_awvs and (baseline is None or baseline == attack)
        for request in attack_sequence or [attack]:
            request.url = _resolve_url(request.url, target_url or base, endpoint)
        if missing_control:
            # Older imports have only an attack step. Never use its payload as a control.
            parsed = urllib.parse.urlsplit(attack.url)
            baseline = HttpRequest(method="GET", url=parsed._replace(query="", fragment="").geturl())
        elif baseline is not None:
            baseline.url = _resolve_url(baseline.url, target_url or base, endpoint)
        cases.append(PocCase(
            result_dir=str(result_dir),
            finding_id=str(finding.get("id") or ""),
            vulnerability_type=str(finding.get("vulnerability_type") or "other"),
            title=str(finding.get("title") or ""),
            endpoint=endpoint,
            mode=mode,
            target_url=attack.url,
            baseline=baseline,
            attack=attack,
            attack_sequence=attack_sequence or [attack],
            source=str(finding.get("origin") or ""),
            notes=str(finding.get("verification_notes") or "")[:1500],
        ))
    return cases


def discover_results(root: Path) -> list[Path]:
    found: list[Path] = []
    for report in sorted(root.rglob("report.json")):
        parent = report.parent
        if any(part in {"verification", ".work"} for part in parent.parts):
            continue
        found.append(parent)
    # Keep only leaf result dirs, not aggregate roots that happen to contain a report.
    unique: list[Path] = []
    for path in found:
        if path not in unique:
            unique.append(path)
    return unique
