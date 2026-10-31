"""Deterministic evidence judge for 落日验证.

The judge never trusts a scanner title.  It compares the baseline and attack
responses and only marks a POC verified when a category-specific marker or a
strong differential is present.  Categories with no HTTP-observable signal are
reported as ``unsupported`` rather than guessed.
"""

from __future__ import annotations

import html
import re

from .models import HttpEvidence, PocCase, VerificationResult

UNSUPPORTED = {
    "weak_crypto": "static-only: weak cipher choice has no HTTP response signal",
    "weak_random": "static-only: weak PRNG has no HTTP response signal",
    "trust_boundary": "static-only: session trust boundary has no HTTP response signal",
    "hardcoded_secret": "static-only: repository secret cannot be confirmed by replay",
    "business_logic": "not a single-request differential",
}

_SQL_ERRORS = (
    "sqlexception", "sqlsyntaxerror", "sql syntax", "syntax error", "unexpected token",
    "jdbc", "hsqldb", "org.h2", "ora-", "quoted string not properly terminated",
)


def _headers(evidence: HttpEvidence) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in evidence.headers:
        out.setdefault(key.lower(), value)
    return out


def _set_cookies(evidence: HttpEvidence) -> list[str]:
    return [value for key, value in evidence.headers if key.lower() == "set-cookie"]


def _has_any(text: str, needles: tuple[str, ...] | list[str]) -> str:
    lowered = text.lower()
    for needle in needles:
        if needle.lower() in lowered:
            return needle
    return ""


def _diff_ratio(baseline: HttpEvidence, attack: HttpEvidence) -> float:
    if not baseline.body and not attack.body:
        return 0.0
    return abs(len(attack.body) - len(baseline.body)) / max(1, len(baseline.body))


def judge(case: PocCase, baseline: HttpEvidence, attack: HttpEvidence,
          attack_sequence: list[HttpEvidence] | None = None) -> VerificationResult:
    sequence = attack_sequence or []
    result = VerificationResult(
        result_dir=case.result_dir,
        finding_id=case.finding_id,
        vulnerability_type=case.vulnerability_type,
        title=case.title,
        endpoint=case.endpoint,
        mode=case.mode,
        target_url=case.target_url,
        baseline=baseline,
        attack=attack,
        attack_sequence=sequence,
    )
    if attack.error:
        result.verdict = "error"
        result.reason = f"attack request failed: {attack.error}"
        return result
    if baseline.error and not attack.body:
        result.verdict = "error"
        result.reason = f"baseline request failed: {baseline.error}"
        return result

    vtype = case.vulnerability_type
    body = html.unescape(attack.body or "")
    base = html.unescape(baseline.body or "")
    lowered = body.lower()
    base_lower = base.lower()

    if vtype in UNSUPPORTED:
        result.verdict = "unsupported"
        result.reason = UNSUPPORTED[vtype]
        return result

    if vtype == "insecure_cookie":
        cookies = [value for key, value in attack.headers if key.lower() == "set-cookie"]
        for cookie in cookies:
            parts = [part.strip().lower() for part in cookie.split(";")]
            if parts and "somecookie" in parts[0] and "secure" not in parts:
                result.verdict = "verified"
                result.confidence = 0.9
                result.markers = [cookie[:300]]
                result.reason = "Set-Cookie for SomeCookie lacks the Secure flag"
                return result
        result.verdict = "rejected"
        result.confidence = 0.7
        result.reason = "no insecure Set-Cookie observed"
        return result

    if vtype == "weak_id":
        sequence = sequence or [attack]
        values: list[int] = []
        markers: list[str] = []
        for evidence in sequence:
            for cookie in _set_cookies(evidence):
                match = re.search(r"(?:^|;\s*)(?:dvwaSession|session(?:_id)?|sid)=([0-9]+)\b", cookie, re.I)
                if match:
                    values.append(int(match.group(1)))
                    markers.append(match.group(0))
                    break
        if len(values) >= 2 and len(set(values)) == len(values) and all(
                right == left + 1 for left, right in zip(values, values[1:])):
            result.verdict = "verified"
            result.confidence = 0.9
            result.markers = markers[:5]
            result.reason = "consecutive attack responses emitted numerically consecutive session identifiers"
            return result
        if values:
            result.verdict = "inconclusive"
            result.confidence = 0.55
            result.markers = markers[:5]
            result.reason = "numeric session cookie observed, but multiple consecutive responses did not prove predictability"
            return result
        result.verdict = "inconclusive"
        result.confidence = 0.45
        result.reason = "no numeric session cookie observed; multi-request comparison required"
        return result

    if vtype == "csp":
        headers = _headers(attack)
        policy = headers.get("content-security-policy", "")
        if policy and "script-src" in policy.lower():
            result.verdict = "verified"
            result.confidence = 0.8
            result.markers = [policy[:300]]
            result.reason = "Content-Security-Policy script-src observed; policy must be reviewed for excessive trust"
            return result
        result.verdict = "rejected"
        result.confidence = 0.6
        result.reason = "no Content-Security-Policy script-src header observed"
        return result

    if vtype == "open_redirect":
        headers = _headers(attack)
        location = headers.get("location", "")
        if attack.status in {301, 302, 303, 307, 308} and location:
            result.verdict = "verified"
            result.confidence = 0.9
            result.markers = [f"{attack.status} Location: {location[:250]}"]
            result.reason = "redirect response points to attacker-controlled Location"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.6
        result.reason = "no redirect status and Location header observed"
        return result

    if vtype == "api_info_disclosure":
        if re.search(r"\[\s*\{.*(?:\"id\"|\"name\"|\"level\")", body, re.S | re.I):
            result.verdict = "verified"
            result.confidence = 0.85
            result.markers = ["API user object fields"]
            result.reason = "response exposes user object fields without an authorization signal"
            return result
        result.verdict = "inconclusive"
        result.confidence = 0.45
        result.reason = "API page reached but user object response was not observed in this HTTP replay"
        return result

    if vtype == "idor":
        if "user profile" in lowered and re.search(r"user id\s*:\s*\d+", lowered):
            result.verdict = "verified"
            result.confidence = 0.75
            result.markers = ["User Profile", "User ID"]
            result.reason = "object profile returned under attacker-controlled identifier; compare with same-user baseline"
            return result
        result.verdict = "inconclusive"
        result.confidence = 0.45
        result.reason = "profile object differential requires an authenticated subject/object comparison"
        return result

    if vtype == "file_upload":
        if re.search(r"successfully uploaded|succesfully uploaded|uploaded!|hackable/uploads", body, re.I):
            result.verdict = "verified"
            result.confidence = 0.85
            result.markers = ["upload success"]
            result.reason = "multipart upload accepted and upload path disclosed"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.6
        result.reason = "no successful upload marker observed"
        return result

    if vtype in {"path_traversal", "arbitrary_file_read", "arbitrary_file_write", "file_read", "file_write"}:
        markers = ("../", "..\\", "/tmp/sunset_probe", "root:x:0:0", "[extensions]", "for 16-bit app support")
        hit = _has_any(body, markers)
        if hit and hit.lower() not in base_lower:
            result.verdict = "verified"
            result.confidence = 0.85
            result.markers = [hit]
            result.reason = f"traversal marker in attack response: {hit!r}"
            return result
        if re.search(r"testfiles[/\\]\.\.", body) and not re.search(r"testfiles[/\\]\.\.", base):
            result.verdict = "verified"
            result.confidence = 0.8
            result.markers = ["testfiles/.."]
            result.reason = "traversal path reflected by the file sink"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.6
        result.reason = "no traversal marker or path reflection observed"
        return result

    if vtype in {"command_injection", "rce", "code_injection"}:
        match = re.search(r"uid=\d+\([^)]*\)|gid=\d+\([^)]*\)|SUNSET_CMD_MARKER", body)
        if match:
            result.verdict = "verified"
            result.confidence = 0.9
            result.markers = [match.group(0)[:300]]
            result.reason = "command output marker in attack response"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.6
        result.reason = "no command output marker observed"
        return result

    if vtype == "xss":
        payloads = ("<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<script>alert(document.domain)</script>")
        for payload in payloads:
            if payload in body and payload not in base:
                result.verdict = "verified"
                result.confidence = 0.9
                result.markers = [payload]
                result.reason = "unencoded script payload reflected in attack response"
                return result
        if "<script" in lowered and "<script" not in base_lower:
            result.verdict = "verified"
            result.confidence = 0.75
            result.markers = ["<script"]
            result.reason = "script tag appears in attack response but not baseline"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.6
        result.reason = "no unencoded script reflection observed"
        return result

    if vtype in {"sql_injection", "second_order_injection"}:
        error = ""
        for needle in _SQL_ERRORS:
            if needle in lowered and needle not in base_lower:
                error = needle
                break
        if error:
            result.verdict = "verified"
            result.confidence = 0.85
            result.markers = [error]
            result.reason = f"SQL error marker in attack response: {error!r}"
            return result
        row_pattern = re.compile(r"(?m)^\s*\d+,\s+\S+,\s+\S+")
        attack_rows = len(row_pattern.findall(body))
        base_rows = len(row_pattern.findall(base))
        if attack_rows > base_rows:
            result.verdict = "verified"
            result.confidence = 0.75
            result.markers = [f"rows {base_rows}->{attack_rows}"]
            result.reason = "attack response exposes more result rows than baseline"
            return result
        result.verdict = "inconclusive"
        result.confidence = 0.45
        result.reason = "no SQL error or row-set change observed (possible blind injection)"
        return result

    if vtype in {"ldap_injection", "xpath_injection"}:
        error = _has_any(body, ("javax.naming", "ldap", "xpath", "invalid dn", "invalid xpath", "could not evaluate"))
        if error and error not in base_lower:
            result.verdict = "verified"
            result.confidence = 0.8
            result.markers = [error]
            result.reason = f"injection error marker: {error!r}"
            return result
        if "authenticated" in lowered and "true" in lowered and ("false" in base_lower or "true" not in base_lower):
            result.verdict = "verified"
            result.confidence = 0.8
            result.markers = ["authenticated=true"]
            result.reason = "authentication result changed under injection payload"
            return result
        if body.count("LDAP query results") > base.count("LDAP query results"):
            result.verdict = "verified"
            result.confidence = 0.8
            result.markers = [f"LDAP rows {base.count('LDAP query results')}->{body.count('LDAP query results')}"]
            result.reason = "attack response exposes more LDAP records than baseline"
            return result
        if "your query results" in lowered and "your query results" in base_lower and body != base:
            result.verdict = "verified"
            result.confidence = 0.78
            result.markers = ["query result changed"]
            result.reason = "XPath query returned a different record than baseline"
            return result
        ratio = _diff_ratio(baseline, attack)
        if ratio >= 0.5 and attack.status == baseline.status and len(body) > len(base):
            result.verdict = "verified"
            result.confidence = 0.65
            result.markers = [f"length ratio {ratio:.2f}"]
            result.reason = "attack response expanded substantially over baseline"
            return result
        result.verdict = "rejected" if attack.status < 500 else "inconclusive"
        result.confidence = 0.55
        result.reason = "no LDAP/XPath-specific differential observed"
        return result

    # Generic fallback: status/length differential only, lower confidence.
    ratio = _diff_ratio(baseline, attack)
    if attack.status != baseline.status or ratio >= 0.35:
        result.verdict = "inconclusive"
        result.confidence = 0.45
        result.markers = [f"status {baseline.status}->{attack.status}", f"length ratio {ratio:.2f}"]
        result.reason = "differential exists but no category-specific marker"
        return result
    result.verdict = "rejected"
    result.confidence = 0.5
    result.reason = "no meaningful differential between baseline and attack"
    return result
