"""SandboxExecutorAgent: execute baseline and attack HTTP requests."""

from __future__ import annotations

import re
import time

from ..executor import execute
from ..models import HttpEvidence, HttpRequest, PocCase


class SandboxExecutorAgent:
    name = "sandbox_executor"
    codename = "沙箱执行"

    @staticmethod
    def _absorb_cookies(cookie_jar: dict[str, str], evidence: HttpEvidence) -> None:
        for key, value in evidence.headers:
            if key.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0]
            if "=" in pair:
                name, cookie_value = pair.split("=", 1)
                if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name.strip()):
                    cookie_jar[name.strip()] = cookie_value.strip()

    @staticmethod
    def _with_cookie_jar(request: HttpRequest, cookie_jar: dict[str, str]) -> HttpRequest:
        if not cookie_jar:
            return request
        merged = dict(cookie_jar)
        for key, value in request.headers.items():
            if key.lower() == "cookie":
                for part in value.split(";"):
                    if "=" in part:
                        name, cookie_value = part.split("=", 1)
                        cookie_value = cookie_value.strip()
                        # Generated multi-step POCs may document a value as
                        # <step 1 value>; the jar already contains the real
                        # value, so never let a narrative placeholder replace it.
                        if cookie_value.startswith(("<", "${")):
                            continue
                        merged[name.strip()] = cookie_value
        headers = {key: value for key, value in request.headers.items() if key.lower() != "cookie"}
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in merged.items())
        return HttpRequest(method=request.method, url=request.url, headers=headers,
                           body=request.body, raw=request.raw)

    def run(self, case: PocCase, *, timeout: float, insecure: bool,
            allow_hosts: list[str], follow_redirects: bool = False) -> tuple[HttpEvidence, HttpEvidence, dict]:
        started = time.time()
        baseline = case.baseline
        if baseline is None:
            baseline = HttpRequest(method="GET", url=case.target_url, headers={}, body=b"", raw="")
        base_evidence = execute(
            baseline, timeout=timeout, insecure=insecure,
            allow_hosts=allow_hosts, follow_redirects=follow_redirects,
        )
        cookie_jar: dict[str, str] = {}
        self._absorb_cookies(cookie_jar, base_evidence)
        requests = case.attack_sequence or [case.attack]
        sequence_evidence: list[HttpEvidence] = []
        for request in requests:
            replay = self._with_cookie_jar(request, cookie_jar)
            evidence = execute(
                replay, timeout=timeout, insecure=insecure,
                allow_hosts=allow_hosts, follow_redirects=follow_redirects,
            )
            sequence_evidence.append(evidence)
            self._absorb_cookies(cookie_jar, evidence)
            if evidence.error:
                break
        attack_evidence = sequence_evidence[-1] if sequence_evidence else HttpEvidence(error="no attack request")
        case.last_attack_sequence = sequence_evidence
        return base_evidence, attack_evidence, {
            "agent": self.name,
            "codename": self.codename,
            "finding_id": case.finding_id,
            "baseline_status": base_evidence.status,
            "attack_status": attack_evidence.status,
            "baseline_error": base_evidence.error,
            "attack_error": attack_evidence.error,
            "attack_requests": len(requests),
            "attack_responses": len(sequence_evidence),
            "cookie_jar_names": sorted(cookie_jar),
            "duration_sec": round(time.time() - started, 2),
        }
