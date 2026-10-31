"""Sandboxed HTTP executor for 落日验证.

Only HTTP(S), only allowlisted hosts, no shell, no file writes.  The verifier
executes the *request objects* parsed from 落日二号 POCs, never the POC script
itself.
"""

from __future__ import annotations

import http.client
import ssl
import time
import urllib.parse
from typing import Iterable

from .models import HttpEvidence, HttpRequest


class SandboxError(RuntimeError):
    pass


def _is_allowed(host: str, allow_hosts: Iterable[str]) -> bool:
    host = (host or "").lower().strip("[]")
    defaults = {"localhost", "127.0.0.1", "::1"}
    allowed = defaults | {item.lower().strip("[]") for item in allow_hosts if item}
    return host in allowed


def execute(request: HttpRequest, *, timeout: float = 15.0, insecure: bool = True,
            allow_hosts: Iterable[str] = (), follow_redirects: bool = False) -> HttpEvidence:
    started = time.time()
    parsed = urllib.parse.urlsplit(request.url)
    if parsed.scheme not in {"http", "https"}:
        return HttpEvidence(error=f"unsupported scheme: {parsed.scheme}", duration_ms=0)
    host = parsed.hostname or ""
    if not _is_allowed(host, allow_hosts):
        return HttpEvidence(error=f"host not allowlisted: {host}", duration_ms=0)

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = dict(request.headers)
    headers.pop("Content-Length", None)
    headers.pop("Host", None)
    body = request.body or b""
    if body:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    headers["Content-Length"] = str(len(body))
    headers.setdefault("Connection", "close")

    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    for attempt in range(2):
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            try:
                conn.request(request.method, path, body=body, headers=headers)
                response = conn.getresponse()
                raw = response.read(2 * 1024 * 1024)
                evidence = HttpEvidence(
                    status=response.status,
                    headers=[(key, value) for key, value in response.getheaders()],
                    body=raw.decode("utf-8", errors="replace"),
                    duration_ms=int((time.time() - started) * 1000),
                )
            finally:
                conn.close()
            if follow_redirects and evidence.status in {301, 302, 303, 307, 308}:
                location = dict(evidence.headers).get("Location") or dict(evidence.headers).get("location")
                if location:
                    next_request = HttpRequest(
                        method="GET" if evidence.status in {301, 302, 303} else request.method,
                        url=urllib.parse.urljoin(request.url, location),
                        headers={key: value for key, value in request.headers.items()
                                 if key.lower() not in {"content-type", "content-length"}},
                        body=b"",
                        raw="",
                    )
                    return execute(next_request, timeout=timeout, insecure=insecure,
                                   allow_hosts=allow_hosts, follow_redirects=False)
            return evidence
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            if attempt == 0:
                time.sleep(0.2)
                continue
            return HttpEvidence(error=f"{type(exc).__name__}: {exc}",
                                duration_ms=int((time.time() - started) * 1000))
    return HttpEvidence(error="unreachable", duration_ms=int((time.time() - started) * 1000))
