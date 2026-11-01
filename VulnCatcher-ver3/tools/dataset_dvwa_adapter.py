"""Local-only adapter for replaying integrated dataset POCs against the DVWA lab.

The generated POCs use dataset sample paths (for example ``/025.php``),
while the PHP lab exposes category routes.  This adapter translates only
those local sample paths and forwards HTTP requests to the isolated DVWA
container.  It never accepts non-local clients and never executes scripts.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import re
import urllib.parse
from pathlib import Path

UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 18080
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18081
LOG_PATH = Path(__file__).with_name("dataset_dvwa_adapter.log")

ROUTES = {
    "001": "/vulnerabilities/api/",
    "002": "/vulnerabilities/api/",
    "003": "/vulnerabilities/api/",
    "004": "/vulnerabilities/authbypass/",
    "005": "/vulnerabilities/authbypass/",
    "006": "/vulnerabilities/authbypass/",
    "007": "/vulnerabilities/bac/",
    "008": "/vulnerabilities/bac/",
    "009": "/vulnerabilities/bac/",
    "010": "/vulnerabilities/brute/",
    "011": "/vulnerabilities/brute/",
    "012": "/vulnerabilities/brute/",
    "013": "/vulnerabilities/captcha/",
    "014": "/vulnerabilities/captcha/",
    "015": "/vulnerabilities/captcha/",
    "016": "/vulnerabilities/cryptography/",
    "017": "/vulnerabilities/cryptography/",
    "018": "/vulnerabilities/cryptography/",
    "019": "/vulnerabilities/csp/",
    "020": "/vulnerabilities/csp/",
    "021": "/vulnerabilities/csp/",
    "022": "/vulnerabilities/csrf/",
    "023": "/vulnerabilities/csrf/",
    "024": "/vulnerabilities/csrf/",
    "025": "/vulnerabilities/exec/",
    "026": "/vulnerabilities/exec/",
    "027": "/vulnerabilities/exec/",
    "028": "/vulnerabilities/fi/",
    "029": "/vulnerabilities/fi/",
    "030": "/vulnerabilities/fi/",
    "031": "/vulnerabilities/javascript/",
    "032": "/vulnerabilities/javascript/",
    "033": "/vulnerabilities/javascript/",
    "034": "/vulnerabilities/open_redirect/",
    "035": "/vulnerabilities/open_redirect/",
    "036": "/vulnerabilities/open_redirect/",
    "037": "/vulnerabilities/sqli_blind/",
    "038": "/vulnerabilities/sqli_blind/",
    "039": "/vulnerabilities/sqli_blind/",
    "040": "/vulnerabilities/sqli/",
    "041": "/vulnerabilities/sqli/",
    "042": "/vulnerabilities/sqli/",
    "043": "/vulnerabilities/upload/",
    "044": "/vulnerabilities/upload/",
    "045": "/vulnerabilities/upload/",
    "046": "/vulnerabilities/weak_id/",
    "047": "/vulnerabilities/weak_id/",
    "048": "/vulnerabilities/weak_id/",
    "049": "/vulnerabilities/xss_d/",
    "050": "/vulnerabilities/xss_d/",
    "051": "/vulnerabilities/xss_d/",
    "052": "/vulnerabilities/xss_r/",
    "053": "/vulnerabilities/xss_r/",
    "054": "/vulnerabilities/xss_r/",
    "055": "/vulnerabilities/xss_s/",
    "056": "/vulnerabilities/xss_s/",
    "057": "/vulnerabilities/xss_s/",
    # 058 is a multi-file SQLi-Labs sample; the DVWA SQLi route is used only
    # as a reachable local URL fallback, not as proof of the same data flow.
    "058": "/vulnerabilities/sqli/",
}


def _sample_route(path: str) -> tuple[str, str] | None:
    match = re.match(r"^/(\d{3})(?:\.php)?(?:/)?$", urllib.parse.urlsplit(path).path)
    if not match:
        return None
    sample = match.group(1)
    route = ROUTES.get(sample)
    return (sample, route) if route else None


def _rewrite(sample: str, route: str, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[str, dict[str, str], bytes]:
    parsed = urllib.parse.urlsplit(path)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_map = dict(query)
    if sample == "008":
        query_map.setdefault("action", "view")
        query_map.setdefault("user_id", "2")
        cookie = headers.get("Cookie", "")
        if "user_id=" in cookie and "id=" not in cookie:
            headers["Cookie"] = re.sub(r"(?:^|;\s*)user_id=([^;]*)", r"id=\1", cookie)
    if sample in {"011", "012"}:
        query_map.setdefault("Login", "Login")
    if sample in {"025", "026", "027"} and method in {"POST", "ANY"}:
        text = body.decode("utf-8", errors="replace")
        if "Submit=" not in text:
            body = (text + ("&" if text else "") + "Submit=Submit").encode()
        headers["Content-Length"] = str(len(body))
    if sample in {"037", "038", "039"}:
        query_map.setdefault("Submit", "Submit")
        if "id=" not in headers.get("Cookie", ""):
            headers["Cookie"] = (headers.get("Cookie", "") + "; " if headers.get("Cookie") else "") + "id=1"
    if sample in {"028", "029", "030"}:
        # DVWA's file-inclusion page redirects when the page selector is absent.
        query_map.setdefault("page", "include.php")
    if sample in {"041", "042"}:
        query_map.setdefault("Submit", "Submit")
        if "id=" not in query_map:
            query_map["id"] = query_map.pop("user_id", "1")
    if sample in {"034", "035", "036"} and "url" not in query_map:
        query_map["url"] = query_map.pop("redirect", "//example.com")
    rewritten = route
    encoded = urllib.parse.urlencode(query_map)
    if encoded:
        rewritten += "?" + encoded
    return rewritten, headers, body


class Adapter(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def do_ANY(self) -> None:
        self._forward()

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _forward(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {"host", "content-length"}}
        mapped = _sample_route(self.path)
        sample = "unmapped"
        upstream_path = self.path
        if mapped:
            sample, route = mapped
            upstream_path, headers, body = _rewrite(sample, route, self.command, self.path, headers, body)
        headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
        headers["Content-Length"] = str(len(body))
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=15)
            conn.request(self.command, upstream_path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read(2 * 1024 * 1024)
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "content-length", "transfer-encoding"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            with LOG_PATH.open("a", encoding="utf-8") as log:
                log.write(f"{self.command} {self.path} -> {upstream_path} [{sample}] {response.status} {len(data)}\n")
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    server = http.server.ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Adapter)
    print(f"integrated dataset DVWA adapter listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
