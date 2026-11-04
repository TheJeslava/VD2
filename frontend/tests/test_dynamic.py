"""Verify the recorded HTTP evidence, not just the presence of a report file."""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

FRONTEND = Path(__file__).resolve().parents[1]


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        value = parse_qs(url.query).get("q", [""])[0]
        ok = url.path == "/lab"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if ok:
            self.wfile.write(("<p>innerHTML</p>" + (escape(value) if self.server.escaped else value)).encode())

    def log_message(self, *args):
        pass


class TestDynamicEvidence(unittest.TestCase):
    def test_probe_and_reverification(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as lab, tempfile.TemporaryDirectory() as output:
            lab.escaped = False
            threading.Thread(target=lab.serve_forever, daemon=True).start()
            target = f"http://127.0.0.1:{lab.server_port}/lab?q=normal"
            child = subprocess.Popen(
                [sys.executable, "-B", "-u", str(FRONTEND / "server.py"), "--port", "0", "--data", output],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                env={k: v for k, v in os.environ.items() if not k.startswith(("SUNSET_", "AWVS_"))},
            )
            try:
                self.origin = child.stdout.readline().strip().split()[-1]
                blob = (FRONTEND / "lab-source.zip").read_bytes()
                for mode in ("url", "zip"):
                    with self.subTest(mode=mode):
                        lab.escaped = False
                        job = self.api("/api/jobs", {"mode": mode, "url": target}, blob if mode == "zip" else b"")
                        route = "/api/jobs/" + job["id"]
                        self.wait_done(route, "status")
                        finding = next(r for r in self.api(route + "/findings") if r["vulnerability_type"] == "xss")
                        attempts = []
                        for encoded, expected in ((False, "verified"), (True, "rejected")):
                            lab.escaped = encoded
                            self.api(route + "/verify", {"url": target})
                            attempts.append(self.wait_done(route, "verification")["verificationId"])
                            result = next(r for r in self.api(route + "/verdicts") if r["finding_id"] == finding["id"])
                            self.assertEqual(urlsplit(result["target_url"]).path, "/lab")
                            self.assertEqual(result["baseline"]["body_preview"], "<p>innerHTML</p>normal")
                            self.assertEqual(result["verdict"], expected, result["reason"])
                        self.assertNotEqual(*attempts)
                job = self.api("/api/jobs", {"mode": "url", "url": target})
                done = self.wait_done("/api/jobs/" + job["id"], "status")
                self.assertEqual(done["count"], 0)
            finally:
                lab.shutdown()
                child.terminate()
                child.wait(timeout=10)
                child.stdout.close()

    def api(self, path, meta=None, body=b""):
        headers = {"X-VD2": "1", "X-Job": quote(json.dumps(meta or {}))}
        req = Request(self.origin + path, data=body if meta is not None else None, headers=headers)
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    def wait_done(self, route, field):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = self.api(route)
            if state[field] != "running":
                self.assertEqual(state[field], "done", state["error"])
                return state
            time.sleep(.05)
        self.fail("Engine timed out")


if __name__ == "__main__":
    unittest.main()
