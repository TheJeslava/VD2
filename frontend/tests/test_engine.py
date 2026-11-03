"""Regression: the workbench must analyze the submitted bytes, including clean input."""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import quote, urlsplit
import zipfile


FRONTEND = Path(__file__).resolve().parents[1]


class EngineIntegrationTest(unittest.TestCase):
    def test_real_zip_reports(self):
        with tempfile.TemporaryDirectory() as data:
            child = subprocess.Popen(
                [sys.executable, "-B", "-u", str(FRONTEND / "server.py"), "--port", "0", "--data", data],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                env={k: v for k, v in os.environ.items() if not k.startswith(("AWVS_", "SUNSET_"))},
            )
            try:
                origin = child.stdout.readline().strip().split()[-1]
                port = urlsplit(origin).port
                clean = io.BytesIO()
                with zipfile.ZipFile(clean, "w") as archive:
                    archive.writestr("Hello.java", "class Hello { int answer() { return 42; } }")
                for blob, expect_findings in ((clean.getvalue(), False), ((FRONTEND / "lab-source.zip").read_bytes(), True)):
                    with self.subTest(expect_findings=expect_findings):
                        job = self.request(port, "POST", "/api/jobs", blob)
                        route = "/api/jobs/" + job["id"]
                        deadline = time.monotonic() + 30
                        while time.monotonic() < deadline:
                            state = self.request(port, "GET", route)
                            if state["status"] != "running":
                                break
                            time.sleep(0.1)
                        self.assertEqual(state["status"], "done", state["error"])
                        self.assertIn(("report", "done"), [(r["key"], r["state"]) for r in state["events"]])
                        report = json.loads((Path(data) / job["id"] / "scan/report.json").read_text(encoding="utf-8"))
                        rows = self.request(port, "GET", route + "/findings")
                        self.assertEqual(rows, report["findings"])
                        self.assertEqual(bool(rows), expect_findings)
                        self.assertIn(hashlib.sha256(blob).hexdigest(), json.dumps(report))
            finally:
                child.terminate()
                child.wait(timeout=10)
                child.stdout.close()

    def request(self, port, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            headers = {"X-VD2": "1", "X-Job": quote(json.dumps({"mode": "zip", "name": "test.zip"}))}
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            data = json.loads(response.read())
            self.assertLess(response.status, 300, data)
            return data
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
