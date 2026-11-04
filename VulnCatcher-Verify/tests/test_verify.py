"""VulnCatcher-Verify end-to-end tests against a local fixture HTTP server."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sunset_verify.collector import collect_from_result
from sunset_verify.config import VerifySettings
from sunset_verify.pipeline import verify_result, verify_batch


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"normal page"
        if self.path.startswith("/weakid"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "dvwaSession=1; Path=/")
            self.end_headers()
            self.wfile.write(b"baseline")
            return
        if self.path.startswith("/pathtraver"):
            cookie = self.headers.get("Cookie", "")
            if "../" in cookie or "..%2F" in cookie:
                body = b"root:x:0:0:root:/root:/bin/bash\n"
            else:
                body = b"Now ready to write to file: testfiles/FileName\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "SomeCookie=test; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.startswith("/weakid"):
            current = 0
            for part in self.headers.get("Cookie", "").split(";"):
                if part.strip().startswith("dvwaSession="):
                    current = int(part.split("=", 1)[1])
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", f"dvwaSession={current + 1}; Path=/")
            self.end_headers()
            self.wfile.write(str(current + 1).encode())
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


def _write_result(root: Path, target: str, request: str) -> Path:
    result = root / "result"
    (result / "poc" / "F1").mkdir(parents=True)
    report = {
        "schema_version": "1.0",
        "run": {"run_id": "t", "input_mode": "url", "target_url": target},
        "findings": [
            {
                "id": "F1",
                "vulnerability_type": "path_traversal",
                "title": "fixture",
                "origin": "awvs",
                "location": {"file": "", "line_start": 0, "line_end": 0,
                             "endpoint": "/pathtraver", "http_method": "GET"},
                "poc": {
                    "steps": [
                        {"step": 1, "action": "baseline",
                         "request": f"curl -sS -i -X GET '{target}/pathtraver'"},
                        {"step": 2, "action": "attack", "request": request},
                    ],
                    "scripts": {"poc.sh": request},
                    "safety": {"target_url": target, "executed": False},
                },
            }
        ],
    }
    (result / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return result


class TestVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_url_mode_verifies_traversal(self):
        with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
            root = Path(tmp)
            request = (
                f"curl -sS -i -X GET '{self.base}/pathtraver' "
                "-H 'Cookie: BenchmarkTest=../../etc/passwd'"
            )
            result_dir = _write_result(root, self.base, request)
            results, _ = verify_result(result_dir, VerifySettings(
                mode="url", result_dir=result_dir, target_base=self.base,
                timeout=5, insecure=True,
            ))
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].verdict, "verified")
            self.assertTrue((result_dir / "verification" / "verification.json").is_file())

    def test_zip_mode_resolves_target_base(self):
        with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
            root = Path(tmp)
            request = "curl -sS -i -X GET 'http://TARGET:8080/pathtraver' -H 'Cookie: BenchmarkTest=../../etc/passwd'"
            result_dir = _write_result(root, "http://TARGET:8080", request)
            results, _ = verify_result(result_dir, VerifySettings(
                mode="zip", result_dir=result_dir, target_base=self.base,
                timeout=5, insecure=True,
            ))
            self.assertEqual(results[0].verdict, "verified")
            self.assertTrue(results[0].target_url.startswith(self.base))

    def test_legacy_awvs_single_step_is_not_replayed_as_its_own_baseline(self):
        attack = "GET /lab?q=attack HTTP/1.1\r\nHost: TARGET\r\n\r\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {"findings": [{"id": "AWVS-1", "origin": "awvs", "poc": {
                "steps": [{"step": 1, "request": attack}],
                "scripts": {"awvs_request.http": attack},
            }}]}
            (root / "report.json").write_text(json.dumps(report), encoding="utf-8")
            case, = collect_from_result(root, mode="zip", base=self.base + "/lab?q=clean")
            self.assertEqual(case.attack.url, self.base + "/lab?q=attack")
            self.assertEqual(case.baseline.url, self.base + "/lab")

    def test_external_host_is_blocked(self):
        with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
            root = Path(tmp)
            request = "curl -sS -i -X GET 'http://example.com/pathtraver'"
            result_dir = _write_result(root, "http://example.com", request)
            results, _ = verify_result(result_dir, VerifySettings(
                mode="url", result_dir=result_dir, target_base="",
                timeout=5, insecure=True,
            ))
            self.assertEqual(results[0].verdict, "error")
            self.assertIn("allowlisted", results[0].reason)

    def test_batch_aggregate(self):
        with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
            root = Path(tmp)
            request = "curl -sS -i -X GET 'http://TARGET:8080/pathtraver' -H 'Cookie: BenchmarkTest=../../etc/passwd'"
            _write_result(root / "a", "http://TARGET:8080", request)
            _write_result(root / "b", "http://TARGET:8080", request)
            results, _ = verify_batch(VerifySettings(
                mode="zip", results_dir=root, target_base=self.base,
                out_dir=root / "out", timeout=5, insecure=True, workers=2,
            ))
            self.assertEqual(len(results), 2)
            self.assertTrue((root / "out" / "verification-batch.json").is_file())

    def test_multi_request_cookie_sequence_verifies_weak_id(self):
        with tempfile.TemporaryDirectory(prefix="verify-weakid-") as tmp:
            root = Path(tmp)
            result = root / "result"
            result.mkdir(parents=True)
            report = {
                "run": {"target_url": self.base},
                "findings": [{
                    "id": "W1", "vulnerability_type": "weak_id", "title": "weak id",
                    "location": {"endpoint": "/weakid", "http_method": "POST"},
                    "poc": {"steps": [
                        {"step": 1, "request": f"curl -sS -i '{self.base}/weakid'"},
                        {"step": 2, "request": f"curl -sS -i -X POST '{self.base}/weakid'"},
                        {"step": 3, "request": f"curl -sS -i -X POST '{self.base}/weakid'"},
                    ]},
                }],
            }
            (result / "report.json").write_text(json.dumps(report), encoding="utf-8")
            results, _ = verify_result(result, VerifySettings(
                mode="url", result_dir=result, target_base=self.base,
                timeout=5, insecure=True,
            ))
            self.assertEqual(results[0].verdict, "verified")
            self.assertEqual(len(results[0].attack_sequence), 2)

    def test_single_numeric_session_cookie_is_not_verified(self):
        with tempfile.TemporaryDirectory(prefix="verify-weakid-single-") as tmp:
            root = Path(tmp)
            result = root / "result"
            result.mkdir(parents=True)
            report = {
                "run": {"target_url": self.base},
                "findings": [{
                    "id": "W1", "vulnerability_type": "weak_id", "title": "weak id",
                    "location": {"endpoint": "/weakid", "http_method": "POST"},
                    "poc": {"steps": [
                        {"step": 1, "request": f"curl -sS -i '{self.base}/weakid'"},
                        {"step": 2, "request": f"curl -sS -i -X POST '{self.base}/weakid'"},
                    ]},
                }],
            }
            (result / "report.json").write_text(json.dumps(report), encoding="utf-8")
            results, _ = verify_result(result, VerifySettings(
                mode="url", result_dir=result, target_base=self.base,
                timeout=5, insecure=True,
            ))
            self.assertEqual(results[0].verdict, "inconclusive")


if __name__ == "__main__":
    unittest.main()
