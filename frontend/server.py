"""Local, same-origin web console for VD2. Python 3.10+; no dependencies."""
import argparse
import io
import json
import mimetypes
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from urllib.parse import unquote, urlsplit
from worker import AGENTS, OPTIONAL

HERE = Path(__file__).resolve().parent
LIMIT = 32 * 1024 * 1024
LOCK = threading.RLock()
STATIC = {"index.html", "app.js", "review.js", "samples.js", "style.css", "mark.svg", "stack.svg", "lab-source.zip"}
STATIC.update(f"samples/{kind}/{file}" for kind in ("zip", "url", "hybrid") for file in ("report.html", "verification.txt"))
JOBS = {}
PROCESSES = set()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(job):
    dest = DATA / job["id"] / "state.json"
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
    tmp.replace(dest)


def target(value, required):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("URL 格式无效")
    value = value.strip()
    if not value and not required:
        return ""
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None
            or parts.fragment or any(c.isspace() or ord(c) < 32 for c in value)):
        raise ValueError("请输入完整的 HTTP(S) 目标地址，不含账号或锚点")
    _ = parts.port
    return value


def options(raw):
    if not isinstance(raw, dict):
        raise ValueError("模块配置格式错误")
    result = {"llm": raw.get("llm") is True}
    for key, allowed in (("off", OPTIONAL), ("noLlm", AGENTS)):
        values = raw.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) or v not in allowed for v in values):
            raise ValueError("模块配置无效")
        result[key] = sorted(set(values))
    return result


def execute(job, phase):
    folder = DATA / job["id"]
    events = job["verificationEvents" if phase == "verify" else "events"]
    state = "verification" if phase == "verify" else "status"
    try:
        with (folder / "engine.log").open("a", encoding="utf-8") as log:
            proc = subprocess.Popen([sys.executable, "-u", str(HERE / "worker.py"), str(REPO), str(folder), phase],
                                    cwd=folder, stdout=subprocess.PIPE, stderr=log, encoding="utf-8",
                                    errors="replace", env=dict(os.environ, PYTHONIOENCODING="utf-8"))
            with LOCK:
                PROCESSES.add(proc)
            try:
                for line in proc.stdout:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        log.write(line)
                        continue
                    if not isinstance(row, dict) or not {"state", "name", "key", "at"} <= row.keys():
                        continue
                    with LOCK:
                        events.append(row)
                        save(job)
                code = proc.wait()
            finally:
                with LOCK:
                    PROCESSES.discard(proc)
            if code:
                raise ValueError(next((r["note"] for r in reversed(events) if r["state"] == "failed"), "执行器退出，详见本地 engine.log"))
        if phase == "scan":
            count = len(read_json(folder / "scan/report.json")["findings"])
        else:
            count = read_json(folder / "scan/verification/verification.json")["summary"]["total"]
        with LOCK:
            job["count" if phase == "scan" else "verifiedCount"] = count
            job[state] = "done"
            save(job)
    except Exception as exc:
        with LOCK:
            job[state] = "failed"
            job["error"] = str(exc)[:500]
            save(job)


class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, body, mime, status=200, sandbox=False):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", ("sandbox; default-src 'none'; style-src 'unsafe-inline'" if sandbox else
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"))
        self.end_headers()
        self.wfile.write(body)

    def json(self, value, status=200):
        self.send_bytes(json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8", status)

    def local(self):
        port = self.server.server_port
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self):
        if not self.local():
            return self.json({"error": "仅限本机访问"}, 403)
        path = urlsplit(self.path).path
        with LOCK:
            if path == "/api/jobs":
                return self.json([{k: v for k, v in job.items() if k not in ("events", "verificationEvents", "settings")}
                                  for job in reversed(list(JOBS.values()))])
            if path == "/api/health":
                return self.json({"engine": "VulnCatcher v5"})
            match = re.fullmatch(r"/api/jobs/([a-f0-9]{12})(?:/(findings|verdicts|report|verify-report))?", path)
            if match and match[1] in JOBS:
                job = JOBS[match[1]]
                if not match[2]:
                    return self.json(job)
                root = DATA / match[1] / "scan"
                verified = match[2] in ("verdicts", "verify-report")
                if job["verification" if verified else "status"] != "done":
                    return self.json({"error": "报告尚未生成"}, 409)
                if match[2] == "findings":
                    return self.json(read_json(root / "report.json")["findings"])
                if match[2] == "verdicts":
                    return self.json(read_json(root / "verification/verification.json")["results"])
                if verified:
                    return self.send_bytes((root / "verification/verification.md").read_bytes(), "text/plain; charset=utf-8")
                return self.send_bytes((root / "report.html").read_bytes(), "text/html; charset=utf-8", sandbox=True)
        asset = "index.html" if path == "/" else path.lstrip("/")
        if asset in STATIC and (HERE / asset).is_file():
            mime = mimetypes.guess_type(asset)[0] or "application/octet-stream"
            if mime.startswith("text/"):
                mime += "; charset=utf-8"
            return self.send_bytes((HERE / asset).read_bytes(), mime, sandbox=asset.startswith("samples/"))
        self.json({"error": "未找到"}, 404)

    def do_POST(self):
        if (not self.local() or self.headers.get("X-VD2") != "1"
                or self.headers.get("Origin", "http://" + self.headers["Host"]) != "http://" + self.headers["Host"]):
            return self.json({"error": "请求来源不正确"}, 403)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= LIMIT:
                return self.json({"error": "ZIP 最大支持 32 MiB"}, 413)
            meta = json.loads(unquote(self.headers.get("X-Job", "%7B%7D")))
            if not isinstance(meta, dict):
                raise ValueError("任务描述格式无效")
            body = self.rfile.read(size)
            with LOCK:
                if any("running" in (j["status"], j["verification"]) for j in JOBS.values()):
                    return self.json({"error": "执行器正在处理任务，请在当前任务结束后重试"}, 409)
                if self.path == "/api/jobs":
                    mode = meta.get("mode")
                    if mode not in ("zip", "url"):
                        raise ValueError("请选择分析模式")
                    url = target(meta.get("url", ""), mode == "url")
                    settings = options(meta.get("settings", {}))
                    if mode == "zip" and not zipfile.is_zipfile(io.BytesIO(body)):
                        raise ValueError("文件不是有效的 ZIP 归档")
                    if mode == "url" and body:
                        raise ValueError("URL 模式无需文件")
                    name = str(meta.get("name") or "source.zip")[:150] if mode == "zip" else url
                    job = dict(id=uuid.uuid4().hex[:12], mode=mode, url=url, name=name, created=time.time(),
                               kind=("hybrid" if mode == "zip" and url else mode), settings=settings, status="running", verification="idle", verifyUrl="", events=[],
                               verificationEvents=[], count=0, verifiedCount=0, error="")
                    folder = DATA / job["id"]
                    folder.mkdir()
                    if mode == "zip":
                        (folder / "input.zip").write_bytes(body)
                    phase = "scan"
                else:
                    match = re.fullmatch(r"/api/jobs/([a-f0-9]{12})/verify", self.path)
                    if not match or match[1] not in JOBS:
                        return self.json({"error": "找不到任务"}, 404)
                    job = JOBS[match[1]]
                    if job["status"] != "done":
                        raise ValueError("请先完成漏洞挖掘")
                    url = target(job["url"] if job["mode"] == "url" else meta.get("url", ""), True)
                    job.update(verification="running", verificationId=uuid.uuid4().hex, verificationEvents=[],
                               verifiedCount=0, verifyUrl=url, error="")
                    phase = "verify"
                save(job)
                JOBS[job["id"]] = job
                threading.Thread(target=execute, args=(job, phase), daemon=True).start()
                return self.json({"id": job["id"]}, 202)
        except (ValueError, TypeError, UnicodeError) as exc:
            self.json({"error": str(exc)}, 400)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnCatcher 本地工作台")
    parser.add_argument("--repo", type=Path, default=HERE.parent)
    parser.add_argument("--data", type=Path, default=HERE.parent / "vulncatcher-results" / "workbench")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("需要 Python 3.10 或更高版本")
    REPO, DATA = args.repo.resolve(), args.data.resolve()
    if not all((REPO / p).is_file() for p in ("VulnCatcher-ver5/sunset/pipeline.py", "VulnCatcher-Verify/sunset_verify/pipeline.py")):
        parser.error("--repo 应指向含 VulnCatcher-ver5 和 VulnCatcher-Verify 的 VD2 根目录")
    class LocalServer(ThreadingHTTPServer):
        def server_bind(self):
            TCPServer.server_bind(self)
            self.server_name, self.server_port = self.server_address

    server = LocalServer(("127.0.0.1", args.port), Handler)
    DATA.mkdir(parents=True, exist_ok=True)
    if os.environ.get("SUNSET_ENV_FILE"):
        os.environ["SUNSET_ENV_FILE"] = str(Path(os.environ["SUNSET_ENV_FILE"]).resolve(strict=True))
    for entry in sorted(DATA.glob("*/state.json"), key=lambda p: p.parent.stat().st_mtime):
        job = read_json(entry)
        for key in ("status", "verification"):
            if job[key] == "running":
                job[key] = "failed"
                job["error"] = "本地服务已中断，请重新运行"
                save(job)
        JOBS[job["id"]] = job
    JOBS = dict(sorted(JOBS.items(), key=lambda pair: pair[1]["created"]))
    print(f"VulnCatcher · http://127.0.0.1:{server.server_port}", flush=True)
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        with LOCK:
            for proc in PROCESSES:
                proc.terminate()
