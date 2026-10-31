"""Run local static + HTTP/state comparisons; no .env, APIs or external targets.

Usage: python -m examples.logic_lab.run_experiment --out docs/experiments/logic_20261101
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from .server import running_lab

HERE = Path(__file__).resolve().parent
FIXTURE_FILES = ("vulnerable.py", "fixed.py", "missing_context.py")


def _request(base, path, body, session="alice-demo"):
    request = Request(base + path, json.dumps(body).encode("utf-8"),
                      headers={"Content-Type": "application/json", "Cookie": "lab_session=" + session},
                      method="POST")
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as response:
        with response:
            return response.code, json.loads(response.read())


def _cases():
    verify = {"path": "/verify", "body": {"answer": "demo-ok"}, "session": "alice-demo",
              "expected_status": 200, "expected_captcha": True, "expected_store_change": False}
    return [
        {"id": "workflow_direct", "category": "workflow_bypass", "path": "/password",
         "body": {"password": "changed"}, "vulnerable": True, "fixed": False},
        {"id": "workflow_forged_client_flag", "category": "workflow_bypass", "path": "/password-client",
         "body": {"password": "changed", "passed_captcha": True}, "vulnerable": True, "fixed": False},
        {"id": "workflow_missing_client_flag", "category": "workflow_bypass", "path": "/password-client",
         "body": {"password": "changed"}, "vulnerable": False, "fixed": False},
        {"id": "workflow_verified", "category": "workflow_bypass", "path": "/password",
         "setup": [verify], "body": {"password": "changed"}, "vulnerable": True, "fixed": True},
        {"id": "workflow_client_verified", "category": "workflow_bypass", "path": "/password-client",
         "setup": [verify], "body": {"password": "changed", "passed_captcha": True},
         "vulnerable": True, "fixed": True},
        {"id": "workflow_wrong_verification", "category": "workflow_bypass", "path": "/password",
         "setup": [{"path": "/verify", "body": {"answer": "wrong"}, "session": "alice-demo",
                    "expected_status": 403, "expected_captcha": False, "expected_store_change": False}],
         "body": {"password": "changed"}, "vulnerable": True, "fixed": False},
        {"id": "workflow_other_session", "category": "workflow_bypass", "path": "/password",
         "setup": [{"path": "/verify", "body": {"answer": "demo-ok"}, "session": "bob-demo",
                    "expected_status": 200, "expected_captcha": True, "expected_store_change": False}],
         "body": {"password": "changed"}, "vulnerable": True, "fixed": False},
        {"id": "workflow_replay", "category": "workflow_bypass", "path": "/password",
         "setup": [verify, {"path": "/password", "body": {"password": "first-change"}, "session": "alice-demo",
                            "expected_status": 200, "expected_captcha": {"vulnerable": True, "fixed": False},
                            "expected_store_change": True}],
         "body": {"password": "second-change"}, "vulnerable": True, "fixed": False},
        {"id": "object_other_order", "category": "object_authorization", "path": "/order",
         "body": {"order_id": "202", "memo": "changed"}, "vulnerable": True, "fixed": False},
        {"id": "object_own_order", "category": "object_authorization", "path": "/order",
         "body": {"order_id": "101", "memo": "changed"}, "vulnerable": True, "fixed": True},
        {"id": "object_forged_user", "category": "object_authorization", "path": "/order",
         "body": {"order_id": "202", "memo": "changed", "user_id": "bob"},
         "vulnerable": True, "fixed": False},
        {"id": "quantity_negative", "category": "business_constraint", "path": "/purchase",
         "body": {"quantity": -2}, "vulnerable": True, "fixed": False},
        {"id": "quantity_zero", "category": "business_constraint", "path": "/purchase",
         "body": {"quantity": 0}, "vulnerable": True, "fixed": False},
        {"id": "quantity_valid", "category": "business_constraint", "path": "/purchase",
         "body": {"quantity": 2}, "vulnerable": True, "fixed": True},
        {"id": "quantity_wrong_type", "category": "business_constraint", "path": "/purchase",
         "body": {"quantity": "2"}, "vulnerable": False, "fixed": False},
        {"id": "unauthenticated", "category": "transport_control", "path": "/password",
         "session": "not-a-session", "body": {"password": "changed"},
         "vulnerable": False, "fixed": False},
    ]


def _expected_state(before, path, body, session, accepted):
    expected = copy.deepcopy(before)
    if not accepted:
        return expected
    user = {"alice-demo": "alice", "bob-demo": "bob"}[session]
    if path in {"/password", "/password-client"}:
        expected["passwords"][user] = body["password"]
    elif path == "/order":
        expected["orders"][body["order_id"]]["memo"] = body["memo"]
    elif path == "/purchase":
        expected["credits"][user] -= body["quantity"] * 10
        expected["purchases"].append({"user_id": user, "quantity": body["quantity"]})
    return expected


def run_dynamic():
    results = []
    for variant in ("vulnerable", "fixed"):
        for case in _cases():
            with running_lab(variant) as (lab, base):
                setup_log = []
                for step in case.get("setup", []):
                    path, body, session = step["path"], step["body"], step["session"]
                    state_before = lab.store.snapshot()
                    sessions_before = copy.deepcopy(lab.sessions)
                    expected_state = _expected_state(state_before, path, body, session, step["expected_store_change"])
                    expected_sessions = copy.deepcopy(sessions_before)
                    expected_captcha = step["expected_captcha"]
                    if isinstance(expected_captcha, dict):
                        expected_captcha = expected_captcha[variant]
                    expected_sessions[session]["captcha_passed"] = expected_captcha
                    status, response = _request(base, path, body, session)
                    state_after = lab.store.snapshot()
                    sessions_after = copy.deepcopy(lab.sessions)
                    setup_passed = (status == step["expected_status"] and state_after == expected_state
                                    and sessions_after == expected_sessions)
                    setup_log.append({
                        "path": path, "session": session, "body": body, "http_status": status,
                        "response_body": response, "expected_http_status": step["expected_status"],
                        "state_before": state_before, "state_after": state_after, "expected_state_after": expected_state,
                        "sessions_before": sessions_before, "sessions_after": sessions_after,
                        "expected_sessions_after": expected_sessions, "passed": setup_passed,
                    })
                before = lab.store.snapshot()
                session = case.get("session", "alice-demo")
                status, _ = _request(base, case["path"], case["body"], session)
                after = lab.store.snapshot()
                changed, expected = before != after, case[variant]
                expected_after = _expected_state(before, case["path"], case["body"], session, expected)
                setup_passed = all(step["passed"] for step in setup_log)
                passed = setup_passed and after == expected_after and changed == expected and ((status == 200) == expected)
                results.append({
                    "case_id": case["id"], "category": case["category"], "variant": variant,
                    "request": {"method": "POST", "path": case["path"], "session": session, "body": case["body"]},
                    "setup": setup_log, "setup_passed": setup_passed, "http_status": status,
                    "state_before": before, "state_after": after, "expected_state_after": expected_after,
                    "state_matches_expected": after == expected_after, "state_changed": changed,
                    "expected_state_changed": expected, "passed": passed,
                })
    return results


def build_source_zip(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FIXTURE_FILES:
            entry = zipfile.ZipInfo(name, date_time=(2026, 11, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, (HERE / name).read_bytes())
    return destination


def _project(contents, root):
    from sunset.models import Project, SourceFile
    files = [SourceFile(rel_path=name, size=len(text.encode("utf-8")), lines=len(text.splitlines()),
                        language="python" if name.endswith(".py") else "php",
                        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
             for name, text in contents.items()]
    return Project(zip_path="", zip_sha256="", root=str(root), extracted_dir=str(root), files=files)


def run_static():
    from sunset.logic_analysis import analyze_logic
    contents = {name: (HERE / name).read_text(encoding="utf-8") for name in FIXTURE_FILES}
    policy = json.loads((HERE / "policies.json").read_text(encoding="utf-8"))
    assessments = analyze_logic(_project(contents, HERE), contents, policies=policy["rules"])
    by_rule = {item["rule_id"]: item for item in assessments}
    checks = []
    for rule in policy["rules"]:
        expected = {"vulnerable.py": "candidate", "fixed.py": "guarded",
                    "missing_context.py": "needs_context"}[rule["file"]]
        result = by_rule.get(rule["id"], {})
        checks.append({"rule_id": rule["id"], "file": rule["file"], "function": rule["function"],
                       "category": rule["category"], "expected": expected,
                       "actual": result.get("status", "missing"), "passed": result.get("status") == expected})
    return assessments, checks


def run_repository_static():
    from sunset.logic_analysis import analyze_logic
    sample_root = HERE.parents[2] / "暴风星云裂"
    entries = []
    for name in ("014.php", "015.php"):
        path = sample_root / name
        if not path.is_file():
            entries.append({"file": name, "available": False, "dynamic_verified": False})
            continue
        data = path.read_bytes()
        contents = {name: data.decode("utf-8")}
        assessments = analyze_logic(_project(contents, sample_root), contents)
        entries.append({"file": name, "available": True, "sha256": hashlib.sha256(data).hexdigest(),
                        "assessments": assessments, "dynamic_verified": False,
                        "note": "仓库原始 PHP 源码仅做静态分析；未启动 DVWA / PHP / 数据库。"})
    return entries


def _markdown(result):
    lines = ["# 勇旭：隐性逻辑漏洞本地对照实验", "",
             f"- UTC 时间：{result['generated_at']}",
             "- HTTP 实验来源：自行编写的最小教学复现，不是原始 DVWA / PHP 样本的动态运行记录。",
             "- 绑定：127.0.0.1 随机端口；Python 标准库；未调用 LLM、AWVS 或任何外部目标。",
             "- 静态分析与 HTTP 实验使用同一组 vulnerable.py / fixed.py 函数。",
             "- 可信策略由实验方在源码包之外提供；缺上下文样本只分析、不执行。",
             "- 动态结论根据服务端状态变化和响应共同判断，不是仅检查 HTTP 200。",
             "- 每个准备步骤也核对预期 HTTP、完整业务状态及各会话状态；前置条件不成立时该场景判为失败。",
             "- 验证码用确定性的服务端测试桩代替，只验证流程状态与会话绑定，不测试验证码算法。",
             "- 实验未覆盖生产持久化、并发、完整认证和所有业务规则。", "",
             f"静态对照：{sum(x['passed'] for x in result['static_checks'])}/{len(result['static_checks'])} 满足预期。",
             f"HTTP 对照：{sum(x['passed'] for x in result['dynamic'])}/{len(result['dynamic'])} 满足预期。",
             "", "## 静态判定", "",
             "| 规则 | 类别 | 预期 | 实际 | 通过 |", "|---|---|---|---|---|"]
    for item in result["static_checks"]:
        lines.append(f"| {item['rule_id']} | {item['category']} | {item['expected']} | {item['actual']} | {item['passed']} |")
    lines += ["", "## 仓库原始 PHP 样本（仅静态）", ""]
    for item in result["repository_static"]:
        statuses = ", ".join(x["status"] for x in item.get("assessments", [])) or "未得到结果"
        lines.append(f"- {item['file']}：{statuses}；动态验证：未执行。")
    lines += ["", "## HTTP 与状态对照", "",
              "| 场景 | 版本 | HTTP | 状态改变 | 预期改变 | 通过 |", "|---|---|---|---|---|---|"]
    for item in result["dynamic"]:
        lines.append(f"| {item['case_id']} | {item['variant']} | {item['http_status']} | {item['state_changed']} | {item['expected_state_changed']} | {item['passed']} |")
    lines += ["", "完整请求、服务端状态前后值、分析证据和 SHA-256 见 experiment.json。", "",
              "## 复现", "", "在 ver5 目录执行：", "",
              "    python -m examples.logic_lab.run_experiment --out docs/experiments/logic_20261101",
              "    python -m unittest discover -s tests -p test_logic_lab.py -v", ""]
    return "\n".join(lines)


def run_experiment(output):
    from sunset import logic_analysis
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    assessments, checks = run_static()
    dynamic = run_dynamic()
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(HERE.iterdir()) if path.is_file() and path.suffix in {".py", ".json"}}
    archive = build_source_zip(output / "logic_lab_sources.zip")
    passed = all(item["passed"] for item in checks + dynamic)
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fixture_provenance": "synthetic_minimal_reproduction_not_DVWA",
        "runtime": {"python": sys.version.split()[0], "bind": "127.0.0.1", "external_requests": False},
        "source_sha256": hashes,
        "analyzer_sha256": hashlib.sha256(Path(logic_analysis.__file__).read_bytes()).hexdigest(),
        "policy_sha256": hashes["policies.json"], "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "summary": {"static_status_counts": dict(Counter(item["status"] for item in assessments)),
                    "static_passed": sum(item["passed"] for item in checks), "static_total": len(checks),
                    "dynamic_passed": sum(item["passed"] for item in dynamic), "dynamic_total": len(dynamic),
                    "all_passed": passed},
        "static_checks": checks, "assessments": assessments, "repository_static": run_repository_static(),
        "dynamic": dynamic,
    }
    (output / "experiment.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "experiment.md").write_text(_markdown(result), encoding="utf-8")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("sunset-results/logic-lab"))
    args = parser.parse_args(argv)
    result = run_experiment(args.out)
    print(json.dumps(result["summary"], ensure_ascii=False))
    print(str(args.out.resolve() / "experiment.md"))
    return 0 if result["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
