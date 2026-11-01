"""Evaluate a Baofeng 58-sample run against the repository's gold categories.

The evaluator is deliberately sample/category based.  It does not treat a
candidate finding or a generated POC as a confirmed vulnerability.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "集成数据集金标提示"
MAPPING = ROOT / "集成数据集" / "编号对应表.md"

CATEGORY_LABELS = {
    "api": "API 信息泄露",
    "authbypass": "认证绕过",
    "bac": "越权/IDOR",
    "brute": "暴力破解",
    "captcha": "验证码绕过",
    "cryptography": "弱加密",
    "csp": "CSP 配置缺陷",
    "csrf": "CSRF",
    "exec": "命令注入",
    "fi": "路径穿越/LFI",
    "javascript": "客户端 JavaScript 校验绕过",
    "open_redirect": "开放重定向",
    "sqli_blind": "盲 SQL 注入",
    "sqli": "SQL 注入",
    "upload": "文件上传",
    "weak_id": "弱 ID/可预测会话标识",
    "xss_d": "DOM 型 XSS",
    "xss_r": "反射型 XSS",
    "xss_s": "存储型 XSS",
    "sqli_labs_less24": "二次注入",
}
EXPECTED = {
    "api": {"api_info_disclosure", "information_disclosure"},
    "authbypass": {"auth_bypass"},
    "bac": {"idor"},
    "brute": {"brute_force"},
    "captcha": {"captcha_bypass"},
    "cryptography": {"weak_crypto"},
    "csp": {"csp"},
    "csrf": {"csrf"},
    "exec": {"command_injection"},
    "fi": {"path_traversal", "lfi"},
    "javascript": {"client_side_validation"},
    "open_redirect": {"open_redirect"},
    "sqli_blind": {"sql_injection", "blind_sql_injection"},
    "sqli": {"sql_injection"},
    "upload": {"file_upload"},
    "weak_id": {"weak_id", "predictable_id", "insecure_session"},
    "xss_d": {"xss"}, "xss_r": {"xss"}, "xss_s": {"xss"},
    "sqli_labs_less24": {"second_order_injection"},
}

ACCEPTED_SEMANTIC_058 = {"sql_injection", "auth_bypass", "second_order_injection"}

# API levels have different intended root causes in the gold material.
SAMPLE_EXPECTED = {
    ("api", "low"): {"api_info_disclosure", "information_disclosure"},
    ("api", "medium"): {"auth_bypass", "business_logic"},
    ("api", "high"): {"command_injection"},
}

def parse_mapping() -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for line in MAPPING.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*(\d{3})\s*\|.*?\|\s*([A-Za-z0-9_]+)_(low|medium|high)\s*\|", line)
        if m:
            result[m.group(1)] = (m.group(2), m.group(3))
    result["058"] = ("sqli_labs_less24", "low")
    return result

def load_findings(run_root: Path) -> dict[str, list[dict]]:
    findings: dict[str, list[dict]] = {}
    for sample_dir in sorted(run_root.iterdir()):
        if not sample_dir.is_dir() or not re.fullmatch(r"\d{3}", sample_dir.name):
            continue
        report = sample_dir / "report.json"
        if not report.is_file():
            findings[sample_dir.name] = []
            continue
        payload = json.loads(report.read_text(encoding="utf-8"))
        findings[sample_dir.name] = payload.get("findings") or []
    return findings

def expected_hit(category: str, sample: str, found_types: set[str]) -> tuple[bool, str]:
    if category == "sqli_labs_less24":
        if "second_order_injection" in found_types:
            return True, "正确"
        if found_types & ACCEPTED_SEMANTIC_058:
            return False, "部分命中（未标为二次注入）"
        return False, "漏报"
    level = parse_mapping().get(sample, (category, ""))[1]
    expected = SAMPLE_EXPECTED.get((category, level), EXPECTED[category])
    if found_types & expected:
        return True, "正确"
    return False, "漏报" if not found_types else "误报/漏报"

def cause(category: str, found: list[dict], matched: bool) -> str:
    if matched:
        return "命中对应类别；仍需动态复核"
    actual = ", ".join(sorted({str(x.get("vulnerability_type", "unknown")) for x in found})) or "无 finding"
    if not found:
        return {
            "xss_d": "客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查",
            "xss_r": "输出上下文与反射路径未被规则覆盖，LLM 上下文截断或注意力不足",
            "xss_s": "上下文/跨请求数据流未闭合，Prompt 未要求区分存储型输出位置",
            "csrf": "缺少状态改变请求与 CSRF token/Origin 校验的专项候选规则",
            "brute": "业务速率限制/失败计数属于行为语义，静态 source→sink 规则覆盖不足",
            "weak_crypto": "算法/模式语义未纳入确定性候选，LLM 易把影响误标为认证绕过",
            "open_redirect": "重定向响应与可控 URL 的端点关系未被规则闭合",
            "weak_id": "可预测 ID 需要跨请求比较，单文件上下文不足",
            "javascript": "客户端校验绕过需要浏览器执行语义，静态模型未形成专类候选",
            "api": "API 字段暴露/权限语义不等同于通用 source→sink，缺少 API 专项提示",
            "csp": "响应头/策略语义未进入当前 PHP 规则覆盖",
            "captcha": "验证码流程状态机未被识别，缺少步骤绕过检查",
            "bac": "对象授权关系需要业务主体/对象对比，LLM 未获得足够业务上下文",
            "fi": "include/路径规范化链未被当前规则稳定识别",
            "sqli_blind": "盲注时间/布尔差异依赖运行时语义，静态候选缺少盲注专类证据",
        }.get(category, "类别专项规则或模型上下文不足")
    return f"类型不匹配（实际：{actual}）；通用模式偏置/Prompt 未强制按金标根因分类"

def build_report(run_root: Path) -> tuple[str, dict]:
    mapping = parse_mapping()
    findings = load_findings(run_root)
    rows = []
    statuses = {}
    for sample, (category, level) in sorted(mapping.items()):
        fs = findings.get(sample, [])
        types = {str(f.get("vulnerability_type", "")) for f in fs}
        hit, status = expected_hit(category, sample, types)
        statuses[sample] = {"category": category, "level": level, "found_types": sorted(types),
                            "hit": hit, "status": status}
        rows.append((sample, category, level, fs, types, hit, status))

    sample_reported = sum(bool(fs) for _, _, _, fs, *_ in rows)
    sample_hit = sum(hit for *_, hit, _ in rows)
    strict_fp = sum(bool(fs) and not hit for _, _, _, fs, _, hit, _ in rows)
    strict_fn = sum(not hit for *_, hit, _ in rows)
    poc_counts = Counter()
    poc_total = 0
    poc_bad = []
    for sample, fs in findings.items():
        for f in fs:
            poc_total += 1
            validation = ((f.get("poc") or {}).get("safety") or {}).get("contract_validation") or {}
            status = validation.get("status", "missing")
            poc_counts[status] += 1
            if status != "static_consistent":
                poc_bad.append((sample, f.get("id", ""), status, validation.get("errors", [])))

    lines = [
        f"# 集成数据集 ver4 评估（{run_root.name}）", "",
        "本报告将 finding 与 20 个金标类别逐样本比较；finding 仍是 candidate，POC 只做静态契约检查，未执行网络请求。", "",
        "## 指标", "",
        "| 口径 | TP | FP | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|",
    ]
    def metric(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        f = 2*p*r/(p+r) if p+r else 0
        return f"{p:.2%}", f"{r:.2%}", f"{f:.2%}"
    p, r, f = metric(sample_hit, strict_fp, strict_fn)
    lines.append(f"| 样本类别严格匹配 | {sample_hit} | {strict_fp} | {strict_fn} | {p} | {r} | {f} |")
    bp, br, bf = metric(sample_reported, 0, 58-sample_reported)
    lines.append(f"| 仅判断样本是否有 finding | {sample_reported} | 0 | {58-sample_reported} | {bp} | {br} | {bf} |")
    lines += ["", "数据集 58 个样本全部是正例，不能估计 TN、特异度或常规二分类 accuracy。", "",
              "## 20 类别 low/medium/high 正确情况", "",
              "| 类别 | low | medium | high |", "|---|---|---|---|"]
    category_order = list(CATEGORY_LABELS)
    for category in category_order:
        cells = []
        for level in ("low", "medium", "high"):
            target = next((x for x in rows if x[1] == category and x[2] == level), None)
            if not target:
                cells.append("-"); continue
            sample, _, _, fs, types, hit, status = target
            if hit: cells.append(f"正确（{sample}）")
            elif status.startswith("部分"): cells.append(f"部分（{sample}: {','.join(sorted(types)) or '无'}）")
            elif fs: cells.append(f"误报/漏报（{sample}: {','.join(sorted(types))}）")
            else: cells.append(f"漏报（{sample}）")
        lines.append(f"| {CATEGORY_LABELS[category]} | " + " | ".join(cells) + " |")

    lines += ["", "## POC 静态契约结果", "", f"共检查 {poc_total} 个 POC：" + ", ".join(f"{k}={v}" for k,v in sorted(poc_counts.items())) + "。", "",
              "静态一致不等于漏洞已验证：未执行目标服务、未重放请求、未观察响应差异。"]
    if poc_bad:
        lines += ["", "| 样本 | finding | 状态 | 原因 |", "|---|---|---|---|"]
        for sample, fid, status, errors in poc_bad:
            lines.append(f"| {sample} | {fid} | {status} | {'；'.join(errors)} |")
    lines += ["", "## 误报/漏报归因", "", "| 样本 | 金标类别 | finding 类型 | 结论 | 核心原因 |", "|---|---|---|---|---|"]
    for sample, category, level, fs, types, hit, status in rows:
        if not hit:
            lines.append(f"| {sample} | {CATEGORY_LABELS[category]}（{level}） | {', '.join(sorted(types)) or '无'} | {status} | {cause(category, fs, hit)} |")

    lines += ["", "## 误报过滤规则", "",
              "1. 只有存在可定位 source→sink 链、同一请求入口和真实代码行号时，才保留通用注入 finding。",
              "2. session、Cookie、Referer、Authorization 等来源必须与 POC 的实际请求载体一致；生成 param/query 代替非参数来源时过滤。",
              "3. 认证绕过只能在存在认证决策点且攻击者输入可控时成立；弱算法是根因时归类为 weak_crypto，不把影响冒充根因。",
              "4. SQL 注入必须同时满足可控表达式、SQL 拼接/执行 sink 和可达端点；只有字符串/数据库调用没有污点链时过滤。",
              "5. 业务语义类别（BAC、暴力破解、验证码、弱 ID、CSRF）需要状态/主体/对象对比证据，通用模式命中不得升级为该类别。",
              "6. POC 的方法、端点、参数或请求头必须与 finding 的 source 对齐；契约失败的 finding 进入人工复核。",
              "", "## 漏报补强核查清单", "",
              "| 类别 | 补强检查 | 所需证据 |",
              "|---|---|---|"]
    checklist = {
        "api": "逐字段检查响应/序列化输出与权限边界，区分信息泄露和批量赋值",
        "authbypass": "追踪认证条件、默认值、状态变量和密码/令牌比较",
        "bac": "构造不同用户/对象 ID 对比，确认服务端授权而非仅有 SQL 查询",
        "brute": "检查失败计数、速率限制、锁定、验证码与 IP/账户维度",
        "captcha": "串联 step 参数、session/client 状态和最终改密请求",
        "cryptography": "枚举算法、模式、密钥来源与令牌生成/验证路径",
        "csp": "检查响应头、nonce/hash、脚本来源和策略是否实际生效",
        "csrf": "枚举所有状态改变请求并检查 token、Origin/Referer、SameSite",
        "exec": "确认输入进入命令参数/命令字符串，区分环境变量和 argv",
        "fi": "追踪 include/file_get_contents/路径规范化和目录限制",
        "javascript": "审计客户端校验与服务端重复校验，记录可直接构造的请求",
        "open_redirect": "确认 Location/redirect sink 使用可控 URL 且无 allowlist",
        "sqli_blind": "保留布尔/时间差异证据，区分盲注与普通错误回显",
        "sqli": "验证输入到 SQL 拼接/执行的完整链和参数名",
        "upload": "检查扩展名、MIME、内容、存储路径及可执行权限",
        "weak_id": "跨请求比较 ID/会话标识可预测性与授权检查",
        "xss_d": "审计 DOM source→sink、URL fragment 和客户端执行路径",
        "xss_r": "追踪同请求参数到响应输出的反射位置与编码",
        "xss_s": "跨请求追踪存储点到 HTML/属性/JS sink 的编码上下文",
        "sqli_labs_less24": "串联注册写入→登录会话→改密读取，确认二次注入与数据库字符集",
    }
    for category in category_order:
        lines.append(f"| {CATEGORY_LABELS[category]} | {checklist[category]} | 对应源码、跨文件调用/请求与可观察结果 |")

    lines += ["", "## 初始版本缺陷与 ver2 改动", "",
              "初始版本关闭确定性规则候选，主要依赖一次 LLM DeepFinder，导致上下文截断、类别覆盖不均和类型根因/影响混淆；POC 只写不跑且没有 source/请求契约检查。",
              "ver3 在 ver2 基础上加入 API、验证码、CSP、弱 ID、客户端校验、CSRF、弱加密等语义候选，修正 PHP 常量覆盖造成的旧污点残留，并要求筛选器保护有明确源码证据的语义候选；同时保留 POC 静态契约校验。改进提升了类别覆盖，但未覆盖全部路径穿越、DOM/存储型 XSS 和二次注入链。",
              "ver3 的另一轮筛选器反证试验把模型解释文本直接用作丢弃规则，实测严格匹配从 41/58 降至 33/58，表明自然语言反证正则过于脆弱；最终结果采用不含该规则的 ver3_revision 批次。POC 仍未在隔离目标上动态执行。"]
    data = {"run": str(run_root), "metrics": {"sample_reported": sample_reported, "sample_category_tp": sample_hit,
            "sample_category_fp": strict_fp, "sample_category_fn": strict_fn, "poc": dict(poc_counts)},
            "samples": statuses}
    return "\n".join(lines) + "\n", data

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: evaluate_baofeng.py RUN_ROOT", file=sys.stderr); return 2
    run_root = Path(sys.argv[1]).resolve()
    report, data = build_report(run_root)
    (run_root / "evaluation_vs_gold_ver2.md").write_text(report, encoding="utf-8")
    (run_root / "evaluation_vs_gold_ver2.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(data["metrics"], ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
