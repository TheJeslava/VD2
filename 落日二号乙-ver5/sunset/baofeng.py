"""暴风星云裂 20 类金标注册表。

The dataset has three severity variants for each DVWA family and one
multi-file SQLi-Labs sample.  Keeping the mapping here makes URL manifests,
AWVS target seeds, and ZIP target exports use the same vocabulary.  These
fields describe a fixture and probe profile only; they must never create a
finding without evidence from an imported scanner report or a live response.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class BaofengCategory:
    key: str
    label: str
    vuln_type: str
    cwe: str
    severity: str
    samples: tuple[str, ...]
    method: str = "GET"
    channel: str = "query"
    param_name: str = "input"
    param_value: str = "test"


_FAMILIES = (
    ("api", "API 信息泄露", "api_info_disclosure", "CWE-200", "high", "GET", "query", "input", "1"),
    ("authbypass", "认证绕过", "auth_bypass", "CWE-287", "critical", "GET", "query", "user", "guest"),
    ("bac", "越权 / IDOR", "idor", "CWE-639", "high", "GET", "query", "user_id", "1"),
    ("brute", "暴力破解防护缺失", "brute_force", "CWE-307", "high", "GET", "query", "username", "admin"),
    ("captcha", "验证码绕过", "captcha_bypass", "CWE-804", "high", "POST", "form", "g-recaptcha-response", ""),
    ("cryptography", "弱加密", "weak_crypto", "CWE-327", "medium", "GET", "query", "token", "test"),
    ("csp", "CSP 配置缺陷", "csp", "CWE-693", "medium", "GET", "query", "include", "<script>alert(1)</script>"),
    ("csrf", "跨站请求伪造", "csrf", "CWE-352", "medium", "POST", "form", "Change", "Change"),
    ("exec", "命令注入", "command_injection", "CWE-78", "critical", "POST", "form", "ip", "127.0.0.1"),
    ("fi", "路径穿越 / LFI", "path_traversal", "CWE-22", "high", "GET", "query", "page", "include.php"),
    ("javascript", "客户端 JavaScript 校验绕过", "client_side_validation", "CWE-602", "high", "GET", "query", "default", "English"),
    ("open_redirect", "开放重定向", "open_redirect", "CWE-601", "medium", "GET", "query", "redirect", "info.php"),
    ("sqli_blind", "盲 SQL 注入", "blind_sql_injection", "CWE-89", "critical", "GET", "cookie", "id", "1"),
    ("sqli", "SQL 注入", "sql_injection", "CWE-89", "critical", "GET", "query", "id", "1"),
    ("upload", "不安全文件上传", "file_upload", "CWE-434", "critical", "POST", "multipart", "uploaded", "sunset.txt"),
    ("weak_id", "弱 ID / 可预测会话标识", "weak_id", "CWE-330", "high", "POST", "cookie", "dvwaSession", "1"),
    ("xss_d", "DOM 型 XSS", "xss", "CWE-79", "high", "GET", "query", "default", "English"),
    ("xss_r", "反射型 XSS", "xss", "CWE-79", "high", "GET", "query", "name", "SafeText"),
    ("xss_s", "存储型 XSS", "xss", "CWE-79", "high", "POST", "form", "txtName", "SafeText"),
    ("sqli_labs_less24", "二次注入", "second_order_injection", "CWE-89", "critical", "POST", "form", "username", "sunset_user"),
)


def _samples(start: int) -> tuple[str, ...]:
    return tuple(f"{value:03d}" for value in range(start, start + 3))


BAOFENG_CATEGORIES: tuple[BaofengCategory, ...] = tuple(
    BaofengCategory(
        key=key,
        label=label,
        vuln_type=vuln_type,
        cwe=cwe,
        severity=severity,
        samples=_samples(index) if key != "sqli_labs_less24" else ("058",),
        method=method,
        channel=channel,
        param_name=param_name,
        param_value=param_value,
    )
    for index, (key, label, vuln_type, cwe, severity, method, channel, param_name, param_value)
    in zip(range(1, 59, 3), _FAMILIES[:-1])
) + (
    BaofengCategory(
        key=_FAMILIES[-1][0], label=_FAMILIES[-1][1], vuln_type=_FAMILIES[-1][2],
        cwe=_FAMILIES[-1][3], severity=_FAMILIES[-1][4], samples=("058",),
        method=_FAMILIES[-1][5], channel=_FAMILIES[-1][6],
        param_name=_FAMILIES[-1][7], param_value=_FAMILIES[-1][8],
    ),
)

BY_KEY = {item.key: item for item in BAOFENG_CATEGORIES}
BY_SAMPLE = {sample: item for item in BAOFENG_CATEGORIES for sample in item.samples}


def category_for_sample(sample: str) -> BaofengCategory | None:
    text = str(sample).strip()
    match = __import__("re").match(r"^(\d{3})(?:[_-].*)?$", text)
    key = match.group(1) if match else text.zfill(3)
    return BY_SAMPLE.get(key)


def manifest_target(base_url: str, category: BaofengCategory, sample: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + f"/{sample}.php"
    return {
        "name": sample,
        "dataset_category": category.key,
        "category": category.vuln_type,
        "label": category.label,
        "url": url,
        "method": category.method,
        "channel": category.channel,
        "param_name": category.param_name,
        "param_value": category.param_value,
        "cwe": category.cwe.replace("CWE-", ""),
        "severity": category.severity,
        "metadata_only": True,
        "source_file": f"{sample}.php",
    }


def build_manifest(base_url: str = "http://127.0.0.1:18081") -> dict[str, Any]:
    targets = [manifest_target(base_url, category, sample)
               for category in BAOFENG_CATEGORIES for sample in category.samples]
    return {
        "format": "awvs-compatible-manifest-v2",
        "generated_by": "落日二号乙-ver5",
        "base_url": base_url,
        "count": len(targets),
        "category_count": len(BAOFENG_CATEGORIES),
        "categories": [
            {key: value for key, value in asdict(category).items() if key != "samples"}
            | {"samples": list(category.samples)}
            for category in BAOFENG_CATEGORIES
        ],
        "targets": targets,
        "limitations": [
            "Category, sample, CWE, and parameter fields are fixture metadata only; they never create findings.",
            "Only an observed HTTP response differential or an explicitly imported external report creates a URL finding.",
            "Second-order injection requires a cross-request dynamic workflow; a single request is insufficient.",
        ],
    }


def coverage_summary() -> dict[str, Any]:
    return {
        "expected_categories": [item.key for item in BAOFENG_CATEGORIES],
        "expected_vulnerability_types": sorted({item.vuln_type for item in BAOFENG_CATEGORIES}),
        "category_count": len(BAOFENG_CATEGORIES),
        "sample_count": len(BY_SAMPLE),
        "second_order_dynamic": False,
    }

