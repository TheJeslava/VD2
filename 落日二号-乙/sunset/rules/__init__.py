"""候选发现引擎（CandidateScreener 的确定性内核）。"""

from __future__ import annotations

import re
from collections import Counter

from ..models import Candidate, Endpoint, Project, SourceFile
from ..taxonomy import meta
from .generic import analyze_generic_file, scan_secrets_and_config
from .java import analyze_java_file
from .logic import analyze_logic

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get((value or "").lower(), 0)


def scan_project(
    project: Project,
    contents: dict[str, str],
    *,
    min_severity: str = "high",
    min_confidence: float = 0.6,
    include_config: bool = True,
) -> tuple[list[Candidate], dict]:
    endpoints: list[Endpoint] = list(project.endpoints)
    candidates: list[Candidate] = []
    per_language: Counter = Counter()
    errors: list[str] = []
    project_properties: dict[str, str] = {}
    for path, text in contents.items():
        if not path.lower().endswith(".properties"):
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            project_properties[key.strip()] = value.strip()

    for file in project.files:
        if not file.is_text:
            continue
        text = contents.get(file.rel_path, "")
        if not text:
            continue
        language = file.language
        try:
            if language in {"java", "kotlin"}:
                found = analyze_java_file(file.rel_path, text, endpoints, project_properties)
                found.extend(analyze_logic(file.rel_path, text, endpoints))
            else:
                found = analyze_generic_file(file.rel_path, text, language, endpoints)
            candidates.extend(found)
            per_language[language] += len(found)
        except Exception as exc:  # noqa: BLE001 - 单文件失败不阻塞
            errors.append(f"{file.rel_path}: {exc}")
        try:
            candidates.extend(scan_secrets_and_config(file.rel_path, text, language))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{file.rel_path}: secret/config: {exc}")

    if not include_config:
        candidates = [item for item in candidates if item.rule_id not in {
            "secret-scanner", "python-tls-verify-disabled", "go-tls-insecure", "cors-wildcard",
            "csrf-disabled", "spring-permit-all", "debug-true",
        }]

    floor = severity_rank(min_severity)
    filtered: list[Candidate] = []
    # 被门禁丢弃的候选必须留痕：否则报告无法区分"没检出"与"被策略抑制"。
    # 这里只记录，不改变 finding 的产出（策略仍由 --min-severity / --min-confidence 决定）。
    suppressed: list[dict] = []
    suppressed_seen: set[tuple[str, str, int]] = set()
    for item in candidates:
        reasons: list[str] = []
        if severity_rank(item.severity) < floor:
            reasons.append("severity_below_floor")
        if item.confidence < min_confidence:
            reasons.append("confidence_below_min")
        if reasons:
            key = (item.vuln_type, item.file, item.line_end)
            if key not in suppressed_seen:
                suppressed_seen.add(key)
                suppressed.append({
                    "vulnerability_type": item.vuln_type,
                    "cwe": meta(item.vuln_type).cwe,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "rule_id": item.rule_id,
                    "file": item.file,
                    "line": item.line_end,
                    "endpoint": item.endpoint,
                    "reasons": reasons,
                })
            continue
        filtered.append(item)

    # 去重：同类型同文件同行，保留置信度更高者
    best: dict[tuple[str, str, int], Candidate] = {}
    for item in filtered:
        key = (item.vuln_type, item.file, item.line_end)
        current = best.get(key)
        if current is None or item.confidence > current.confidence:
            best[key] = item
    result = sorted(
        best.values(),
        key=lambda item: (-severity_rank(item.severity), -item.confidence, item.file, item.line_end),
    )
    stats = {
        "raw_candidates": len(candidates),
        "kept_candidates": len(result),
        "suppressed_count": len(suppressed),
        "suppressed_by_type": dict(Counter(item["vulnerability_type"] for item in suppressed)),
        "suppressed_by_reason": dict(Counter(reason for item in suppressed for reason in item["reasons"])),
        "suppressed": suppressed[:200],
        "per_language": dict(per_language),
        "errors": errors[:20],
        "min_severity": min_severity,
        "min_confidence": min_confidence,
        "types": dict(Counter(item.vuln_type for item in result)),
    }
    return result, stats


def candidate_public_dossier(candidate: Candidate, max_snippet: int = 1600) -> dict:
    """给 LLM 的候选摘要：只含确定性证据，不含文件系统访问。"""
    item = meta(candidate.vuln_type)
    return {
        "candidate_id": candidate.candidate_id,
        "vulnerability_type": candidate.vuln_type,
        "label": item.label_zh,
        "cwe": item.cwe,
        "severity": candidate.severity,
        "confidence": candidate.confidence,
        "file_path": candidate.file,
        "line_start": candidate.line_start,
        "line_end": candidate.line_end,
        "endpoint": candidate.endpoint,
        "http_method": candidate.http_method,
        "source_kind": candidate.source_kind,
        "source_name": candidate.source_name,
        "sink": candidate.sink,
        "tainted_expression": candidate.tainted_expression,
        "code_snippet": candidate.code_snippet[:max_snippet],
        "chain": [step.to_dict() for step in candidate.chain],
        "rule_id": candidate.rule_id,
    }


def looks_like_duplicate(candidate: Candidate, existing: list[Candidate]) -> bool:
    for item in existing:
        if item.vuln_type != candidate.vuln_type:
            continue
        if item.file != candidate.file:
            continue
        if abs(item.line_end - candidate.line_end) <= 3:
            return True
    return False


def path_matches_endpoint(file_path: str, endpoint: str) -> bool:
    """用于 AWVS 结果与源码 finding 的粗关联。"""
    if not endpoint:
        return False
    tail = endpoint.rstrip("/").split("/")[-1]
    return bool(tail) and re.search(rf"(?i)(^|[/_.-]){re.escape(tail)}($|[/_.-])", file_path)
