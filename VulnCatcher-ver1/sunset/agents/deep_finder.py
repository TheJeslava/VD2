"""LLM 深挖（DeepFinder）：模仿 AutoCVE Finding 阶段的源码发现环节。

AutoCVE 的 Finding agent 用 Read / Grep / Glob / Bash 自己翻代码，最后调用
FinalizeFinding 提交。VulnCatcher的契约是「零工具」，所以这里把流程倒过来：

1. 仅按预算选择文件、切窗口、编行号，构造 CODE PACK；
2. 一次 system + user 调用（没有 tools / tool_choice / function calling）；
3. 模型直接产出 findings JSON；服务端校验 file_path、clamp 行号、用真实源码
   回填 code_snippet，拒绝缺链/缺 source/缺 sink 的结论；
4. 规范化成 Candidate（origin=llm_finding），对同一批模型输出去重，统计写入
   manifest 供报告审计。

因此「LLM-finding」不是一次新的工具编排，而是把 AutoCVE Finding 的判断标准
（CVE 级、零误报、完整链、可复现 POC）压缩成一次无工具调用。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..ingest import AUDITABLE_LANGUAGES
from ..models import Candidate, ChainStep
from ..rules import severity_rank
from ..security.guard import sanitize_model_text
from ..taxonomy import canonical, meta
from .base import AgentContext, AgentResult, BaseAgent

# CODE PACK 选择与渲染参数
_MIN_FILE_CHARS = 900
_MAX_FILE_CHARS = 7000
_MAX_LINES_PER_FILE = 240
_EXTRA_LANGUAGES = {"xml"}  # MyBatis Mapper 等 XML 里的 ${} 也值得看

_SOURCE_RE = re.compile(
    r"(?:getParameter|getHeader|getCookies|getQueryString|getInputStream|getPathInfo|"
    r"getParameterMap|getParameterNames|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|"
    r"request\.(?:args|form|values|json|files|headers|cookies)|"
    r"req\.(?:query|body|params|headers|cookies)|Request\.(?:QueryString|Form|Headers|Cookies)|"
    r"r\.(?:URL|FormValue|Header))"
)
_SINK_RE = re.compile(
    r"(?:Runtime\.getRuntime|ProcessBuilder|\.exec\s*\(|\bsystem\s*\(|shell_exec|subprocess|"
    r"child_process|executeQuery|executeUpdate|queryForList|queryForObject|createStatement|"
    r"mysqli?_query|PDO::|prepareStatement|Statement\b|"
    r"FileInputStream|FileOutputStream|Files\.(?:read|write|copy)|new\s+File\s*\(|"
    r"readObject|ObjectInputStream|unserialize|pickle\.loads|yaml\.load|"
    r"DocumentBuilderFactory|SAXParserFactory|SAXReader|XMLInputFactory|"
    r"sendRedirect|setHeader\s*\(|getWriter\(\)|innerHTML|document\.write|"
    r"eval\s*\(|Class\.forName|ScriptEngine|render\s*\(|Template|"
    r"getRealPath|ServletContext|@RequestParam|@PathVariable)"
)
_AUTH_RE = re.compile(
    r"(?i)(?:auth|login|logout|session|jwt|token|oauth|admin|permission|role|"
    r"password|passwd|credential|upload|redirect|deserialize|serialize)"
)
_ENTRY_RE = re.compile(
    r"(?i)(?:controller|servlet|action|handler|resource|endpoint|route|api|filter|"
    r"interceptor|aspect|mapper|repository|service)"
)

SEVERITIES = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SOURCE_KINDS = {"query", "body", "header", "cookie", "path", "upload", "session", "config", "repository", "unknown"}
_KIND_ALIASES = {
    "getparameter": "query", "parameter": "query", "params": "query", "querystring": "query",
    "getheader": "header", "headers": "header", "getcookies": "cookie", "cookies": "cookie",
    "form": "body", "post": "body", "get": "query", "pathinfo": "path", "path": "path",
    "multipart": "upload", "file": "upload", "attribute": "session", "session": "session",
}
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY"}


def _interesting_lines(lines: list[str], limit: int = 80) -> list[int]:
    hits: list[int] = []
    for number, line in enumerate(lines, 1):
        if _SINK_RE.search(line) or _SOURCE_RE.search(line):
            hits.append(number)
            if len(hits) >= limit:
                break
    return hits


def _select_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """为超长文件选择少量窗口：优先 sink/source 附近，总量不超过 _MAX_LINES_PER_FILE。"""
    total = len(lines)
    hits = _interesting_lines(lines)
    if not hits:
        return [(1, min(total, 140))]
    ranges = [[max(1, center - 35), min(total, center + 35)] for center in hits[:6]]
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    result: list[tuple[int, int]] = []
    used = 0
    for start, end in merged:
        if used >= _MAX_LINES_PER_FILE:
            break
        end = min(end, start + (_MAX_LINES_PER_FILE - used) - 1)
        result.append((start, end))
        used += end - start + 1
    return result


def _render_file(lines: list[str], cap: int) -> tuple[str, list[tuple[int, int]], bool]:
    """渲染带行号的代码窗口；返回 (文本, 展示区间, 是否截断)。"""
    ranges = _select_ranges(lines)
    rows: list[str] = []
    for start, end in ranges:
        rows.append(f"... lines {start}-{end} of {len(lines)} ...")
        for number in range(start, end + 1):
            rows.append(f"{number:04d}| {lines[number - 1]}")
    text = "\n".join(rows)
    if len(text) <= cap:
        return text, ranges, False
    kept: list[str] = []
    used = 0
    for row in rows:
        if used + len(row) + 1 > cap:
            kept.append("... (达到本次预算，后续行省略)")
            return "\n".join(kept), ranges, True
        kept.append(row)
        used += len(row) + 1
    return "\n".join(kept), ranges, True


class DeepFinderAgent(BaseAgent):
    name = "deep_finder"
    codename = "LLM 深挖"
    prompt_name = "deep_finder.md"

    # ------------------------------------------------------------------
    # CODE PACK
    # ------------------------------------------------------------------

    def _build_code_pack(self, ctx: AgentContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        budget = 36000
        max_files = 12
        try:
            budget = int(getattr(ctx.settings, "llm_finding_budget", budget) or budget)
        except (TypeError, ValueError):
            pass
        try:
            max_files = int(getattr(ctx.settings, "llm_finding_max_files", max_files) or max_files)
        except (TypeError, ValueError):
            pass
        budget = max(4000, min(44000, budget))
        max_files = max(1, min(40, max_files))

        endpoints_by_file: dict[str, list[Any]] = defaultdict(list)
        for endpoint in ctx.project.endpoints:
            endpoints_by_file[endpoint.file].append(endpoint)

        ranked: list[tuple[int, Any, str]] = []
        for item in ctx.project.files:
            if not item.is_text or item.lines < 3:
                continue
            if item.rel_path in ctx.quarantined:
                continue
            if item.size > 400_000:
                continue
            text = ctx.contents.get(item.rel_path) or ""
            if len(text.strip()) < 80:
                continue
            if item.language not in AUDITABLE_LANGUAGES:
                if item.language not in _EXTRA_LANGUAGES or "${" not in text:
                    continue
            score = self._score(item.rel_path, text, item.rel_path in endpoints_by_file)
            ranked.append((score, item, text))

        ranked.sort(key=lambda row: (-row[0], row[1].lines, row[1].rel_path))
        chosen = ranked[:max_files]
        if not chosen:
            return [], {"files": 0, "chars": 0, "truncated": 0, "paths": []}

        per_file = max(_MIN_FILE_CHARS, min(_MAX_FILE_CHARS, budget // len(chosen)))
        pack: list[dict[str, Any]] = []
        chars = 0
        truncated = 0
        for score, item, text in chosen:
            lines = text.splitlines()
            rendered, ranges, cut = _render_file(lines, per_file)
            if cut:
                truncated += 1
            chars += len(rendered)
            pack.append({
                "path": item.rel_path,
                "language": item.language,
                "total_lines": len(lines),
                "priority_score": score,
                "shown_ranges": [f"{start}-{end}" for start, end in ranges],
                "truncated": cut,
                "code": rendered,
            })
        stats = {
            "files": len(pack),
            "chars": chars,
            "truncated": truncated,
            "paths": [entry["path"] for entry in pack],
        }
        return pack, stats

    @staticmethod
    def _score(rel_path: str, text: str, has_endpoint: bool) -> int:
        name = rel_path.lower()
        score = 0
        if has_endpoint:
            score += 8
        if _ENTRY_RE.search(name):
            score += 4
        if _AUTH_RE.search(name):
            score += 3
        if _AUTH_RE.search(text):
            score += 2
        score += min(4, len(_SINK_RE.findall(text)))
        score += min(2, len(_SOURCE_RE.findall(text)))
        if len(text) > 120_000:
            score -= 2
        return score

    # ------------------------------------------------------------------
    # 主流程
    # ------------------------------------------------------------------

    def run(self, ctx: AgentContext) -> AgentResult:
        started = time.time()
        result = AgentResult(name=self.name, codename=self.codename)
        manifest: dict[str, Any] = {
            "enabled": False,
            "mode": ctx.settings.llm_finding,
            "tool_calls": 0,
            "files": 0,
            "chars": 0,
            "truncated_files": 0,
            "findings": 0,
            "duplicates": 0,
            "rejected": [],
            "suppressed": [],
            "summary": "",
            "gaps": [],
            "note": (
                "单次 LLM 调用；请求体不含 tools/tool_choice/function calling；"
                "file_path 与行号由服务端校验，code_snippet 由真实源码回填。"
            ),
        }
        ctx.project.manifest["llm_finding"] = manifest

        def finish(reason: str = "") -> AgentResult:
            if reason:
                manifest["reason"] = reason
            result.duration_sec = round(time.time() - started, 2)
            return result

        if (ctx.project.manifest.get("input_mode") or ctx.project.input_mode) == "url":
            return finish("URL 模式没有源码，跳过 LLM 深挖")
        if str(getattr(ctx.settings, "llm_finding", "auto")).lower() == "off":
            return finish("--llm-finding off")
        if not ctx.llm or not ctx.llm.available:
            return finish("LLM 未启用")

        pack, stats = self._build_code_pack(ctx)
        if not pack:
            return finish("没有可送入模型的源码文件")

        sent = set(stats["paths"])
        endpoints = [
            {"path": item.path, "method": item.method, "file": item.file,
             "line": item.line, "handler": item.handler}
            for item in ctx.project.endpoints
            if item.file in sent
        ][:120]
        surface_notes = ctx.project.manifest.get("surface_notes") or {}
        payload = {
            "task": "source_to_sink_discovery",
            "contract": {
                "tool_access": "none",
                "context": "所有源码都在 code_pack；不要请求读取其它文件",
                "output": "严格 JSON：findings / summary / coverage",
            },
            "project": {
                "languages": ctx.project.languages,
                "frameworks": ctx.project.frameworks,
                "file_count": len(ctx.project.files),
                "endpoint_count": len(ctx.project.endpoints),
            },
            "policy": {
                "min_severity": ctx.settings.min_severity,
                "min_confidence": ctx.settings.min_confidence,
                "max_findings": ctx.settings.max_llm_findings,
            },
            "surface_notes": surface_notes,
            "endpoints": endpoints,
            "code_pack": pack,
        }
        body = json.dumps(payload, ensure_ascii=False, default=str)
        # LlmClient 会把 user 截到 48000 字符；这里先按整包 44000 收敛，
        # 超出预算时从低优先级文件开始丢弃，避免模型收到半截 JSON。
        while len(body) > 44000 and len(pack) > 1:
            pack.pop()
            body = json.dumps(payload, ensure_ascii=False, default=str)
        kept_paths = {entry["path"] for entry in pack}
        if len(kept_paths) != len(sent):
            payload["endpoints"] = [entry for entry in endpoints if entry["file"] in kept_paths]
            body = json.dumps(payload, ensure_ascii=False, default=str)
        stats = {
            "files": len(pack),
            "chars": sum(len(entry["code"]) for entry in pack),
            "truncated": sum(1 for entry in pack if entry["truncated"]),
            "paths": sorted(kept_paths),
        }
        manifest.update({
            "files": stats["files"],
            "chars": stats["chars"],
            "truncated_files": stats["truncated"],
        })
        data = self._llm_json(
            ctx,
            payload,
            label="discovery",
            max_chars=min(46000, len(body) + 3000),
        )
        if data is None:
            return finish("LLM 调用失败，未新增候选")

        result.used_llm = True
        raw_findings = data.get("findings") if isinstance(data.get("findings"), list) else []
        added: list[Candidate] = []
        rejected: list[str] = []
        suppressed: list[dict[str, Any]] = []
        floor = severity_rank(ctx.settings.min_severity)
        duplicates = 0

        for item in raw_findings[: ctx.settings.max_llm_findings]:
            candidate, reason = self._to_candidate(ctx, item)
            if candidate is None:
                rejected.append(reason)
                continue
            if severity_rank(candidate.severity) < floor:
                suppressed.append({"vulnerability_type": candidate.vuln_type,
                                   "file": candidate.file, "line": candidate.line_end,
                                   "reason": "severity_below_floor"})
                continue
            if candidate.confidence < ctx.settings.min_confidence:
                suppressed.append({"vulnerability_type": candidate.vuln_type,
                                   "file": candidate.file, "line": candidate.line_end,
                                   "reason": "confidence_below_min"})
                continue
            duplicate = self._find_duplicate(added, candidate)
            if duplicate is not None:
                duplicates += 1
                note = f"LLM 深挖重复命中（{candidate.vuln_type}，conf={candidate.confidence}）；" \
                       f"保留首条候选，补充：{candidate.description[:160]}"
                if note not in duplicate.notes:
                    duplicate.notes.append(note)
                continue
            added.append(candidate)

        added.sort(key=lambda item: (-severity_rank(item.severity), -item.confidence, item.file, item.line_end))
        ctx.candidates = list(ctx.candidates) + added
        summary = sanitize_model_text(data.get("summary"), 2000) if data.get("summary") else ""
        coverage = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
        gaps = coverage.get("gaps") if isinstance(coverage.get("gaps"), list) else []
        audited = coverage.get("audited_files") if isinstance(coverage.get("audited_files"), list) else []

        manifest.update({
            "enabled": True,
            "findings": len(added),
            "duplicates": duplicates,
            "rejected": rejected[:20],
            "rejected_count": len(rejected),
            "suppressed": suppressed[:20],
            "summary": summary,
            "gaps": [sanitize_model_text(item, 300) for item in gaps[:20]],
            "audited_files": [sanitize_model_text(item, 200) for item in audited[:40]],
        })
        result.data.update({
            "candidates": added,
            "summary": summary,
            "rejected": rejected,
            "duplicates": duplicates,
            "stats": {"files": stats["files"], "chars": stats["chars"]},
        })
        ctx.log(
            self.name,
            f"LLM 深挖：送入 {stats['files']} 个文件/{stats['chars']} 字符，"
            f"新增 {len(added)} 条候选，重复 {duplicates}，拒绝 {len(rejected)}",
        )
        result.duration_sec = round(time.time() - started, 2)
        return result

    # ------------------------------------------------------------------
    # 模型输出 → Candidate
    # ------------------------------------------------------------------

    def _to_candidate(self, ctx: AgentContext, item: Any) -> tuple[Candidate | None, str]:
        if not isinstance(item, dict):
            return None, "finding 不是对象"
        path = str(item.get("file_path") or "")
        allowed = {entry.rel_path for entry in ctx.project.files}
        if path not in allowed:
            return None, f"非仓库路径: {path!r}"
        text = ctx.contents.get(path) or ""
        lines = text.splitlines()
        if not lines:
            return None, f"空文件: {path}"
        try:
            line_start = int(item.get("line_start") or 1)
            line_end = int(item.get("line_end") or line_start)
        except (TypeError, ValueError):
            line_start, line_end = 1, 1
        line_start = max(1, min(line_start, len(lines)))
        line_end = max(line_start, min(line_end, len(lines)))

        source = sanitize_model_text(item.get("source"), 800)
        sink = sanitize_model_text(item.get("sink"), 800)
        description = sanitize_model_text(item.get("description"), 4000)
        chain = self._chain(item.get("exploit_chain"))
        if not source:
            return None, f"{path}:{line_end} 缺少 source"
        if not sink:
            return None, f"{path}:{line_end} 缺少 sink"
        if not description:
            return None, f"{path}:{line_end} 缺少 description"
        if not chain:
            return None, f"{path}:{line_end} 缺少 exploit_chain"

        vuln_type = canonical(str(item.get("vulnerability_type") or "other"))
        severity = str(item.get("severity") or "").lower()
        if severity not in SEVERITIES:
            severity = meta(vuln_type).default_severity
        confidence = self._confidence(item.get("confidence"))
        source_kind = self._source_kind(item.get("source_kind"), source)
        source_name = sanitize_model_text(item.get("source_name"), 200).strip("` ") or "*"
        endpoint, method = self._endpoint(ctx, item, path)
        title = sanitize_model_text(item.get("title"), 300) or \
            f"{Path(path).stem} {meta(vuln_type).label_zh}（{meta(vuln_type).cwe}）"
        snippet = "\n".join(lines[line_start - 1: min(line_end, line_start + 39)])
        digest = hashlib.sha1(f"{path}:{line_end}:{vuln_type}".encode("utf-8")).hexdigest()[:12]

        poc_hint: dict[str, Any] = {}
        raw_poc = item.get("poc")
        if isinstance(raw_poc, dict):
            for key in ("description", "payload"):
                if raw_poc.get(key):
                    poc_hint[key] = sanitize_model_text(raw_poc.get(key), 1500)
            if isinstance(raw_poc.get("preconditions"), list):
                poc_hint["preconditions"] = [sanitize_model_text(value, 300)
                                             for value in raw_poc["preconditions"][:10]]

        verification = sanitize_model_text(item.get("verification_notes"), 2000)
        if poc_hint:
            extra = poc_hint.get("description") or poc_hint.get("payload") or ""
            if extra:
                verification = (verification + "\n模型 POC 要点：" + extra)[:3000]

        return Candidate(
            candidate_id=f"LLM-{digest}",
            vuln_type=vuln_type,
            file=path,
            line_start=line_start,
            line_end=line_end,
            rule_id="llm-deep-discovery",
            sink=sink,
            source_kind=source_kind,
            source_name=source_name,
            endpoint=endpoint,
            http_method=method,
            code_snippet=snippet,
            tainted_expression=sanitize_model_text(item.get("tainted_expression"), 800),
            chain=chain,
            severity=severity,
            confidence=confidence,
            origin="llm_finding",
            notes=[
                "LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；"
                "文件与行号已校验，代码片段由真实源码回填。",
            ],
            title=title,
            description=description,
            impact=sanitize_model_text(item.get("impact"), 2000),
            cve_justification=sanitize_model_text(item.get("cve_justification"), 3000),
            suggestion=sanitize_model_text(item.get("suggestion"), 2000),
            verification_notes=verification,
            poc_hint=poc_hint,
        ), ""

    @staticmethod
    def _chain(raw: Any) -> list[ChainStep]:
        if not isinstance(raw, list):
            return []
        steps: list[ChainStep] = []
        for step in raw[:20]:
            if isinstance(step, dict):
                description = sanitize_model_text(step.get("description"), 900)
                if not description:
                    continue
                steps.append(ChainStep(
                    step=len(steps) + 1,
                    location=sanitize_model_text(step.get("location"), 300),
                    description=description,
                    data_state=sanitize_model_text(step.get("data_state"), 300),
                    bypass_reason=sanitize_model_text(step.get("bypass_reason"), 300),
                ))
            elif isinstance(step, str) and step.strip():
                steps.append(ChainStep(
                    step=len(steps) + 1,
                    location="",
                    description=sanitize_model_text(step, 900),
                ))
        return steps

    @staticmethod
    def _confidence(value: Any) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.72
        # 静态证据没有动态验证，最高 0.90；低于 0.55 的结论没有交付价值。
        return round(max(0.55, min(0.90, number)), 2)

    @staticmethod
    def _source_kind(value: Any, source_text: str) -> str:
        kind = str(value or "").strip().lower()
        kind = _KIND_ALIASES.get(kind, kind)
        if kind in SOURCE_KINDS:
            return kind
        text = (source_text or "").lower()
        for token in ("cookie", "header", "body", "path", "upload", "session", "config", "query"):
            if token in text:
                return token
        return "query"

    @staticmethod
    def _endpoint(ctx: AgentContext, item: dict[str, Any], path: str) -> tuple[str, str]:
        endpoint = str(item.get("endpoint") or "").strip()
        method = str(item.get("http_method") or "").strip().upper()
        known = [entry for entry in ctx.project.endpoints if entry.file == path]
        if endpoint.startswith("/"):
            for entry in known:
                if endpoint == entry.path or endpoint.startswith(entry.path.rstrip("/") + "/"):
                    return entry.path, (entry.method if entry.method != "ANY" else (method if method in _HTTP_METHODS else "GET"))
            return endpoint[:200], method if method in _HTTP_METHODS else "GET"
        if known:
            entry = known[0]
            return entry.path, (entry.method if entry.method != "ANY" else (method if method in _HTTP_METHODS else "GET"))
        return "", method if method in _HTTP_METHODS else "GET"

    @staticmethod
    def _find_duplicate(candidates: list[Candidate], new: Candidate) -> Candidate | None:
        for item in candidates:
            if item.vuln_type != new.vuln_type or item.file != new.file:
                continue
            if abs(item.line_end - new.line_end) <= 3:
                return item
        return None
