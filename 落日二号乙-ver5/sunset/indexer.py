"""源码索引：框架识别、HTTP 端点、攻击面地图。

这一层是确定性的，不调用 LLM。它把「仓库」变成后续 agent 可消费的结构化上下文，
也是 AWVS 目标播种（source→AWVS）的来源。
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from .models import Endpoint, Project, SourceFile

FRAMEWORK_MARKERS = {
    "spring": [r"org\.springframework", r"@RestController", r"@Controller", r"@RequestMapping"],
    "servlet": [r"javax\.servlet", r"jakarta\.servlet", r"HttpServlet"],
    "mybatis": [r"org\.apache\.ibatis", r"#\{", r"\$\{"],
    "hibernate": [r"org\.hibernate", r"@Entity"],
    "flask": [r"from\s+flask\s+import", r"@app\.route", r"Flask\("],
    "django": [r"from\s+django", r"urlpatterns", r"JsonResponse"],
    "fastapi": [r"from\s+fastapi\s+import", r"FastAPI\("],
    "express": [r"require\(['\"]express", r"from\s+['\"]express", r"app\.(?:get|post|put|delete)\("],
    "laravel": [r"Illuminate\\", r"Route::(?:get|post|put|delete)"],
    "rails": [r"Rails\.application", r"ActionController"],
    "gin": [r"github\.com/gin-gonic/gin", r"gin\.Default\("],
    "aspnet": [r"System\.Web", r"Microsoft\.AspNetCore", r"\[Http(?:Get|Post|Put|Delete)"],
}

SOURCE_PATTERNS = [
    re.compile(r"request\s*\.\s*get(?:Parameter|Header|Cookies|QueryString|InputStream|Reader|PathInfo|RequestURI)"),
    re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"),
    re.compile(r"request\s*\.\s*(?:args|form|values|json|files|headers|data)\b"),
    re.compile(r"req\s*\.\s*(?:query|body|params|headers|cookies)\b"),
    re.compile(r"r\s*\.\s*(?:URL|FormValue|Header)\b"),
    re.compile(r"Request\s*\.\s*(?:QueryString|Form|Headers|Cookies)\b"),
]

SINK_PATTERNS = [
    re.compile(r"\b(?:Runtime|ProcessBuilder|exec|system|shell_exec|subprocess|child_process)\b"),
    re.compile(r"\b(?:executeQuery|executeUpdate|queryForList|queryForObject|mysql_query|mysqli_query|PDO)\b"),
    re.compile(r"\b(?:FileOutputStream|FileInputStream|Files\.(?:write|read)|os\.Open|fs\.(?:read|write)File)\b"),
    re.compile(r"\b(?:ObjectInputStream|readObject|unserialize|pickle\.loads|BinaryFormatter)\b"),
    re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader)\b"),
    re.compile(r"\b(?:sendRedirect|setHeader)\b"),
    re.compile(r"\b(?:getWriter\(\)\s*\.\s*(?:print|write|println)|innerHTML|document\.write)\b"),
]


def detect_frameworks(contents: dict[str, str]) -> list[str]:
    found: list[str] = []
    for framework, patterns in FRAMEWORK_MARKERS.items():
        for text in contents.values():
            if any(re.search(pattern, text) for pattern in patterns):
                found.append(framework)
                break
    return sorted(found)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _java_class_prefix(text: str) -> str:
    prefix = ""
    match = re.search(r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?(?:\{[^}]*?)?[\"']([^\"']+)[\"']", text)
    if match:
        prefix = match.group(1)
    return prefix.rstrip("/")


def _java_endpoints(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    servlet = re.search(r"@WebServlet\s*\(\s*(?:value\s*=\s*)?(?:\{[^}]*?)?[\"']([^\"']+)[\"']", text)
    servlet_path = servlet.group(1) if servlet else ""
    class_prefix = _java_class_prefix(text)

    mapping_re = re.compile(
        r"@(?P<kind>RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
        r"\s*\((?P<args>[^)]*)\)\s*(?:\n\s*)*(?:public|protected|private|static|final|\s)*"
        r"(?:[\w$.<>\[\],?]+\s+)+(?P<name>\w+)\s*\(",
        re.MULTILINE,
    )
    method_map = {
        "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
        "DeleteMapping": "DELETE", "PatchMapping": "PATCH", "RequestMapping": "ANY",
    }
    for match in mapping_re.finditer(text):
        args = match.group("args")
        path_match = re.search(r"(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']", args)
        path = path_match.group(1) if path_match else ""
        if not path:
            continue
        full = "/" + "/".join(part for part in [class_prefix.strip("/"), path.strip("/")] if part)
        endpoints.append(
            Endpoint(
                path=full,
                method=method_map.get(match.group("kind"), "ANY"),
                file=rel,
                line=_line_of(text, match.start()),
                framework="spring",
                handler=match.group("name"),
                params=re.findall(r"@(?:RequestParam|PathVariable|RequestBody)\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)", args),
            )
        )

    if servlet_path:
        for http_method, handler_name in (("GET", "doGet"), ("POST", "doPost"), ("PUT", "doPut"), ("DELETE", "doDelete")):
            handler = re.search(rf"\b{handler_name}\s*\(", text)
            if handler:
                endpoints.append(
                    Endpoint(
                        path=servlet_path,
                        method=http_method,
                        file=rel,
                        line=_line_of(text, servlet.start()),
                        framework="servlet",
                        handler=handler_name,
                        params=re.findall(r"getParameter\s*\(\s*[\"']([^\"']+)", text),
                    )
                )

    if not endpoints and re.search(r"extends\s+HttpServlet\b", text):
        stem = Path(rel).stem
        endpoints.append(
            Endpoint(
                path=f"/{stem}",
                method="POST",
                file=rel,
                line=1,
                framework="servlet",
                handler="doPost",
                params=re.findall(r"getParameter\s*\(\s*[\"']([^\"']+)", text),
            )
        )
    return endpoints


def _python_endpoints(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    pattern = re.compile(
        r"@(?:\w+)\.(?:route|get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']"
        r"(?:[^)]*?methods\s*=\s*\[([^\]]*)\])?[^)]*\)\s*(?:\n\s*)*(?:async\s+)?def\s+(\w+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        methods = re.findall(r"[\"'](\w+)[\"']", match.group(2) or "")
        for method in methods or ["GET"]:
            endpoints.append(
                Endpoint(
                    path=match.group(1),
                    method=method.upper(),
                    file=rel,
                    line=_line_of(text, match.start()),
                    framework="python",
                    handler=match.group(3),
                    params=[],
                )
            )
    return endpoints


def _js_endpoints(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    pattern = re.compile(
        r"\b(?:app|router|server|route)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*[\"']([^\"']+)[\"']",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        endpoints.append(
            Endpoint(
                path=match.group(2),
                method=match.group(1).upper(),
                file=rel,
                line=_line_of(text, match.start()),
                framework="express",
                handler="",
            )
        )
    return endpoints


def _go_endpoints(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for match in re.finditer(r"\b(?:r|router|e|g)\s*\.\s*(GET|POST|PUT|DELETE|PATCH)\s*\(\s*[\"']([^\"']+)[\"']", text):
        endpoints.append(
            Endpoint(path=match.group(2), method=match.group(1), file=rel,
                     line=_line_of(text, match.start()), framework="gin")
        )
    return endpoints


def _dotnet_endpoints(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    pattern = re.compile(r"\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*[\"']([^\"']+)[\"']\s*\))?\]", re.IGNORECASE)
    for match in pattern.finditer(text):
        endpoints.append(
            Endpoint(path=match.group(2) or "", method=match.group(1).upper(), file=rel,
                     line=_line_of(text, match.start()), framework="aspnet")
        )
    return endpoints


def _html_forms(rel: str, text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for match in re.finditer(r"<form\b[^>]*>", text, re.IGNORECASE):
        tag = match.group(0)
        action = re.search(r"action\s*=\s*[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
        method = re.search(r"method\s*=\s*[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
        if action:
            endpoints.append(
                Endpoint(path=action.group(1), method=(method.group(1) if method else "GET").upper(),
                         file=rel, line=_line_of(text, match.start()), framework="html-form")
            )
    return endpoints


def extract_endpoints(files: list[SourceFile], contents: dict[str, str]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for file in files:
        if not file.is_text:
            continue
        text = contents.get(file.rel_path, "")
        if not text:
            continue
        language = file.language
        if language in {"java", "kotlin"}:
            endpoints.extend(_java_endpoints(file.rel_path, text))
        elif language == "python":
            endpoints.extend(_python_endpoints(file.rel_path, text))
        elif language in {"javascript", "typescript"}:
            endpoints.extend(_js_endpoints(file.rel_path, text))
        elif language == "go":
            endpoints.extend(_go_endpoints(file.rel_path, text))
        elif language in {"csharp", "aspx"}:
            endpoints.extend(_dotnet_endpoints(file.rel_path, text))
        elif language == "html":
            endpoints.extend(_html_forms(file.rel_path, text))

    seen: set[tuple[str, str, str]] = set()
    unique: list[Endpoint] = []
    for endpoint in endpoints:
        key = (endpoint.path, endpoint.method, endpoint.file)
        if key in seen:
            continue
        seen.add(key)
        unique.append(endpoint)
    return sorted(unique, key=lambda item: (item.path, item.method, item.file))


def attack_surface(project: Project, contents: dict[str, str]) -> dict:
    source_hits = Counter()
    sink_hits = Counter()
    entry_files: set[str] = set()
    for file in project.files:
        text = contents.get(file.rel_path, "")
        if not text:
            continue
        for pattern in SOURCE_PATTERNS:
            count = len(pattern.findall(text))
            if count:
                source_hits[file.rel_path] += count
                entry_files.add(file.rel_path)
        for pattern in SINK_PATTERNS:
            count = len(pattern.findall(text))
            if count:
                sink_hits[file.rel_path] += count
    return {
        "endpoint_count": len(project.endpoints),
        "entry_files": sorted(entry_files)[:50],
        "source_hot_files": source_hits.most_common(20),
        "sink_hot_files": sink_hits.most_common(20),
        "languages": project.languages,
        "frameworks": project.frameworks,
        "awvs_seed": [
            {
                "path": endpoint.path,
                "method": endpoint.method,
                "file": endpoint.file,
                "line": endpoint.line,
                "params": endpoint.params,
            }
            for endpoint in project.endpoints
        ],
    }
