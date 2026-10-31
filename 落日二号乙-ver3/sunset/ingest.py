"""压缩包安全展开与仓库清单。

所有挖掘都从 zip 开始：先做 zip-slip / 符号链接 / zip bomb / 超大文件防护，再建立
文件清单。管线不假设压缩包是「可构建工程」——只做源码级审计。
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .models import Project, SourceFile

MAX_FILES = 6000
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
MAX_PATH_LENGTH = 512
EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "bower_components", "vendor",
    "dist", "build", "target", "out", ".idea", ".vscode", "__pycache__",
    "__MACOSX", ".pytest_cache", ".mypy_cache", ".gradle", ".tox",
}

LANGUAGE_BY_EXT = {
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".php": "php", ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rb": "ruby", ".cs": "csharp", ".fs": "fsharp",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust", ".scala": "scala", ".swift": "swift",
    ".jsp": "jsp", ".jspx": "jsp", ".asp": "asp", ".aspx": "aspx",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".xml": "xml", ".yml": "yaml", ".yaml": "yaml", ".json": "json",
    ".properties": "properties", ".conf": "config", ".ini": "config", ".toml": "config",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".md": "markdown", ".txt": "text", ".gradle": "gradle", ".groovy": "groovy",
    ".tf": "terraform", ".dockerfile": "docker",
}

AUDITABLE_LANGUAGES = {
    "java", "kotlin", "php", "python", "javascript", "typescript", "go", "ruby",
    "csharp", "c", "cpp", "rust", "scala", "jsp", "asp", "aspx", "vue", "svelte",
    "shell", "sql", "groovy", "terraform", "docker",
}


class IngestError(RuntimeError):
    pass


@dataclass
class IngestResult:
    project: Project
    contents: dict[str, str]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_parts(name: str) -> list[str]:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise IngestError(f"拒绝绝对路径条目: {name!r}")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise IngestError(f"拒绝路径穿越条目: {name!r}")
    if len("/".join(parts)) > MAX_PATH_LENGTH:
        raise IngestError(f"路径过长: {name!r}")
    return parts


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def safe_extract(zip_path: Path, dest: Path) -> tuple[list[dict[str, str]], dict[str, int]]:
    """安全展开 zip，返回 (skipped, stats)。"""
    skipped: list[dict[str, str]] = []
    stats = {"entries": 0, "extracted": 0, "skipped": 0, "bytes": 0}
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise IngestError(f"不是有效 zip: {exc}") from exc

    with zf:
        infos = zf.infolist()
        stats["entries"] = len(infos)
        if len(infos) > MAX_FILES:
            raise IngestError(f"zip 条目过多: {len(infos)} > {MAX_FILES}")
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > MAX_TOTAL_BYTES:
            raise IngestError(f"zip 解压后过大: {total_uncompressed} bytes")
        compressed = sum(info.compress_size for info in infos) or 1
        if total_uncompressed > 20 * 1024 * 1024 and total_uncompressed / compressed > 200:
            raise IngestError("疑似 zip bomb（压缩比 > 200）")

        for info in infos:
            name = info.filename
            try:
                parts = _safe_parts(name)
            except IngestError as exc:
                skipped.append({"entry": name, "reason": str(exc)})
                stats["skipped"] += 1
                continue
            if not parts:
                continue
            if any(part in EXCLUDED_DIRS for part in parts[:-1]):
                skipped.append({"entry": name, "reason": "排除目录"})
                stats["skipped"] += 1
                continue
            if info.is_dir():
                continue
            if _is_symlink(info):
                skipped.append({"entry": name, "reason": "符号链接（拒绝展开）"})
                stats["skipped"] += 1
                continue
            if info.file_size > MAX_FILE_BYTES:
                skipped.append({"entry": name, "reason": f"文件过大 {info.file_size} bytes"})
                stats["skipped"] += 1
                continue
            target = dest.joinpath(*parts)
            try:
                target.resolve().relative_to(dest_resolved)
            except ValueError:
                skipped.append({"entry": name, "reason": "解压目标逃逸"})
                stats["skipped"] += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info) as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(1024 * 256)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_FILE_BYTES:
                            raise IngestError("解压过程中文件超过上限")
                        sink.write(chunk)
            except Exception as exc:  # noqa: BLE001 - 记录并继续
                skipped.append({"entry": name, "reason": f"解压失败: {exc}"})
                stats["skipped"] += 1
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            stats["extracted"] += 1
            stats["bytes"] += written

    return skipped, stats


def detect_language(path: Path) -> str:
    name = path.name.lower()
    if name in {"dockerfile", "containerfile"}:
        return "docker"
    if name in {"makefile", "cmakelists.txt"}:
        return "build"
    suffix = path.suffix.lower()
    return LANGUAGE_BY_EXT.get(suffix, "unknown")


def _looks_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    sample = data[:8192]
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13) or byte >= 128)
    return printable / len(sample) > 0.85


def inventory(root: Path) -> tuple[list[SourceFile], dict[str, int], dict[str, str]]:
    files: list[SourceFile] = []
    languages: dict[str, int] = {}
    contents: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in EXCLUDED_DIRS for part in Path(rel).parts[:-1]):
            continue
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                head = handle.read(8192)
        except OSError:
            continue
        is_text = _looks_text(head)
        language = detect_language(path)
        lines = 0
        text = ""
        if is_text:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            if len(text) <= 2 * 1024 * 1024:
                contents[rel] = text
        languages[language] = languages.get(language, 0) + 1
        files.append(
            SourceFile(
                rel_path=rel,
                size=size,
                lines=lines,
                language=language,
                sha256=sha256_bytes(head) if size <= 8192 else "",
                is_text=is_text,
            )
        )
    return files, languages, contents


def ingest_zip(zip_path: Path, work_dir: Path) -> IngestResult:
    zip_path = zip_path.resolve()
    if not zip_path.is_file():
        raise IngestError(f"zip 不存在: {zip_path}")
    zip_sha = sha256_file(zip_path)
    extract_dir = work_dir / "extracted"
    if extract_dir.exists():
        # 清理上一次展开（仅清理本管线自己的 work 目录）
        for child in sorted(extract_dir.rglob("*"), reverse=True):
            try:
                child.unlink() if child.is_file() else child.rmdir()
            except OSError:
                pass
    skipped, stats = safe_extract(zip_path, extract_dir)

    # 若 zip 只有一个顶层目录，把该目录视为仓库根，报告路径更干净。
    children = [child for child in extract_dir.iterdir() if child.name not in EXCLUDED_DIRS]
    if len(children) == 1 and children[0].is_dir():
        root = children[0]
    else:
        root = extract_dir

    files, languages, contents = inventory(root)
    project = Project(
        zip_path=str(zip_path),
        zip_sha256=zip_sha,
        root=str(root),
        extracted_dir=str(extract_dir),
        files=files,
        languages=languages,
        manifest={
            "zip_entries": stats["entries"],
            "extracted": stats["extracted"],
            "skipped": stats["skipped"],
            "extracted_bytes": stats["bytes"],
            "root": str(root.relative_to(extract_dir)) if root != extract_dir else ".",
            "file_count": len(files),
            "text_file_count": sum(1 for item in files if item.is_text),
        },
        skipped=skipped,
    )
    return IngestResult(project=project, contents=contents)
