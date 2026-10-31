#!/usr/bin/env python3
"""Conservative, reproducible normalization for the Baofeng PHP corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def normalize(data: bytes) -> tuple[bytes, dict[str, int]]:
    # Preserve UTF-8 BOM if present; decode strictly to avoid silent corruption.
    bom = data.startswith(b"\xef\xbb\xbf")
    text = data.decode("utf-8-sig" if bom else "utf-8")
    original_lines = text.splitlines()
    output: list[str] = []
    removed_blank = 0
    trimmed = 0
    collapsed = 0
    for line in original_lines:
        cleaned = line.rstrip(" \t\v\f")
        if cleaned != line:
            trimmed += 1
        if not cleaned.strip():
            removed_blank += 1
            continue
        output.append(cleaned)
    normalized = "\n".join(output)
    if output:
        normalized += "\n"
    # No consecutive empty lines remain due to C01. Keep the counter explicit
    # for future rule expansion and for a stable manifest schema.
    result = (b"\xef\xbb\xbf" if bom else b"") + normalized.encode("utf-8")
    return result, {
        "input_lines": len(original_lines),
        "output_lines": len(output),
        "blank_lines_removed": removed_blank,
        "trailing_whitespace_lines": trimmed,
        "collapsed_blank_runs": collapsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    source = args.source.resolve()
    output = (args.output or source.parent / f"{source.name}_预处理").resolve()
    if not source.is_dir():
        parser.error(f"source directory does not exist: {source}")
    if source == output or source in output.parents:
        parser.error("output must be separate from and outside the source directory")
    if output.exists():
        parser.error(f"output already exists; refusing to overwrite: {output}")

    php_files = sorted(source.glob("*.php"), key=lambda p: p.name)
    zip_files = sorted(source.glob("*.zip"), key=lambda p: p.name)
    if not php_files or not zip_files:
        parser.error("source must contain top-level PHP and ZIP files")

    output.mkdir(parents=True)
    records = []
    for path in php_files:
        raw = path.read_bytes()
        cleaned, stats = normalize(raw)
        target = output / path.name
        target.write_bytes(cleaned)
        records.append({
            "kind": "php",
            "name": path.name,
            "source_sha256": sha256(raw),
            "output_sha256": sha256(cleaned),
            **stats,
        })

    zip_records = []
    for archive in zip_files:
        target_zip = output / archive.name
        entries = []
        with zipfile.ZipFile(archive, "r") as zin, zipfile.ZipFile(target_zip, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                if info.is_dir():
                    zout.writestr(info, b"")
                    continue
                payload = zin.read(info.filename)
                cleaned, stats = normalize(payload)
                zout.writestr(info, cleaned)
                entries.append({
                    "name": info.filename,
                    "source_sha256": sha256(payload),
                    "output_sha256": sha256(cleaned),
                    **stats,
                })
        zip_records.append({
            "name": archive.name,
            "source_sha256": sha256(archive.read_bytes()),
            "output_sha256": sha256(target_zip.read_bytes()),
            "members": entries,
        })

    # Carry the original mapping table unchanged for traceability.
    mapping = source / "编号对应表.md"
    if mapping.is_file():
        (output / mapping.name).write_bytes(mapping.read_bytes())
    manifest = {
        "schema_version": 1,
        "source_directory": str(source),
        "rules_applied": ["C01", "C02", "C09", "C12"],
        "semantic_rules_deferred": ["C03", "C04", "C05", "C06", "C07", "C08", "C10", "C11"],
        "php_file_count": len(php_files),
        "zip_file_count": len(zip_files),
        "php_files": records,
        "zip_files": zip_records,
    }
    (output / "预处理清单.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"预处理完成：{len(php_files)} 个 PHP，{len(zip_files)} 个 ZIP -> {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (UnicodeDecodeError, zipfile.BadZipFile, OSError) as exc:
        print(f"预处理失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
