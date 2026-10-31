"""Command line for 落日验证 (Sunset Verify)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import VerifySettings
from .pipeline import summarize, verify_batch, verify_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sunset-verify",
        description="落日验证：对落日二号 URL/zip 两种模式的 POC 做动态验证",
    )
    parser.add_argument("--version", action="version", version=f"落日验证 {__version__}")
    sub = parser.add_subparsers(dest="command")

    verify = sub.add_parser("verify", help="验证单个结果目录或批量结果")
    verify.add_argument("--mode", choices=["url", "zip"], required=True, help="与落日二号输入模式对应")
    verify.add_argument("--result", help="单个落日二号结果目录（含 report.json）")
    verify.add_argument("--results-dir", help="批量结果根目录（递归查找 report.json）")
    verify.add_argument("--target-base", default="", help="zip 模式的部署基址，如 https://localhost:8443")
    verify.add_argument("--out", help="批量汇总输出目录")
    verify.add_argument("--timeout", type=float, default=15.0)
    verify.add_argument("--insecure", action="store_true", default=True, help="允许自签名 HTTPS（默认开）")
    verify.add_argument("--verify-tls", action="store_true", help="严格校验 TLS（默认关闭）")
    verify.add_argument("--follow-redirects", action="store_true")
    verify.add_argument("--workers", type=int, default=4)
    verify.add_argument("--allow-host", action="append", default=[], help="额外允许的目标主机")
    verify.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "verify":
        parser.print_help()
        return 0
    if not args.result and not args.results_dir:
        print("需要 --result 或 --results-dir", file=sys.stderr)
        return 1
    if args.mode == "zip" and not args.target_base:
        print("zip 模式需要 --target-base（已部署的 lite 靶场基址）", file=sys.stderr)
        return 1

    settings = VerifySettings(
        mode=args.mode,
        result_dir=Path(args.result) if args.result else None,
        results_dir=Path(args.results_dir) if args.results_dir else None,
        target_base=args.target_base,
        out_dir=Path(args.out) if args.out else None,
        timeout=args.timeout,
        insecure=not args.verify_tls,
        follow_redirects=args.follow_redirects,
        workers=args.workers,
        allow_hosts=args.allow_host,
    )
    try:
        if settings.result_dir:
            results, stages = verify_result(settings.result_dir, settings)
        else:
            results, stages = verify_batch(settings)
    except Exception as exc:  # noqa: BLE001
        print(f"验证管线失败: {exc}", file=sys.stderr)
        return 1

    summary = summarize(results)
    print("")
    print(f"落日验证完成（{settings.mode}）：{summary['total']} 个 POC，"
          f"verified={summary['verified']} rejected={summary['rejected']} "
          f"inconclusive={summary['inconclusive']} unsupported={summary['unsupported']} "
          f"error={summary['error']}")
    for item in results[:20]:
        print(f"  [{item.verdict:12s}] {item.finding_id:18s} {item.vulnerability_type:22s} "
              f"{item.target_url[:80]} :: {item.reason[:100]}")
    if len(results) > 20:
        print(f"  ... 另有 {len(results) - 20} 条")
    if settings.result_dir:
        print(f"输出：{settings.result_dir / 'verification'}")
    elif settings.out_dir:
        print(f"输出：{settings.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
