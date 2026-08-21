"""The `sec-agent` command line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .agent import SecurityDeps, SecurityReport, build_agent
from .settings import settings

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sec-agent",
        description="Review a codebase for security vulnerabilities.",
    )
    parser.add_argument(
        "prompt",
        nargs="?",
        default="Review this codebase for security vulnerabilities.",
        help="The task to give the agent.",
    )
    parser.add_argument(
        "-C",
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Root directory to review (default: the working directory).",
    )
    parser.add_argument("--model", default=None, help=f"Model (default: {settings.model})")
    parser.add_argument(
        "--effort",
        default=None,
        choices=["low", "medium", "high", "xhigh", "max"],
        help=f"Reasoning depth (default: {settings.effort})",
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    return parser.parse_args(argv)


def _render(report: SecurityReport) -> str:
    lines = [report.summary, ""]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for i, f in enumerate(findings, start=1):
        location = f.file or "-"
        if f.file and f.line:
            location = f"{f.file}:{f.line}"
        lines += [
            f"{i}. [{f.severity.upper()}] {f.title}",
            f"   Location: {location}",
            f"   {f.description}",
            f"   Fix: {f.recommendation}",
            "",
        ]
    return "\n".join(lines)


async def _run(args: argparse.Namespace) -> SecurityReport:
    agent = build_agent(model=args.model, effort=args.effort)
    deps = SecurityDeps(root=args.root.resolve())
    result = await agent.run(args.prompt, deps=deps)
    return result.output


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)

    if not args.root.is_dir():
        print(f"Error: {args.root} is not a directory.", file=sys.stderr)
        return 2

    try:
        report = asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130

    print(report.model_dump_json(indent=2) if args.json else _render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
