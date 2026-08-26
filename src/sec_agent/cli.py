"""The `sec-agent` command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import logfire
from pydantic import ValidationError

from .agent import Alert, TriageDeps, TriageVerdict, build_agent
from .compaction import resolve_profile
from .settings import settings
from .trace import run_traced

VERDICT_LABEL = {
    "true_positive": "TRUE POSITIVE",
    "benign_true_positive": "BENIGN TRUE POSITIVE",
    "false_positive": "FALSE POSITIVE",
    "inconclusive": "INCONCLUSIVE",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sec-agent",
        description="Triage a single authentication alert against Elasticsearch.",
    )
    parser.add_argument(
        "alert",
        type=Path,
        help="Path to the alert JSON file (`-` to read it from stdin).",
    )
    parser.add_argument(
        "--es-url",
        default=None,
        help=f"Elasticsearch base URL (default: {settings.es_url})",
    )
    parser.add_argument(
        "--index",
        action="append",
        default=None,
        dest="indices",
        help="Allow an extra index to be queried. Repeatable.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Model as `provider:model` (default: {settings.model})",
    )
    parser.add_argument(
        "--effort",
        default=None,
        choices=["low", "medium", "high", "xhigh", "max"],
        help=f"Reasoning depth (default: {settings.effort})",
    )
    parser.add_argument(
        "--compaction",
        default=None,
        metavar="PROFILE",
        help="Message-history compaction profile from compaction.toml (default: its own).",
    )
    parser.add_argument(
        "--compaction-config",
        default=None,
        metavar="PATH",
        help="Read compaction profiles from this file instead of ./compaction.toml.",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Show the run as it happens: reasoning, tool calls and their results.",
    )
    parser.add_argument("--json", action="store_true", help="Print the verdict as JSON.")
    return parser.parse_args(argv)


def _load_alert(path: Path) -> Alert:
    raw = sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8")
    return Alert.model_validate_json(raw)


def _render(verdict: TriageVerdict) -> str:
    label = VERDICT_LABEL.get(verdict.verdict, verdict.verdict.upper())
    lines = [
        f"{label}  [{verdict.severity.upper()}]  confidence {verdict.confidence:.2f}"
        f"{'  ESCALATE' if verdict.escalate else ''}",
        f"Alert: {verdict.alert_id}",
        "",
        verdict.summary,
        "",
    ]

    if verdict.attack_pattern:
        lines += [f"Pattern: {verdict.attack_pattern}", ""]

    if verdict.timeline:
        lines.append("Timeline")
        for event in verdict.timeline:
            docs = f"  [{', '.join(event.doc_ids)}]" if event.doc_ids else ""
            lines.append(f"  {event.timestamp.isoformat()}  {event.description}{docs}")
        lines.append("")

    scope = verdict.scope
    pivots = scope.pivots()
    if pivots:
        lines.append("Scope")
        for field_name, value in pivots:
            lines.append(f"  {field_name} = {value}")
        lines.append("")

    if verdict.recommended_actions:
        lines.append("Recommended actions")
        lines += [f"  {i}. {a}" for i, a in enumerate(verdict.recommended_actions, start=1)]
        lines.append("")

    if verdict.queries_run:
        lines.append(f"Queries run ({len(verdict.queries_run)})")
        for query in verdict.queries_run:
            lines.append(f"  [{query.hits} hits] {query.purpose}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


async def _run(args: argparse.Namespace, alert: Alert) -> TriageVerdict:
    logfire.configure()
    logfire.instrument_pydantic_ai()
    agent = build_agent(model=args.model, effort=args.effort, compaction=args.profile)
    deps = TriageDeps(alert=alert)
    if args.es_url:
        deps.es_url = args.es_url
    if args.indices:
        deps.allowed_indices = tuple({*deps.allowed_indices, *args.indices})
    if args.trace:
        return await run_traced(agent, deps)
    result = await agent.run(f"Triage alert {alert.alert_id}.", deps=deps)
    return result.output


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)

    if str(args.alert) != "-" and not args.alert.is_file():
        print(f"Error: {args.alert} is not a file.", file=sys.stderr)
        return 2

    try:
        alert = _load_alert(args.alert)
    except (ValidationError, json.JSONDecodeError) as exc:
        print(f"Error: {args.alert} is not a valid alert.\n{exc}", file=sys.stderr)
        return 2

    variable, key = settings.api_key_for(args.model)
    if variable and not key:
        print(f"Error: {variable} is not set (put it in .env).", file=sys.stderr)
        return 2

    # Resolve the compaction profile before spending anything, so an unknown
    # name or a malformed strategy fails as an argument error rather than mid-run.
    try:
        args.profile = resolve_profile(
            args.compaction or settings.compaction,
            args.compaction_config or settings.compaction_config,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        verdict = asyncio.run(_run(args, alert))
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(verdict.model_dump_json(indent=2) if args.json else _render(verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
