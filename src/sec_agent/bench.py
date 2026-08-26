"""Price the compaction profiles against the alert corpus.

Running one alert tells you what a verdict costs. Running every alert under
every profile in `compaction.toml` tells you what each compaction strategy is
*worth* — which is a different question, because compaction is not free in
either direction. Clearing an old tool result saves the tokens it occupied on
every subsequent request, but a model that can no longer see the document it was
about may go and fetch it again. Summarizing saves more and costs a whole model
call to do it.

So this measures three things at once, and a profile is only a win if it moves
all three the right way:

    spend       tokens in and out, and the dollar cost of them
    pressure    peak estimated context, the thing compaction actually targets
    fidelity    whether the verdict is still grounded in retrieved documents

Fidelity is the one that matters. A profile that halves the cost and starts
returning `inconclusive`, or cites no documents in its timeline, has not made
triage cheaper — it has stopped doing triage. The checks in `CHECKS` are
deliberately mechanical: they read the `TriageVerdict` structure against
`siem/ground_truth.json` and never ask a model to grade another model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pydantic_ai.usage import RunUsage

from .agent import Alert, TriageDeps, TriageVerdict, build_agent
from .compaction import CompactionProfile, load_config
from .settings import provider_of, settings

DEFAULT_ALERTS = Path("siem/alerts")
DEFAULT_GROUND_TRUTH = Path("siem/ground_truth.json")


# ---------------------------------------------------------------------------
# Fidelity checks
#
# Each returns None when the verdict passes, or a short reason when it does not.
# `truth` is the scenario's entry in ground_truth.json, or an empty dict when the
# alert has no matching scenario.
# ---------------------------------------------------------------------------

Check = Callable[[TriageVerdict, dict[str, Any], Alert], str | None]


def _check_alert_id(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """The verdict has to say which alert it is about."""
    if verdict.alert_id != alert.alert_id:
        return f"alert_id {verdict.alert_id!r} != {alert.alert_id!r}"
    return None


def _check_decided(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """Every scenario in the corpus really happened, so `inconclusive` is a miss."""
    if verdict.verdict == "inconclusive":
        return "returned inconclusive"
    return None


def _check_positive(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """The activity described did occur; calling it a false positive is wrong.

    `benign_true_positive` passes: whether an off-hours admin login from a
    corporate range is *benign* is a judgement call the agent is allowed to make.
    """
    if verdict.verdict == "false_positive":
        return "called it a false positive"
    return None


def _check_user_in_scope(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """The account the scenario is about has to survive into the verdict's scope."""
    expected = truth.get("user")
    if not expected:
        return None
    if expected not in verdict.scope.users:
        return f"{expected!r} missing from scope.users"
    return None


def _check_ip_in_scope(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """So does the source address."""
    expected = truth.get("source_ips") or ([truth["source_ip"]] if truth.get("source_ip") else [])
    if not expected:
        return None
    found = {str(ip) for ip in verdict.scope.source_ips}
    missing = [ip for ip in expected if ip not in found]
    if missing:
        return f"{', '.join(missing)} missing from scope.source_ips"
    return None


def _check_timeline(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """A verdict with no timeline has not reconstructed anything."""
    if not verdict.timeline:
        return "empty timeline"
    return None


def _check_grounded(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> str | None:
    """Timeline steps must cite the documents behind them.

    This is the check compaction breaks first. Clear the tool result that carried
    a document id and the model can still describe what happened — it just can no
    longer prove it, which is the failure the instructions exist to prevent.
    """
    uncited = [event for event in verdict.timeline if not event.doc_ids]
    if uncited:
        return f"{len(uncited)}/{len(verdict.timeline)} timeline steps cite no document"
    return None


def _check_queries_recorded(
    verdict: TriageVerdict, truth: dict[str, Any], alert: Alert
) -> str | None:
    """An unauditable conclusion is worthless, per the instructions."""
    if not verdict.queries_run:
        return "no queries recorded"
    return None


CHECKS: dict[str, Check] = {
    "alert_id": _check_alert_id,
    "decided": _check_decided,
    "positive": _check_positive,
    "user_in_scope": _check_user_in_scope,
    "ip_in_scope": _check_ip_in_scope,
    "timeline": _check_timeline,
    "grounded": _check_grounded,
    "queries_recorded": _check_queries_recorded,
}


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------


@dataclass
class RunRecord:
    """Everything one (profile, alert) run is worth recording."""

    profile: str
    alert: str
    repeat: int
    model: str
    ok: bool = False
    error: str | None = None
    seconds: float = 0.0

    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None

    peak_context_tokens: int = 0
    context_window: int | None = None
    context_window_resolved: bool = False
    context_readings: list[int] = field(default_factory=list)
    """Estimated history size before each request, after this profile's compaction."""

    verdict: str | None = None
    severity: str | None = None
    confidence: float | None = None
    escalate: bool | None = None
    timeline_events: int = 0
    cited_events: int = 0
    queries_run: int = 0

    checks_passed: int = 0
    checks_total: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def peak_context_fraction(self) -> float | None:
        if not self.context_window:
            return None
        return self.peak_context_tokens / self.context_window


def price(usage: RunUsage, model: str) -> float | None:
    """Dollar cost of a run's usage, or None when the model is not in the registry.

    The summarizing strategy folds its own model call into the run's usage, so
    this prices an LLM-backed profile honestly rather than billing only the
    tokens the triage itself spent.
    """
    from genai_prices import Usage, calc_price

    provider = provider_of(model)
    _, _, model_ref = model.partition(":")
    try:
        calculation = calc_price(
            Usage(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_read_tokens=usage.cache_read_tokens or None,
                cache_write_tokens=usage.cache_write_tokens or None,
            ),
            model_ref=model_ref or model,
            provider_id=provider,
        )
    except LookupError:
        return None
    return float(calculation.total_price)


def grade(verdict: TriageVerdict, truth: dict[str, Any], alert: Alert) -> tuple[int, list[str]]:
    """Run every fidelity check, returning how many passed and why the rest did not."""
    failures = []
    for name, check in CHECKS.items():
        reason = check(verdict, truth, alert)
        if reason is not None:
            failures.append(f"{name}: {reason}")
    return len(CHECKS) - len(failures), failures


async def run_once(
    profile: CompactionProfile,
    alert_path: Path,
    truth: dict[str, Any],
    *,
    model: str | None,
    effort: str | None,
    es_url: str | None,
    repeat: int,
) -> RunRecord:
    """Triage one alert under one profile and measure what it cost."""
    from pydantic_ai_harness.compaction import ContextUsage, ReportContextUsage

    resolved_model = model or settings.model
    record = RunRecord(
        profile=profile.name,
        alert=alert_path.stem,
        repeat=repeat,
        model=resolved_model,
    )
    alert = Alert.model_validate_json(alert_path.read_text(encoding="utf-8"))

    def observe(usage: ContextUsage) -> None:
        record.context_readings.append(usage.used_tokens)
        record.peak_context_tokens = max(record.peak_context_tokens, usage.used_tokens)
        record.context_window = usage.window_tokens
        record.context_window_resolved = usage.resolved

    # Registered last, so the reading is of the history this profile leaves
    # behind rather than the one that triggered it.
    agent = build_agent(
        model=model,
        effort=effort,
        compaction=profile,
        extra_capabilities=[ReportContextUsage(on_usage=observe)],
    )
    deps = TriageDeps(alert=alert)
    if es_url:
        deps.es_url = es_url

    started = time.perf_counter()
    try:
        result = await agent.run(f"Triage alert {alert.alert_id}.", deps=deps)
    except Exception as exc:  # noqa: BLE001 — a failed profile is a result, not a crash
        record.seconds = time.perf_counter() - started
        record.error = f"{type(exc).__name__}: {exc}"
        return record
    record.seconds = time.perf_counter() - started

    usage = result.usage
    record.ok = True
    record.requests = usage.requests
    record.input_tokens = usage.input_tokens
    record.output_tokens = usage.output_tokens
    record.cache_read_tokens = usage.cache_read_tokens
    record.cache_write_tokens = usage.cache_write_tokens
    record.total_tokens = usage.total_tokens
    record.cost_usd = price(usage, resolved_model)

    verdict = result.output
    record.verdict = verdict.verdict
    record.severity = verdict.severity
    record.confidence = verdict.confidence
    record.escalate = verdict.escalate
    record.timeline_events = len(verdict.timeline)
    record.cited_events = sum(1 for event in verdict.timeline if event.doc_ids)
    record.queries_run = len(verdict.queries_run)
    record.checks_passed, record.failures = grade(verdict, truth, alert)
    record.checks_total = len(CHECKS)
    return record


# ---------------------------------------------------------------------------
# Aggregation and reporting
# ---------------------------------------------------------------------------


@dataclass
class ProfileSummary:
    """One profile's numbers, averaged over the alerts it was run on."""

    profile: str
    description: str
    strategies: str
    uses_llm: bool
    runs: int
    failed_runs: int
    input_tokens: float
    output_tokens: float
    total_tokens: float
    cost_usd: float | None
    seconds: float
    requests: float
    peak_context_tokens: float
    checks_passed: int
    checks_total: int
    grounded_fraction: float | None
    cost_delta_pct: float | None = None
    tokens_delta_pct: float | None = None


def _mean(values: Iterable[float]) -> float:
    collected = list(values)
    return statistics.fmean(collected) if collected else 0.0


def summarize(
    records: list[RunRecord], profiles: dict[str, CompactionProfile], baseline: str | None
) -> list[ProfileSummary]:
    """Fold the per-run records into one row per profile."""
    summaries: list[ProfileSummary] = []
    for name, profile in profiles.items():
        mine = [record for record in records if record.profile == name]
        if not mine:
            continue
        good = [record for record in mine if record.ok]
        priced = [record.cost_usd for record in good if record.cost_usd is not None]
        timeline_total = sum(record.timeline_events for record in good)
        summaries.append(
            ProfileSummary(
                profile=name,
                description=profile.description,
                strategies=profile.summary(),
                uses_llm=profile.uses_llm,
                runs=len(mine),
                failed_runs=len(mine) - len(good),
                input_tokens=_mean(r.input_tokens for r in good),
                output_tokens=_mean(r.output_tokens for r in good),
                total_tokens=_mean(r.total_tokens for r in good),
                cost_usd=_mean(priced) if priced else None,
                seconds=_mean(r.seconds for r in good),
                requests=_mean(r.requests for r in good),
                peak_context_tokens=_mean(r.peak_context_tokens for r in good),
                checks_passed=sum(r.checks_passed for r in good),
                checks_total=sum(r.checks_total for r in good),
                grounded_fraction=(
                    sum(r.cited_events for r in good) / timeline_total if timeline_total else None
                ),
            )
        )

    anchor = next((s for s in summaries if s.profile == baseline), None)
    if anchor:
        for summary in summaries:
            if anchor.cost_usd and summary.cost_usd is not None:
                summary.cost_delta_pct = (summary.cost_usd / anchor.cost_usd - 1) * 100
            if anchor.total_tokens:
                summary.tokens_delta_pct = (summary.total_tokens / anchor.total_tokens - 1) * 100
    return summaries


def _cell(value: Any, width: int, spec: str = "") -> str:
    text = "—" if value is None else format(value, spec)
    return text.rjust(width)


def render(summaries: list[ProfileSummary], records: list[RunRecord], baseline: str | None) -> str:
    """The report a human reads."""
    lines: list[str] = []
    header = (
        f"{'profile':<20}{'in':>9}{'out':>8}{'total':>9}{'Δtok':>8}"
        f"{'$/alert':>10}{'Δ$':>8}{'peak ctx':>10}{'reqs':>6}{'sec':>7}"
        f"{'checks':>9}{'cited':>8}"
    )
    lines += [header, "─" * len(header)]
    for summary in summaries:
        marker = "*" if summary.profile == baseline else " "
        checks = f"{summary.checks_passed}/{summary.checks_total}" if summary.checks_total else "—"
        lines.append(
            f"{marker}{summary.profile:<19}"
            + _cell(summary.input_tokens, 9, ",.0f")
            + _cell(summary.output_tokens, 8, ",.0f")
            + _cell(summary.total_tokens, 9, ",.0f")
            + _cell(summary.tokens_delta_pct, 8, "+.0f")
            + _cell(summary.cost_usd, 10, ".5f")
            + _cell(summary.cost_delta_pct, 8, "+.0f")
            + _cell(summary.peak_context_tokens, 10, ",.0f")
            + _cell(summary.requests, 6, ".1f")
            + _cell(summary.seconds, 7, ".1f")
            + checks.rjust(9)
            + _cell(
                summary.grounded_fraction * 100 if summary.grounded_fraction is not None else None,
                8,
                ".0f",
            )
        )

    lines += [
        "",
        "Δ columns are against the profile marked *.  `peak ctx` is the largest estimated",
        "history sent in a run, after compaction.  `checks` counts structural fidelity checks",
        "passed across all runs; `cited` is the percentage of timeline steps citing a document.",
    ]

    failed = [record for record in records if not record.ok]
    if failed:
        lines += ["", "Runs that failed outright"]
        lines += [f"  {r.profile}/{r.alert}: {r.error}" for r in failed]

    degraded = [record for record in records if record.ok and record.failures]
    if degraded:
        lines += ["", "Fidelity failures"]
        for record in degraded:
            for failure in record.failures:
                lines.append(f"  {record.profile}/{record.alert}: {failure}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _ground_truth(path: Path) -> dict[str, dict[str, Any]]:
    """Scenario id -> its recorded answer, empty when the file is absent."""
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {scenario["id"]: scenario for scenario in payload.get("scenarios", [])}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sec-agent-bench",
        description="Run the alert corpus under every compaction profile and compare the cost.",
    )
    parser.add_argument(
        "alerts",
        nargs="*",
        type=Path,
        default=None,
        help=f"Alert JSON files (default: every *.json in {DEFAULT_ALERTS}).",
    )
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        default=None,
        help="Only run this profile. Repeatable. Default: every profile in the config.",
    )
    parser.add_argument(
        "--compaction-config",
        default=None,
        help="Read profiles from this file instead of ./compaction.toml.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Profile the Δ columns compare against (default: the config's default_profile).",
    )
    parser.add_argument("--model", default=None, help=f"Model (default: {settings.model})")
    parser.add_argument(
        "--effort",
        default=None,
        choices=["low", "medium", "high", "xhigh", "max"],
        help=f"Reasoning depth (default: {settings.effort})",
    )
    parser.add_argument(
        "--es-url", default=None, help=f"Elasticsearch (default: {settings.es_url})"
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Runs per (profile, alert) pair, averaged. Default 1.",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=DEFAULT_GROUND_TRUTH,
        help=f"Answer key for the fidelity checks (default: {DEFAULT_GROUND_TRUTH}).",
    )
    parser.add_argument("--out", type=Path, default=None, help="Write the full records as JSON.")
    parser.add_argument(
        "--quiet", action="store_true", help="Only print the table, not per-run progress."
    )
    return parser.parse_args(argv)


async def _bench(args: argparse.Namespace) -> int:
    config = load_config(args.compaction_config or settings.compaction_config)
    wanted = args.profiles or list(config.profiles)
    profiles = {name: config.get(name) for name in wanted}

    alert_paths = args.alerts or sorted(DEFAULT_ALERTS.glob("*.json"))
    if not alert_paths:
        print(f"Error: no alerts found in {DEFAULT_ALERTS}.", file=sys.stderr)
        return 2

    truths = _ground_truth(args.ground_truth)
    baseline = args.baseline or (
        config.default_profile if config.default_profile in profiles else next(iter(profiles))
    )

    total = len(profiles) * len(alert_paths) * args.repeat
    records: list[RunRecord] = []
    index = 0
    for name, profile in profiles.items():
        for alert_path in alert_paths:
            for repeat in range(args.repeat):
                index += 1
                if not args.quiet:
                    print(
                        f"[{index}/{total}] {name} · {alert_path.stem}"
                        + (f" · run {repeat + 1}" if args.repeat > 1 else ""),
                        file=sys.stderr,
                        flush=True,
                    )
                record = await run_once(
                    profile,
                    alert_path,
                    truths.get(alert_path.stem, {}),
                    model=args.model,
                    effort=args.effort,
                    es_url=args.es_url,
                    repeat=repeat,
                )
                records.append(record)
                if not args.quiet:
                    detail = (
                        record.error
                        if record.error
                        else f"{record.total_tokens:,} tok · "
                        f"{record.checks_passed}/{record.checks_total} checks · {record.verdict}"
                    )
                    print(f"      {record.seconds:.1f}s · {detail}", file=sys.stderr, flush=True)

    summaries = summarize(records, profiles, baseline)
    print()
    print(render(summaries, records, baseline))

    if args.out:
        args.out.write_text(
            json.dumps(
                {
                    "model": args.model or settings.model,
                    "effort": args.effort or settings.effort,
                    "baseline": baseline,
                    "config": str(config.path) if config.path else None,
                    "checks": list(CHECKS),
                    "summaries": [asdict(summary) for summary in summaries],
                    "runs": [asdict(record) for record in records],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Wrote {args.out}")

    return 1 if any(not record.ok for record in records) else 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for `sec-agent-bench`."""
    args = _parse_args(argv)

    variable, key = settings.api_key_for(args.model)
    if variable and not key:
        print(f"Error: {variable} is not set (put it in .env).", file=sys.stderr)
        return 2

    try:
        return asyncio.run(_bench(args))
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
