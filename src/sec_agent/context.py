"""Keeping a long triage run inside the model's context window.

`compact.py` compacts a *single tool result* on its way into the history: it
folds near-identical Elasticsearch documents down to one shape plus its
exceptions, losing nothing. This module compacts *the history itself*, once the
accumulated results no longer fit however well each one was folded.

The two are complementary and the order matters. Folding first means the
history fills far more slowly, so the expensive techniques here — the ones that
drop or paraphrase evidence — are reached late, if at all.

Every technique the harness ships is built here; `settings.compaction` picks the
one that runs, and picks `none` unless asked otherwise. That default is the
point of the paragraph above: with results folded on the way in, a single-alert
triage seldom fills a modern window, and every technique costs something — a
rewritten history busts the provider's prompt cache, a summary spends a model
call. Compaction is what a long investigation turns on, not a tax on every run.

When one is turned on, `tiered` is the one to reach for first: it runs the cheap
deterministic passes and pays for a summary only if they were not enough.
Summarization is deliberately last, because a triage verdict resting on a
paraphrase of the evidence is exactly what `INSTRUCTIONS` forbids.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from pydantic_ai.messages import ModelMessage, ModelRequest, ToolCallPart
from pydantic_ai_harness.compaction import (
    ClampOversizedMessages,
    ClearToolResults,
    CompactionStrategy,
    ContextUsage,
    DeduplicateFileReads,
    FallbackCompaction,
    ReportContextUsage,
    SlidingWindowCompaction,
    SummarizingCompaction,
    TieredCompaction,
    WarnNearLimits,
    compact_now,
    is_pinned,
    pin,
    reinject_pinned,
)

from .settings import settings

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer
    from pydantic_ai.models import Model

    from .agent import TriageDeps

__all__ = [
    "COMPACTION_TECHNIQUES",
    "ContextUsage",
    "build_strategy",
    "capabilities",
    "compact_history",
    "is_pinned",
    "pinned_notes",
    "query_key",
]

# ---------------------------------------------------------------------------
# Tuning that belongs to the techniques rather than to the deployment.
#
# These are properties of *this agent's* tools and prompt, not choices an
# operator makes per run, so they are constants rather than settings.
# ---------------------------------------------------------------------------

CLAMP_PART_TOKENS = 8_000
"""A single message part above this is pathological: no tool here emits one.

The triage tools return folded results measured in hundreds of tokens, and the
model's own turns are short. Only a degenerate generation reaches this, which is
the one failure no other technique can reach — it is the *newest* message.
"""

KEEP_HEAD_CHARS = KEEP_TAIL_CHARS = 2_000
"""Kept from each end of a clamped part. Well under `CLAMP_PART_TOKENS`, so the
clamp always actually shrinks the part it fires on."""

KEEP_TOOL_PAIRS = 3
"""Tool call/result pairs kept verbatim when older results are blanked.

Three covers the query the model is reasoning about plus the two it is
comparing against; everything older it can re-run, because these tools are
read-only and the data behind them does not move.
"""

MIN_CLEAR_TOKENS = 1_000
"""Don't blank tool results for less than this.

Rewriting history invalidates the provider's prompt cache from the edit point
on, and the next request pays a cache write. Reclaiming a few hundred tokens is
not worth that; escalating to the next tier is.
"""

KEEP_MESSAGES = 20
"""Recent messages kept verbatim behind a summary or a sliding window."""

KEEP_TOKENS = 20_000
"""Tail budget for the deterministic last resort, when even summarizing failed."""

NEVER_CLEAR = frozenset({"entity_baseline"})
"""Tool results that are never blanked.

A baseline is the reference every later judgement is measured against — "is this
unusual for this account?" is the question that separates an incident from
routine activity. It is also the cheapest result the agent produces: a single
flat dict of counts. Clearing it would save almost nothing and force the model
to re-establish the very thing it is comparing to.
"""

QUERYING_TOOLS = frozenset({"search_events", "aggregate_events", "entity_baseline"})
"""Tools whose results are a pure function of their arguments.

All three are read-only queries against a fixed index over a fixed time range,
so re-running one with identical arguments cannot return anything new. That is
what makes deduplicating them lossless.
"""

SUPERSEDED = "[superseded: this exact query was re-run later; read the newer result]"

# A triage summary has to survive being the only record of the evidence. The
# default harness prompt summarises a coding session; this one preserves the
# things a verdict is later challenged on — document ids, measured counts, and
# which claims were checked against the logs rather than assumed.
SUMMARY_PROMPT = """\
You are compacting the working notes of a SOC analyst mid-investigation. The
conversation below will be replaced by your summary, so anything you leave out
is gone: the analyst cannot re-read it and must be able to finish the triage,
and defend the verdict, from your summary alone.

Write under these exact headings, omitting one only if it has no content:

## Alert
The alert under investigation and the claim it makes.

## Established
What the logs actually showed, as measurements, not impressions — counts,
outcomes, timestamps, entities. Quote every supporting document `_id` verbatim.
An `_id` you drop can never be cited again.

## Queries run
Each query already executed, what it was meant to establish, and what came back.
This is what stops the analyst re-running work and what fills `queries_run`.

## Baselines
What each entity normally looks like, and how the alert-window activity differs.

## Ruled out
Hypotheses the evidence has already killed, and the evidence that killed them.

## Open questions
What is still unresolved, and the query that would resolve it.

Report findings, not a replay of actions. Never upgrade a measurement into a
conclusion the analyst had not yet drawn. Respond ONLY with the summary — no
preamble, no markdown fences.

<messages>
{messages}
</messages>
"""

SUMMARY_INSTRUCTIONS = (
    "You compact a security investigation's working notes. You preserve evidence "
    "verbatim — document ids, counts, timestamps — and never infer beyond it."
)


# ---------------------------------------------------------------------------
# Deduplication key
# ---------------------------------------------------------------------------


def query_key(call: ToolCallPart) -> str | None:
    """Identify a repeated query, or `None` if this call is not one.

    `DeduplicateFileReads` ships no default key because guessing one risks
    dropping live data. Here the answer is exact: the triage tools are read-only
    queries over an index that does not change mid-run, so two calls with the
    same arguments have the same result and the older one is pure restatement.

    Arguments left unset are dropped before hashing, since the tools treat an
    omitted `start` and an explicit `null` identically. Two calls that differ
    only by an explicitly-passed default hash apart and are simply not
    deduplicated — the safe direction to be wrong in.
    """
    if call.tool_name not in QUERYING_TOOLS:
        return None

    args: Any = call.args
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            return None
    if not isinstance(args, dict):
        return None

    supplied = {key: value for key, value in args.items() if value is not None}
    return f"{call.tool_name}:{json.dumps(supplied, sort_keys=True, default=str)}"


# ---------------------------------------------------------------------------
# The techniques
#
# Each builder takes the fraction of the context window it should act at, so one
# setting is correct on every model: 0.75 is 150k tokens on a 200k model and
# 750k on a 1M one. Only `clamp` ignores it — it triggers per *part*, because
# the failure it exists for is one oversized part rather than a large total.
# ---------------------------------------------------------------------------


def _override() -> dict[str, Any]:
    """The window override, when one is configured, and nothing otherwise."""
    return {"context_window": settings.context_window} if settings.context_window else {}


def _window(fraction: float) -> dict[str, Any]:
    """Trigger arguments shared by every size-based technique."""
    return {"max_fraction": fraction, **_override()}


def _clamp(_fraction: float) -> ClampOversizedMessages:
    """Head/tail-truncate one runaway part, in place.

    The only builder that ignores the fraction: it triggers per *part*, since
    the failure it exists for is one oversized part, not a large total.
    """
    return ClampOversizedMessages(
        max_part_tokens=CLAMP_PART_TOKENS,
        keep_head_chars=KEEP_HEAD_CHARS,
        keep_tail_chars=KEEP_TAIL_CHARS,
        # A runaway tool call here would be a giant `filters` dict; the call has
        # already run, so shrinking the history's copy of it costs nothing.
        clamp_tool_call_args=True,
    )


def _dedupe(fraction: float) -> DeduplicateFileReads:
    """Blank every query result superseded by an identical later query."""
    return DeduplicateFileReads(
        file_key=query_key,
        placeholder=SUPERSEDED,
        **_window(fraction),
    )


def _clear_tool_results(fraction: float) -> ClearToolResults:
    """Blank the content of older tool results, keeping the recent pairs."""
    return ClearToolResults(
        keep_pairs=KEEP_TOOL_PAIRS,
        placeholder="[result cleared to save context; re-run the query if you still need it]",
        exclude_tools=NEVER_CLEAR,
        # The *arguments* stay. Knowing which query was cleared is what lets the
        # model decide whether it needs to run it again.
        clear_tool_inputs=False,
        min_clear_tokens=MIN_CLEAR_TOKENS,
        **_window(fraction),
    )


def _sliding_window(fraction: float) -> SlidingWindowCompaction:
    """Drop the oldest messages outright, keeping a recent tail."""
    return SlidingWindowCompaction(
        keep_messages=KEEP_MESSAGES,
        # Without this the model loses the alert it was asked to triage.
        preserve_first_user_message=True,
        **_window(fraction),
    )


def _summarize(fraction: float) -> SummarizingCompaction:
    """Replace older messages with a summary written by the model itself."""
    return SummarizingCompaction(
        # `None` inherits the triage model, API key and all.
        model=None,
        keep_messages=KEEP_MESSAGES,
        summary_prompt=SUMMARY_PROMPT,
        instructions=SUMMARY_INSTRUCTIONS,
        # Later compactions revise the standing summary rather than rewriting it
        # from scratch, so evidence does not degrade through repeated paraphrase.
        incremental=True,
        preserve_first_user_message=True,
        **_window(fraction),
    )


def _fallback(fraction: float) -> TieredCompaction:
    """Summarize, and fall back to dropping messages if the summary call fails.

    `FallbackCompaction` advances only on an exception and has no trigger of its
    own, so it cannot be a capability directly; a single-tier `TieredCompaction`
    gives it one. The point is that a provider error during compaction degrades
    the run to a cheaper history instead of ending it.
    """
    return TieredCompaction(
        tiers=[
            FallbackCompaction(
                fallback_chain=[
                    # Triggers are not consulted when a composing strategy calls
                    # `compact` directly, so `max_messages=1` just means "valid".
                    SummarizingCompaction(
                        max_messages=1,
                        keep_tokens=KEEP_TOKENS,
                        summary_prompt=SUMMARY_PROMPT,
                        instructions=SUMMARY_INSTRUCTIONS,
                    ),
                    SlidingWindowCompaction(max_messages=1, keep_tokens=KEEP_TOKENS),
                ]
            )
        ],
        target_fraction=fraction,
        **_override(),
    )


def _tiered(fraction: float) -> TieredCompaction:
    """Escalate: cheap deterministic passes first, a summary only if still over.

    The order is deliberate. Clamping and deduplicating are lossless, clearing
    is recoverable (the tools are read-only, so any cleared result can be
    re-fetched), and only the last tier paraphrases evidence — and it degrades to
    a plain sliding window rather than failing the run if the summary call errors.
    """
    return TieredCompaction(
        tiers=[
            _clamp(fraction),
            _dedupe(fraction),
            _clear_tool_results(fraction),
            FallbackCompaction(
                fallback_chain=[
                    _summarize(fraction),
                    SlidingWindowCompaction(max_messages=1, keep_tokens=KEEP_TOKENS),
                ]
            ),
        ],
        target_fraction=fraction,
        **_override(),
    )


def _warn(fraction: float) -> WarnNearLimits:
    """Tell the model it is running out of room, and let it wrap up itself.

    The only technique that adds nothing and removes nothing: an agent that
    knows it has two requests left can write the verdict it has, which beats
    having its evidence rewritten underneath it.
    """
    limits: dict[str, Any] = {"max_context_fraction": fraction}
    if settings.context_window:
        limits["context_window"] = settings.context_window
    return WarnNearLimits(
        max_iterations=MAX_ITERATIONS,
        critical_remaining_iterations=3,
        warning_threshold=0.7,
        **limits,
    )


MAX_ITERATIONS = 40
"""Model requests a triage run is expected to need. Warned about, never enforced."""

COMPACTION_TECHNIQUES: dict[str, Callable[[float], Any]] = {
    "tiered": _tiered,
    "clamp": _clamp,
    "dedupe": _dedupe,
    "clear-tools": _clear_tool_results,
    "sliding": _sliding_window,
    "summarize": _summarize,
    "fallback": _fallback,
    "warn": _warn,
}
"""Every technique, by the name `settings.compaction` selects it with."""


def build_strategy(technique: str | None = None, fraction: float | None = None) -> Any:
    """Build one technique by name. `none` builds nothing."""
    name = (technique or settings.compaction).strip().lower()
    if name in ("none", "off", ""):
        return None
    try:
        build = COMPACTION_TECHNIQUES[name]
    except KeyError:
        raise ValueError(
            f"Unknown compaction technique {name!r}. "
            f"Choose one of: {', '.join(sorted(COMPACTION_TECHNIQUES))}, none."
        ) from None
    return build(fraction if fraction is not None else settings.context_fraction)


def capabilities(
    *,
    technique: str | None = None,
    on_usage: Callable[[ContextUsage], None] | None = None,
) -> list[Any]:
    """The capability list for `build_agent`: the chosen technique, plus a gauge.

    `ReportContextUsage` is not a compaction technique — it never edits history,
    it only reports. It is registered *after* the technique so a reading
    reflects the corrected history rather than what triggered the compaction.
    """
    chosen = build_strategy(technique)
    return [c for c in (chosen, _reporter(on_usage)) if c is not None]


def _reporter(
    on_usage: Callable[[ContextUsage], None] | None,
) -> ReportContextUsage[TriageDeps] | None:
    if on_usage is None:
        return None
    window = {"context_window": settings.context_window} if settings.context_window else {}
    return ReportContextUsage(on_usage=on_usage, **window)


# ---------------------------------------------------------------------------
# Pinning, and compacting outside a run
# ---------------------------------------------------------------------------


def pinned_notes(notes: Sequence[str]) -> list[ModelMessage]:
    """Seed a run's history with standing direction no compaction may discard.

    Everything else in the history is fair game: results get blanked, messages
    get dropped, evidence gets paraphrased into a summary. A pinned note is
    carried through verbatim by every technique, and re-injected if one would
    have dropped it — which is what makes it the right home for an analyst's
    standing instruction ("185.220.101.44 is a known scanner; I care about the
    successful logins"), the one piece of context that must not be reworded
    three compactions into a long run.
    """
    if not notes:
        return []
    return [ModelRequest(parts=[pin(note) for note in notes])]


async def compact_history(
    history: Sequence[ModelMessage],
    *,
    model: Model | str,
    focus: str | None = None,
    strategy: CompactionStrategy[Any] | None = None,
    tracer: Tracer | None = None,
) -> list[ModelMessage]:
    """Compact a finished run's history, with no run in progress.

    A strategy's `compact` wants a `RunContext`, which an application holding a
    conversation *between* runs does not have — the case a user-invoked
    `/compact` is. `compact_now` builds a throwaway one.

    `focus` steers the techniques that write prose ("the successful logins, not
    the failed sweep"); the ones that drop or blank by rule ignore it. Pins are
    re-injected afterwards: the shipped techniques preserve them already, but a
    caller-supplied `strategy` need not, and doing it here is a no-op when
    nothing was lost.
    """
    chosen = strategy if strategy is not None else build_strategy()
    if chosen is None:
        return list(history)
    compacted = await compact_now(
        chosen, list(history), model=model, focus=focus, tracer=tracer
    )
    return reinject_pinned(history, compacted)
