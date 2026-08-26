"""Definition of the security analysis agent."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import requests
from pydantic import AwareDatetime, BaseModel, Field, IPvAnyAddress, model_validator
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.models import Model, infer_model
from pydantic_ai.settings import ModelSettings

from .compact import cap_histogram, fold_events
from .compaction import CompactionProfile, resolve_profile
from .settings import provider_of, settings

Severity = Literal["info", "low", "medium", "high", "critical"]

# ---------------------------------------------------------------------------
# Alert triage models
#
# The input contract for the triage agent: what fired, on whom, when, and with
# what evidence. The analysis itself is the agent's job, not the alert's.
# ---------------------------------------------------------------------------


class DataSource(BaseModel):
    """Where the agent should look, so no index name is hardcoded in the agent."""

    index: str = "auth-logs"
    timestamp_field: str = "@timestamp"
    ecs_version: str = "8.11"


class TimeWindow(BaseModel):
    """When the alert fired, and how far back "normal" should be measured."""

    start: AwareDatetime
    end: AwareDatetime
    baseline_days: int = Field(
        default=7, ge=0, description="How many days of history define normal for these entities"
    )

    @property
    def baseline_start(self) -> datetime:
        """Start of the baseline period used to judge what is unusual."""
        return self.start - timedelta(days=self.baseline_days)

    @model_validator(mode="after")
    def _check_order(self) -> TimeWindow:
        if self.end < self.start:
            raise ValueError("window.end cannot be before window.start")
        return self


class Entities(BaseModel):
    """The pivots an investigation hangs off. Names mirror the ECS fields."""

    users: list[str] = Field(default_factory=list)
    source_ips: list[IPvAnyAddress] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)

    def pivots(self) -> list[tuple[str, str]]:
        """Return `(elasticsearch field, value)` pairs ready to drop into a term query."""
        return (
            [("user.name", u) for u in self.users]
            + [("source.ip", str(ip)) for ip in self.source_ips]
            + [("host.name", h) for h in self.hosts]
            + [("service.name", s) for s in self.services]
        )


class Detection(BaseModel):
    """The rule that fired. The agent verifies these numbers rather than trusting them."""

    rule_id: str
    rule_name: str
    rule_type: Literal["threshold", "new_terms", "correlation", "sequence", "ml", "manual"]
    query: str | None = Field(default=None, description="The query that fired, verbatim")
    query_language: Literal["kql", "lucene", "eql", "dsl"] | None = None
    signals: dict[str, float | int | str] = Field(
        default_factory=dict, description="Measured values that tripped the rule"
    )
    threshold: dict[str, float | int | str] = Field(
        default_factory=dict, description="The values the rule compared against"
    )
    mitre: list[str] = Field(
        default_factory=list, description="ATT&CK technique ids, e.g. T1110.001"
    )


class Evidence(BaseModel):
    """A small slice of the matching documents, so the first query is not blind."""

    index: str
    doc_ids: list[str] = Field(default_factory=list)
    sample: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    total_matched: int | None = None


class EntityContext(BaseModel):
    """Enrichment. This is usually what decides true positive versus false positive."""

    user_is_privileged: bool | None = None
    user_is_service_account: bool | None = None
    user_department: str | None = None
    asset_criticality: Literal["low", "medium", "high"] | None = None
    known_corp_ranges: list[str] = Field(default_factory=list)
    notes: str | None = None


class Alert(BaseModel):
    """A single alert handed to the triage agent."""

    schema_version: Literal["1.0"] = "1.0"
    alert_id: str
    dedup_key: str = Field(
        description="rule_id + entity + time bucket, so the same event does not reopen"
    )
    created_at: AwareDatetime
    producer: str = Field(description="elastalert | kibana-rule | sigma | manual")

    title: str
    description: str = ""
    severity: Severity = Field(description="The detector's claim; the agent decides its own")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_score: int = Field(default=50, ge=0, le=100)

    data_source: DataSource = Field(default_factory=DataSource)
    window: TimeWindow
    entities: Entities
    detection: Detection
    evidence: Evidence | None = None
    context: EntityContext = Field(default_factory=EntityContext)

    related_alert_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, description="Original payload, lossless")


class TimelineEvent(BaseModel):
    """One reconstructed step of what happened."""

    timestamp: AwareDatetime
    description: str
    doc_ids: list[str] = Field(default_factory=list, description="Documents backing this step")


class ExecutedQuery(BaseModel):
    """A query the agent ran, kept so its reasoning can be audited."""

    purpose: str = Field(description="What the agent was trying to establish")
    index: str
    query: str
    hits: int


Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "inconclusive"]


class TriageVerdict(BaseModel):
    """The triage agent's structured output."""

    alert_id: str
    verdict: Verdict
    severity: Severity = Field(description="The agent's own rating, independent of the detector")
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(description="What happened, in two or three sentences")
    timeline: list[TimelineEvent] = Field(default_factory=list)
    attack_pattern: str | None = Field(
        default=None, description="e.g. 'credential brute force, successful'"
    )
    scope: Entities = Field(
        default_factory=Entities, description="Affected entities; may be wider than the alert's"
    )
    queries_run: list[ExecutedQuery] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    escalate: bool = False


# ---------------------------------------------------------------------------
# Dependencies: the Elasticsearch connection and the guardrails around it
# ---------------------------------------------------------------------------


@dataclass
class TriageDeps:
    """Dependencies carried through a single triage run."""

    alert: Alert
    """The alert under investigation. Rendered into the prompt by `build_agent`."""

    es_url: str = field(default_factory=lambda: settings.es_url)
    allowed_indices: tuple[str, ...] = ("auth-logs",)
    """Indices the tools may query. Anything else is refused."""

    max_hits: int = 50
    max_buckets: int = 50
    max_time_slots: int = 120
    """Total date-histogram slots returned, shared out across the groups asked for.

    A seven-day hourly breakdown over ten groups is some 1,700 mostly-idle slots.
    The budget is deliberately tight: a histogram is for reading the *shape* of
    activity, and a model that needs more resolution than this should narrow the
    window or coarsen the interval rather than page through idle buckets.
    """

    timeout_seconds: float = 30.0

    source_excludes: tuple[str, ...] = ("labels.scenario", "event.id", "source.port")
    """Fields Elasticsearch is told never to return.

    `labels.scenario` is the lab's answer key; letting the model read it would
    turn every evaluation into a tautology.

    `event.id` and `source.port` are per-document noise: both differ on every
    single event, so they survive every attempt to fold a result set down while
    telling a triage analyst nothing — `_id` already identifies a document, and
    an ephemeral client port has no bearing on whether a login was legitimate.
    """

    def index_for(self, index: str | None) -> str:
        """Validate `index` against the allowlist, defaulting to the alert's index."""
        candidate = index or self.alert.data_source.index
        if candidate not in self.allowed_indices:
            raise ModelRetry(
                f"{candidate!r} is not queryable. Allowed indices: {list(self.allowed_indices)}."
            )
        return candidate

    def search(self, body: dict[str, Any], index: str | None = None) -> dict[str, Any]:
        """Run a `_search` request and return the parsed response."""
        target = self.index_for(index)
        url = f"{self.es_url.rstrip('/')}/{target}/_search"
        try:
            response = requests.post(url, json=body, timeout=self.timeout_seconds)
        except requests.RequestException as exc:
            raise RuntimeError(f"Elasticsearch at {self.es_url} is unreachable: {exc}") from exc

        if response.status_code >= 400:
            # A malformed query is something the model can fix on its own.
            raise ModelRetry(
                f"Elasticsearch rejected the query ({response.status_code}): {response.text[:600]}"
            )
        return response.json()


def _time_filter(deps: TriageDeps, start: str | None, end: str | None) -> dict[str, Any]:
    """Build the range clause every query is confined to."""
    window = deps.alert.window
    return {
        "range": {
            deps.alert.data_source.timestamp_field: {
                "gte": start or window.start.isoformat(),
                "lte": end or window.end.isoformat(),
            }
        }
    }


def _term_clauses(filters: dict[str, str] | None) -> list[dict[str, Any]]:
    """Turn `{"user.name": "kadmin"}` into Elasticsearch term clauses."""
    return [{"term": {key: value}} for key, value in (filters or {}).items()]


# System Instructions
INSTRUCTIONS = """\
You are a SOC analyst triaging a single authentication alert. The alert that
fired is given below; the authentication logs live in Elasticsearch and you
reach them through your tools.

How to work:
- TREAT the alert as a claim, not as a fact. Re-measure the numbers in
  `detection.signals` yourself before you rely on them.
- The alert's own window is only the starting point. Always ask what happened
  just before and just after it, and what this user, IP or host normally looks
  like — `entity_baseline` exists for exactly that. An event is only suspicious
  relative to a baseline.
- Answer the questions the alert does not: did any attempt actually succeed,
  did the same source touch other accounts, did the account do anything after
  the login.
- Base every statement on documents you retrieved. Cite them by `_id` in the
  timeline. If the data does not settle a question, say so and return
  `inconclusive` rather than guessing.
- Distinguish `false_positive` (the activity did not happen as described) from
  `benign_true_positive` (it happened, but it is legitimate — a scheduled job,
  a known corporate range, an expected admin task).
- Set `severity` and `confidence` from what you found, not from what the
  detector claimed. They may disagree with the alert; that is the point.
- Record every query you ran in `queries_run`, with what it was meant to
  establish. An unauditable conclusion is worthless.
- Keep `recommended_actions` concrete and few: what a responder should do next.
"""


# ---------------------------------------------------------------------------
# Model wiring
#
# The model is chosen by `SEC_AGENT_MODEL`, so the same agent runs against
# Anthropic or against anything OpenRouter fronts. Only the reasoning knob
# differs between them, and that is all these two helpers exist to hide.
# ---------------------------------------------------------------------------

# `max` has no equivalent outside Anthropic; `xhigh` is the closest thing.
GENERIC_THINKING = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "xhigh",
    "max": "xhigh",
}


def resolve_model(name: str) -> Model:
    """Build the model named by `provider:model`, holding its own API key.

    `infer_model` would look the key up in the process environment, which misses
    one that lives only in `.env`, so the key is passed in explicitly.
    """
    variable, key = settings.api_key_for(name)
    if variable is None or key is None:
        # Not a provider we manage a key for: let pydantic-ai sort it out.
        return infer_model(name)

    provider_name = provider_of(name)
    _, _, model_name = name.partition(":")

    if provider_name == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(model_name, provider=AnthropicProvider(api_key=key))

    from pydantic_ai.models.openrouter import OpenRouterModel
    from pydantic_ai.providers.openrouter import OpenRouterProvider

    return OpenRouterModel(model_name, provider=OpenRouterProvider(api_key=key))


def model_settings_for(model: Model, effort: str) -> ModelSettings:
    """Reasoning settings in whichever dialect this model speaks."""
    if model.system == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        return AnthropicModelSettings(
            max_tokens=settings.max_tokens,
            # Adaptive thinking: the model decides how much to think.
            anthropic_thinking={"type": "adaptive"},
            anthropic_effort=effort,
        )

    # Everywhere else, the unified `thinking` level is translated by the
    # provider — OpenRouter turns it into a `reasoning.effort` request.
    return ModelSettings(
        max_tokens=settings.max_tokens,
        thinking=GENERIC_THINKING.get(effort, "medium"),
    )


def build_agent(
    *,
    model: str | Model | None = None,
    effort: str | None = None,
    compaction: str | CompactionProfile | None = None,
    extra_capabilities: Sequence[AbstractCapability[TriageDeps]] = (),
) -> Agent[TriageDeps, TriageVerdict]:
    """Build the triage agent and register its tools.

    Args:
        model: `provider:model`, or an already-built model. Defaults to `SEC_AGENT_MODEL`.
        effort: Reasoning depth. Defaults to `SEC_AGENT_EFFORT`.
        compaction: Message-history compaction profile, by name or already resolved.
            Defaults to `SEC_AGENT_COMPACTION`, then to the config's own default.
        extra_capabilities: Registered after the profile's, so an observer such as
            `ReportContextUsage` sees the history the profile leaves behind.
    """
    resolved = model if isinstance(model, Model) else resolve_model(model or settings.model)
    profile = (
        compaction
        if isinstance(compaction, CompactionProfile)
        else resolve_profile(compaction or settings.compaction, settings.compaction_config)
    )
    agent = Agent(
        resolved,
        deps_type=TriageDeps,
        output_type=TriageVerdict,
        instructions=INSTRUCTIONS,
        retries=settings.retries,
        model_settings=model_settings_for(resolved, effort or settings.effort),
        capabilities=[*profile.capabilities(), *extra_capabilities],
    )

    @agent.instructions
    def describe_alert(ctx: RunContext[TriageDeps]) -> str:
        """Put the alert itself, and the shape of the data, in front of the model."""
        alert = ctx.deps.alert
        return (
            f"## Alert under investigation\n"
            f"{alert.model_dump_json(indent=2, exclude={'raw'})}\n\n"
            f"## Data\n"
            f"Index `{alert.data_source.index}`, ECS {alert.data_source.ecs_version}, "
            f"time field `{alert.data_source.timestamp_field}`.\n"
            f"Useful fields: event.action, event.outcome, event.reason, user.name, "
            f"user.roles, source.ip, source.geo.country_iso_code, source.as.organization.name, "
            f"host.name, service.name, auth.method, auth.mfa_used, user_agent.name.\n"
            f"All of these are keyword fields, so tool filters match them exactly.\n"
            f"Baseline period for this alert: {alert.window.baseline_start.isoformat()} to "
            f"{alert.window.start.isoformat()}.\n"
            f"Copy `{alert.alert_id}` into the `alert_id` field of your verdict."
        )

    @agent.tool
    def search_events(
        ctx: RunContext[TriageDeps],
        filters: dict[str, str] | None = None,
        start: str | None = None,
        end: str | None = None,
        size: int = 20,
        newest_first: bool = False,
    ) -> dict[str, Any]:
        """Fetch authentication events, newest or oldest first.

        Results are folded: fields shared by the matching documents are stated
        once under `shape`, and any document departing from them is listed in
        `outliers` with the fields it departs on. Read `legend` before the data.
        Nothing is dropped, so a lone success among failures shows up in
        `outliers` rather than being lost among them.

        Args:
            filters: Exact-match field/value pairs, e.g. `{"user.name": "kadmin"}`.
            start: ISO-8601 lower bound. Defaults to the start of the alert window.
            end: ISO-8601 upper bound. Defaults to the end of the alert window.
            size: How many documents to return.
            newest_first: Sort descending by timestamp instead of ascending.
        """
        deps = ctx.deps
        timestamp_field = deps.alert.data_source.timestamp_field
        body = {
            "size": min(size, deps.max_hits),
            "query": {
                "bool": {"filter": [*_term_clauses(filters), _time_filter(deps, start, end)]}
            },
            "sort": [{timestamp_field: "desc" if newest_first else "asc"}],
            "_source": {"excludes": list(deps.source_excludes)},
            "track_total_hits": True,
        }
        response = deps.search(body)
        return fold_events(
            [{"_id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]],
            timestamp_field=timestamp_field,
            total_matched=response["hits"]["total"]["value"],
        )

    @agent.tool
    def aggregate_events(
        ctx: RunContext[TriageDeps],
        group_by: str,
        filters: dict[str, str] | None = None,
        start: str | None = None,
        end: str | None = None,
        size: int = 10,
        distinct_field: str | None = None,
        interval: str | None = None,
    ) -> dict[str, Any]:
        """Count events grouped by a field. Use this before reading raw documents.

        Args:
            group_by: Field to group on, e.g. `user.name`, `source.ip`, `event.outcome`.
            filters: Exact-match field/value pairs applied before grouping.
            start: ISO-8601 lower bound. Defaults to the start of the alert window.
            end: ISO-8601 upper bound. Defaults to the end of the alert window.
            size: How many groups to return, largest first.
            distinct_field: Also count distinct values of this field per group,
                e.g. `user.name` to see how many accounts one IP touched.
            interval: Also break each group down over time, e.g. `1m`, `1h`, `1d`.
        """
        deps = ctx.deps
        grouping: dict[str, Any] = {
            "terms": {"field": group_by, "size": min(size, deps.max_buckets)}
        }
        sub_aggs: dict[str, Any] = {}
        if distinct_field:
            sub_aggs["distinct"] = {"cardinality": {"field": distinct_field}}
        if interval:
            sub_aggs["over_time"] = {
                "date_histogram": {
                    "field": deps.alert.data_source.timestamp_field,
                    "fixed_interval": interval,
                    "min_doc_count": 1,
                }
            }
        if sub_aggs:
            grouping["aggs"] = sub_aggs

        body = {
            "size": 0,
            "query": {
                "bool": {"filter": [*_term_clauses(filters), _time_filter(deps, start, end)]}
            },
            "aggs": {"grouped": grouping},
            "track_total_hits": True,
        }
        response = deps.search(body)

        grouped = response["aggregations"]["grouped"]["buckets"]
        # Share the slot budget out, but never leave a group too thin to read.
        slot_budget = max(8, deps.max_time_slots // max(len(grouped), 1))

        buckets = []
        for bucket in grouped:
            entry: dict[str, Any] = {"key": bucket["key"], "count": bucket["doc_count"]}
            if distinct_field:
                entry[f"distinct_{distinct_field}"] = bucket["distinct"]["value"]
            if interval:
                slots, note = cap_histogram(
                    [
                        {"at": slot["key_as_string"], "count": slot["doc_count"]}
                        for slot in bucket["over_time"]["buckets"]
                    ],
                    slot_budget,
                )
                entry["over_time"] = slots
                if note:
                    entry["over_time_note"] = note
            buckets.append(entry)

        return {
            "total_events": response["hits"]["total"]["value"],
            "group_by": group_by,
            "buckets": buckets,
        }

    @agent.tool
    def entity_baseline(
        ctx: RunContext[TriageDeps],
        field_name: str,
        value: str,
        days: int | None = None,
    ) -> dict[str, Any]:
        """Profile what one entity normally looks like, before the alert window.

        Answers "is this unusual for them?" — the question that separates a real
        incident from routine activity.

        Args:
            field_name: The entity's field, e.g. `user.name`, `source.ip`, `host.name`.
            value: The entity's value, e.g. `kadmin`.
            days: How far back to look. Defaults to the alert's baseline period.
        """
        deps = ctx.deps
        window = deps.alert.window
        timestamp_field = deps.alert.data_source.timestamp_field
        start = window.start - timedelta(days=days) if days else window.baseline_start

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {field_name: value}},
                        {
                            "range": {
                                timestamp_field: {
                                    "gte": start.isoformat(),
                                    "lt": window.start.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "first_seen": {"min": {"field": timestamp_field}},
                "last_seen": {"max": {"field": timestamp_field}},
                "outcomes": {"terms": {"field": "event.outcome", "size": 5}},
                "source_ips": {"terms": {"field": "source.ip", "size": 10}},
                "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 10}},
                "hosts": {"terms": {"field": "host.name", "size": 10}},
                "services": {"terms": {"field": "service.name", "size": 10}},
                "auth_methods": {"terms": {"field": "auth.method", "size": 5}},
                "mfa_used": {"terms": {"field": "auth.mfa_used", "size": 2}},
                "distinct_users": {"cardinality": {"field": "user.name"}},
                "by_hour": {
                    "date_histogram": {
                        "field": timestamp_field,
                        "calendar_interval": "hour",
                        "min_doc_count": 1,
                    }
                },
            },
            "track_total_hits": True,
        }
        response = deps.search(body)
        aggs = response["aggregations"]

        def terms(name: str) -> dict[str, int]:
            return {str(b["key"]): b["doc_count"] for b in aggs[name]["buckets"]}

        # Fold the histogram into a 24-hour profile: the cheapest way to see
        # that an account only ever logs in during office hours.
        hours = [0] * 24
        for bucket in aggs["by_hour"]["buckets"]:
            hours[datetime.fromtimestamp(bucket["key"] / 1000, tz=UTC).hour] += bucket["doc_count"]

        total = response["hits"]["total"]["value"]
        return {
            "entity": {field_name: value},
            "period": {"start": start.isoformat(), "end": window.start.isoformat()},
            "total_events": total,
            "note": "No activity at all in this period." if total == 0 else None,
            # `min`/`max` over an empty result set carry no `value_as_string` at all.
            "first_seen": aggs["first_seen"].get("value_as_string"),
            "last_seen": aggs["last_seen"].get("value_as_string"),
            "outcomes": terms("outcomes"),
            "source_ips": terms("source_ips"),
            "countries": terms("countries"),
            "hosts": terms("hosts"),
            "services": terms("services"),
            "auth_methods": terms("auth_methods"),
            "mfa_used": terms("mfa_used"),
            "distinct_users": aggs["distinct_users"]["value"],
            "events_by_hour_utc": hours,
        }

    return agent
