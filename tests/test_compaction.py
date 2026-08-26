"""Tests for compaction profiles and the benchmark's fidelity checks.

No API key and no Elasticsearch: the config loader is pure, and the checks read
an already-built `TriageVerdict`.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sec_agent.agent import Alert, Entities, TimelineEvent, TriageVerdict
from sec_agent.bench import CHECKS, grade
from sec_agent.compaction import (
    CompactionProfile,
    build_strategy,
    load_config,
    resolve_profile,
)

CONFIG = """\
default_profile = "none"

[profiles.none]
description = "Nothing."
strategies = []

[[profiles.clearing.strategies]]
type = "ClearToolResults"
max_tokens = 5000
keep_pairs = 1

[[profiles.escalating.strategies]]
type = "TieredCompaction"
target_tokens = 5000

  [[profiles.escalating.strategies.tiers]]
  type = "ClampOversizedMessages"
  max_part_tokens = 500

  [[profiles.escalating.strategies.tiers]]
  type = "SummarizingCompaction"
  max_messages = 1
  keep_messages = 4
"""


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "compaction.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_profiles_load_with_their_default(config_file):
    config = load_config(config_file)
    assert set(config.profiles) == {"none", "clearing", "escalating"}
    assert config.get(None).name == "none"
    assert config.get("clearing").description == ""


def test_the_shipped_config_builds_every_profile():
    """Every profile in the repository's own compaction.toml has to instantiate."""
    config = load_config()
    assert config.profiles, "compaction.toml declares no profiles"
    for name, profile in config.profiles.items():
        capabilities = profile.capabilities()
        assert len(capabilities) == len(profile.strategies), name


def test_baseline_profile_registers_no_capabilities(config_file):
    assert resolve_profile("none", config_file).capabilities() == []


def test_nested_tiers_are_built_recursively(config_file):
    (tiered,) = resolve_profile("escalating", config_file).capabilities()
    assert type(tiered).__name__ == "TieredCompaction"
    assert [type(tier).__name__ for tier in tiered.tiers] == [
        "ClampOversizedMessages",
        "SummarizingCompaction",
    ]


def test_summarizing_tier_is_reported_as_llm_backed(config_file):
    """A summarizer nested inside a tier still costs a model call."""
    assert resolve_profile("escalating", config_file).uses_llm is True
    assert resolve_profile("clearing", config_file).uses_llm is False


def test_named_file_key_resolves_to_a_callable():
    strategy = build_strategy({"type": "DeduplicateFileReads", "file_key": "tool_call"})
    assert callable(strategy.file_key)


def test_unknown_profile_names_the_alternatives(config_file):
    with pytest.raises(ValueError, match="clearing"):
        resolve_profile("nope", config_file)


def test_unknown_strategy_is_refused():
    with pytest.raises(ValueError, match="Unknown compaction strategy"):
        build_strategy({"type": "MakeItSmaller"})


def test_bad_strategy_option_names_the_strategy():
    with pytest.raises(ValueError, match="ClearToolResults rejected"):
        build_strategy({"type": "ClearToolResults", "keep_pears": 3})


def test_missing_config_falls_back_to_no_compaction(tmp_path):
    config = load_config(tmp_path / "absent.toml")
    assert config.get(None).capabilities() == []


def test_summary_lists_the_strategies(config_file):
    assert resolve_profile("escalating", config_file).summary() == "TieredCompaction"
    assert CompactionProfile(name="x").summary() == "(none)"


# ---------------------------------------------------------------------------
# Fidelity checks
# ---------------------------------------------------------------------------


ALERT = Alert.model_validate(
    {
        "alert_id": "AL-1",
        "dedup_key": "k",
        "created_at": "2026-08-23T02:20:00Z",
        "producer": "manual",
        "title": "Brute force",
        "severity": "high",
        "window": {"start": "2026-08-23T02:14:00Z", "end": "2026-08-23T02:17:00Z"},
        "entities": {"users": ["mehmet.kaya"], "source_ips": ["185.220.101.44"]},
        "detection": {"rule_id": "R1", "rule_name": "Brute force", "rule_type": "threshold"},
    }
)

TRUTH = {"id": "S1_brute_force", "user": "mehmet.kaya", "source_ip": "185.220.101.44"}


def _verdict(**overrides) -> TriageVerdict:
    payload = {
        "alert_id": "AL-1",
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 0.9,
        "summary": "Password guessing that succeeded.",
        "timeline": [
            TimelineEvent(
                timestamp=datetime(2026, 8, 23, 2, 17, tzinfo=UTC),
                description="Successful login",
                doc_ids=["IgXSOKAB"],
            )
        ],
        "scope": Entities(users=["mehmet.kaya"], source_ips=["185.220.101.44"]),
        "queries_run": [
            {"purpose": "count outcomes", "index": "auth-logs", "query": "...", "hits": 214}
        ],
    }
    return TriageVerdict.model_validate(payload | overrides)


def test_a_grounded_verdict_passes_every_check():
    passed, failures = grade(_verdict(), TRUTH, ALERT)
    assert failures == []
    assert passed == len(CHECKS)


def test_an_uncited_timeline_fails_grounding():
    verdict = _verdict(
        timeline=[
            TimelineEvent(
                timestamp=datetime(2026, 8, 23, 2, 17, tzinfo=UTC),
                description="Successful login",
                doc_ids=[],
            )
        ]
    )
    _, failures = grade(verdict, TRUTH, ALERT)
    assert failures == ["grounded: 1/1 timeline steps cite no document"]


def test_a_dropped_entity_fails_scope():
    _, failures = grade(_verdict(scope=Entities(users=["mehmet.kaya"])), TRUTH, ALERT)
    assert failures == ["ip_in_scope: 185.220.101.44 missing from scope.source_ips"]


def test_inconclusive_is_a_miss():
    _, failures = grade(_verdict(verdict="inconclusive"), TRUTH, ALERT)
    assert failures == ["decided: returned inconclusive"]


def test_benign_true_positive_is_allowed():
    """Calling planted activity legitimate is a judgement, not a fidelity failure."""
    _, failures = grade(_verdict(verdict="benign_true_positive"), TRUTH, ALERT)
    assert failures == []


def test_false_positive_is_not():
    _, failures = grade(_verdict(verdict="false_positive"), TRUTH, ALERT)
    assert failures == ["positive: called it a false positive"]


def test_checks_that_need_ground_truth_pass_without_it():
    """An alert with no matching scenario is still graded on what is checkable."""
    _, failures = grade(_verdict(scope=Entities()), {}, ALERT)
    assert failures == []
