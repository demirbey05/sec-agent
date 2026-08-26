"""Message-history compaction profiles, read from `compaction.toml`.

A profile names a set of Pydantic AI harness capabilities that rewrite the
conversation history just before each request goes out. They range from free
(blank an old tool result) to a whole extra model call (summarize the
transcript). See https://pydantic.dev/docs/ai/harness/compaction/

This is a different mechanism from the tool-result folding in `compact.py`,
which is always on: that fold is lossless and happens *before* a result enters
the history, whereas these strategies act on history that has already been
folded. The question `bench.py` exists to answer is how much history compaction
is still worth paying for on top of it.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.messages import ToolCallPart

DEFAULT_CONFIG_NAME = "compaction.toml"

PACKAGED_CONFIG = Path(__file__).resolve().parents[2] / DEFAULT_CONFIG_NAME
"""The config shipped with the repository, used when the working directory has none."""


# ---------------------------------------------------------------------------
# The strategy registry
#
# Names in the config are the harness class names. Imports are deferred so that
# a profile with no strategies — the `none` baseline — costs nothing to load.
# ---------------------------------------------------------------------------

STRATEGY_NAMES = (
    "ClampOversizedMessages",
    "ClearToolResults",
    "DeduplicateFileReads",
    "FallbackCompaction",
    "SlidingWindowCompaction",
    "SummarizingCompaction",
    "TieredCompaction",
    "WarnNearLimits",
)

NESTED_STRATEGY_KEYS = ("tiers", "fallback_chain")
"""Constructor arguments that are themselves lists of strategies."""


def _strategy_class(type_name: str) -> type:
    from pydantic_ai_harness import compaction as harness

    try:
        return getattr(harness, type_name)
    except AttributeError:
        raise ValueError(
            f"Unknown compaction strategy {type_name!r}. Available: {', '.join(STRATEGY_NAMES)}."
        ) from None


def _tool_call_key(call: ToolCallPart) -> str | None:
    """Identity of a query, so an identical later call supersedes this one's result.

    `DeduplicateFileReads` is written for an agent that re-reads files, where only
    the newest read of a path matters. The triage agent has no files, but it does
    re-run queries — the same `search_events` twice, verbatim, is a common way for
    a model to convince itself of something it already saw. Keying on the tool name
    plus its normalised arguments makes the older copy of that answer disposable.
    """
    try:
        arguments = call.args_as_dict()
    except Exception:  # noqa: BLE001 — malformed args are simply not deduplicable
        return None
    return f"{call.tool_name}:{json.dumps(arguments, sort_keys=True, default=str)}"


FILE_KEYS: dict[str, Callable[[ToolCallPart], str | None]] = {
    "tool_call": _tool_call_key,
}
"""Named `file_key` resolvers a config can ask for by string."""


def build_strategy(spec: dict[str, Any]) -> Any:
    """Build one strategy from its config table.

    The table's `type` names a harness class; every other key is handed to that
    class's constructor unchanged, so a strategy gains a new option without this
    module needing to know about it.
    """
    options = dict(spec)
    type_name = options.pop("type", None)
    if not type_name:
        raise ValueError(f"Compaction strategy {spec!r} has no `type`.")

    for key in NESTED_STRATEGY_KEYS:
        if key in options:
            options[key] = [build_strategy(nested) for nested in options[key]]

    if isinstance(options.get("file_key"), str):
        name = options["file_key"]
        if name not in FILE_KEYS:
            raise ValueError(f"Unknown file_key {name!r}. Available: {', '.join(FILE_KEYS)}.")
        options["file_key"] = FILE_KEYS[name]

    if isinstance(options.get("exclude_tools"), list):
        options["exclude_tools"] = frozenset(options["exclude_tools"])

    strategy_class = _strategy_class(type_name)
    try:
        return strategy_class(**options)
    except TypeError as exc:
        raise ValueError(f"{type_name} rejected its configuration: {exc}") from exc


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompactionProfile:
    """One named combination of compaction mechanisms."""

    name: str
    description: str = ""
    strategies: tuple[dict[str, Any], ...] = ()
    """Harness strategy specs, in the order they should be registered."""

    def capabilities(self) -> list[AbstractCapability[Any]]:
        """Instantiate this profile's history-compaction capabilities."""
        return [build_strategy(spec) for spec in self.strategies]

    @property
    def uses_llm(self) -> bool:
        """Whether any strategy here spends a model call of its own."""
        return _mentions(self.strategies, "SummarizingCompaction")

    def summary(self) -> str:
        """One-line rendering of what this profile turns on."""
        types = [str(spec.get("type", "?")) for spec in self.strategies]
        return " + ".join(types) if types else "(none)"


def _mentions(specs: Any, type_name: str) -> bool:
    """Whether `type_name` appears anywhere in a strategy spec tree."""
    if isinstance(specs, dict):
        if specs.get("type") == type_name:
            return True
        return any(_mentions(value, type_name) for value in specs.values())
    if isinstance(specs, (list, tuple)):
        return any(_mentions(item, type_name) for item in specs)
    return False


NO_COMPACTION = CompactionProfile(
    name="none",
    description="No history compaction.",
)
"""Fallback used when no config file can be found."""


@dataclass(frozen=True)
class CompactionConfig:
    """Everything `compaction.toml` declares."""

    profiles: dict[str, CompactionProfile] = field(default_factory=dict)
    default_profile: str = "none"
    path: Path | None = None

    def get(self, name: str | None) -> CompactionProfile:
        """Look a profile up by name, defaulting to the config's own default."""
        wanted = name or self.default_profile
        try:
            return self.profiles[wanted]
        except KeyError:
            raise ValueError(
                f"Unknown compaction profile {wanted!r}. "
                f"Available: {', '.join(self.profiles) or '(none)'}"
                + (f" (from {self.path})" if self.path else "")
            ) from None


def config_path(explicit: str | Path | None = None) -> Path | None:
    """Where to read profiles from: the given path, the cwd, then the repository's."""
    if explicit is not None:
        return Path(explicit)
    local = Path.cwd() / DEFAULT_CONFIG_NAME
    if local.is_file():
        return local
    return PACKAGED_CONFIG if PACKAGED_CONFIG.is_file() else None


def load_config(path: str | Path | None = None) -> CompactionConfig:
    """Read the compaction profiles.

    A missing file is not an error: the agent then runs with no compaction at
    all, which is a meaningful configuration rather than a broken one.
    """
    resolved = config_path(path)
    if resolved is None or not resolved.is_file():
        return CompactionConfig(profiles={"none": NO_COMPACTION}, default_profile="none")

    raw = tomllib.loads(resolved.read_text(encoding="utf-8"))
    profiles = {
        name: CompactionProfile(
            name=name,
            description=body.get("description", ""),
            strategies=tuple(body.get("strategies", ())),
        )
        for name, body in raw.get("profiles", {}).items()
    }
    if not profiles:
        raise ValueError(f"{resolved} declares no `[profiles.*]`.")

    default = raw.get("default_profile") or next(iter(profiles))
    if default not in profiles:
        raise ValueError(f"{resolved}: default_profile {default!r} is not a declared profile.")
    return CompactionConfig(profiles=profiles, default_profile=default, path=resolved)


def resolve_profile(name: str | None = None, config: str | Path | None = None) -> CompactionProfile:
    """The profile a run should use, by name."""
    return load_config(config).get(name)
