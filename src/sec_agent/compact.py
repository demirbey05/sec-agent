"""Lossless compaction of tool results, so context is spent on signal.

Authentication logs are extremely repetitive. A password-guessing burst is the
same document a few hundred times over with only the timestamp moving: of the
twenty-six fields on a login event, twenty-two are usually identical across
every document in a result set. Returning each one in full spends thousands of
tokens restating what the model already knows, and buries the one document that
*differs* — which, in triage, is nearly always the document that decides the
verdict.

`fold_events` states the shared fields once and surfaces every document that
departs from them, along with exactly the fields it departs on. Nothing is
discarded, so the model still sees the outlier login four seconds past the
alert window; it just no longer has to find it in ten thousand tokens of
boilerplate.

The folding is deterministic on purpose. Handing this job to a second model
would make every downstream conclusion rest on an unverified summary, which is
the failure mode the triage instructions exist to prevent.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

ABSENT = "<absent>"
"""Marks a field the shape carries but an individual document does not."""


def _flatten(document: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Turn nested ECS objects into dotted keys. Lists are kept as whole values."""
    flat: dict[str, Any] = {}
    for key, value in document.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{path}."))
        else:
            flat[path] = value
    return flat


def _hashable(value: Any) -> str:
    """A comparable stand-in, so list-valued fields like `user.roles` can be counted."""
    return repr(value)


def fold_events(
    documents: list[dict[str, Any]],
    *,
    timestamp_field: str = "@timestamp",
    total_matched: int | None = None,
) -> dict[str, Any]:
    """Fold near-identical documents into one shared shape plus its exceptions.

    Args:
        documents: Hits as `{"_id": ..., **_source}`, in the order the query sorted them.
        timestamp_field: The time field, always reported per document rather than shared.
        total_matched: How many documents matched in total, to flag a truncated view.
    """
    if not documents:
        return {
            "returned": 0,
            "total_matched": total_matched or 0,
            "events": [],
            "note": "No documents matched.",
        }

    rows = [_flatten(document) for document in documents]
    pinned = {"_id", timestamp_field}

    # The shape holds the *modal* value of each field, not its constant value.
    # Nineteen failures and one success share no constant `event.outcome`, and
    # it is precisely the success that has to stand out.
    tally: dict[str, Counter[str]] = {}
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        for name, value in row.items():
            if name in pinned:
                continue
            token = _hashable(value)
            tally.setdefault(name, Counter())[token] += 1
            seen.setdefault(name, {})[token] = value

    shape: dict[str, Any] = {}
    for name, counter in tally.items():
        token, hits = counter.most_common(1)[0]
        # A value that never repeats is nothing to share; leave it on its document.
        if hits > 1:
            shape[name] = seen[name][token]

    conforming: list[list[Any]] = []
    outliers: list[dict[str, Any]] = []
    for row in rows:
        departures = {
            name: row.get(name, ABSENT)
            for name in {*row, *shape} - pinned
            if _hashable(row.get(name, ABSENT)) != _hashable(shape.get(name, ABSENT))
        }
        identity = [row.get("_id"), row.get(timestamp_field)]
        if departures:
            outliers.append({"_id": identity[0], timestamp_field: identity[1], **departures})
        else:
            conforming.append(identity)

    folded: dict[str, Any] = {
        "returned": len(documents),
        "total_matched": len(documents) if total_matched is None else total_matched,
        "legend": (
            "`shape` lists field values shared by the documents in `events`. Each entry "
            f"in `events` is `[_id, {timestamp_field}]` and carries every field in "
            "`shape`. Documents in `outliers` differ, and list only their differing "
            f"fields — read those against `shape`; `{ABSENT}` means the field is missing."
        ),
        "shape": shape,
        "events": conforming,
    }
    if outliers:
        folded["outliers"] = outliers
        folded["outlier_count"] = len(outliers)
    if total_matched is not None and total_matched > len(documents):
        folded["truncated"] = (
            f"{len(documents)} of {total_matched} matching documents returned. "
            "Narrow the window or filters, or aggregate instead of reading raw events."
        )
    return folded


def cap_histogram(
    slots: list[dict[str, Any]], limit: int
) -> tuple[list[dict[str, Any]], str | None]:
    """Trim a date histogram to its busiest `limit` slots, kept in time order.

    A seven-day hourly breakdown across ten groups is several thousand tokens of
    mostly-idle buckets. The busy ones are what a shape of activity is read from.
    """
    if len(slots) <= limit:
        return slots, None

    busiest = sorted(slots, key=lambda slot: slot["count"], reverse=True)[:limit]
    kept = sorted(busiest, key=lambda slot: slot["at"])
    note = (
        f"{limit} busiest of {len(slots)} time slots shown. "
        "Use a coarser `interval`, or a narrower start/end, for the full series."
    )
    return kept, note
