"""Tests for tool-result compaction (no Elasticsearch or API key required)."""

from __future__ import annotations

from sec_agent.compact import ABSENT, cap_histogram, fold_events


def _failure(doc_id: str, timestamp: str, **overrides):
    """A login failure, in the nested shape Elasticsearch returns."""
    doc = {
        "_id": doc_id,
        "@timestamp": timestamp,
        "event": {"action": "login_failed", "outcome": "failure", "reason": "invalid_password"},
        "user": {"name": "mehmet.kaya", "roles": ["employee"]},
        "source": {"ip": "185.220.101.44", "geo": {"country_iso_code": "NL"}},
        "auth": {"method": "password", "mfa_used": False},
    }
    for path, value in overrides.items():
        target = doc
        *parents, leaf = path.split(".")
        for parent in parents:
            target = target.setdefault(parent, {})
        if value is None:
            target.pop(leaf, None)
        else:
            target[leaf] = value
    return doc


def test_identical_documents_collapse_to_one_shape():
    docs = [_failure(f"id{i}", f"2026-08-23T02:14:0{i}Z") for i in range(5)]
    folded = fold_events(docs)

    assert folded["returned"] == 5
    assert folded["events"] == [[f"id{i}", f"2026-08-23T02:14:0{i}Z"] for i in range(5)]
    assert "outliers" not in folded
    # The shared fields are stated once, flattened to dotted keys.
    assert folded["shape"]["event.outcome"] == "failure"
    assert folded["shape"]["user.roles"] == ["employee"]
    assert folded["shape"]["auth.mfa_used"] is False


def test_the_lone_success_becomes_an_outlier():
    """The point of the whole exercise: one different document must not hide."""
    docs = [_failure(f"id{i}", f"2026-08-23T02:14:0{i}Z") for i in range(9)]
    docs.append(
        _failure(
            "win",
            "2026-08-23T02:17:04Z",
            **{"event.action": "login_success", "event.outcome": "success", "event.reason": None},
        )
    )
    folded = fold_events(docs)

    assert len(folded["events"]) == 9
    assert folded["outlier_count"] == 1
    (outlier,) = folded["outliers"]
    assert outlier["_id"] == "win"
    assert outlier["event.outcome"] == "success"
    # A field the majority carries but this document lacks is called out, not silently shared.
    assert outlier["event.reason"] == ABSENT
    # Fields it shares with the rest stay in the shape rather than being repeated.
    assert "source.ip" not in outlier
    assert folded["shape"]["source.ip"] == "185.220.101.44"


def test_shape_is_modal_not_constant():
    """With no constant value anywhere, folding must still isolate the minority."""
    docs = [_failure(f"f{i}", f"2026-08-23T02:14:0{i}Z") for i in range(4)]
    docs.append(_failure("odd", "2026-08-23T02:15:00Z", **{"source.ip": "10.0.0.5"}))
    folded = fold_events(docs)

    assert folded["shape"]["source.ip"] == "185.220.101.44"
    assert folded["outliers"] == [
        {"_id": "odd", "@timestamp": "2026-08-23T02:15:00Z", "source.ip": "10.0.0.5"}
    ]


def test_round_trip_is_lossless():
    """Shape plus deviations must rebuild the originals exactly."""
    docs = [_failure(f"id{i}", f"2026-08-23T02:14:0{i}Z") for i in range(6)]
    docs.append(_failure("s", "2026-08-23T02:17:04Z", **{"event.outcome": "success"}))
    docs.append(
        _failure("m", "2026-08-23T02:18:00Z", **{"auth.mfa_used": True, "user.roles": None})
    )
    folded = fold_events(docs)

    rebuilt = {}
    for doc_id, timestamp in folded["events"]:
        rebuilt[doc_id] = {"_id": doc_id, "@timestamp": timestamp, **folded["shape"]}
    for outlier in folded.get("outliers", []):
        row = dict(folded["shape"])
        for name, value in outlier.items():
            if name in ("_id", "@timestamp"):
                continue
            if value == ABSENT:
                row.pop(name, None)
            else:
                row[name] = value
        rebuilt[outlier["_id"]] = {
            "_id": outlier["_id"],
            "@timestamp": outlier["@timestamp"],
            **row,
        }

    def flatten(value, prefix=""):
        flat = {}
        for key, item in value.items():
            path = f"{prefix}{key}"
            flat.update(flatten(item, f"{path}.") if isinstance(item, dict) else {path: item})
        return flat

    assert {doc["_id"]: flatten(doc) for doc in docs} == rebuilt


def test_unique_valued_fields_stay_on_their_documents():
    """A field that never repeats is nothing to share."""
    docs = [
        _failure(f"id{i}", f"2026-08-23T02:14:0{i}Z", **{"user.name": f"user{i}"}) for i in range(3)
    ]
    folded = fold_events(docs)

    assert "user.name" not in folded["shape"]
    assert {o["user.name"] for o in folded["outliers"]} == {"user0", "user1", "user2"}


def test_truncation_is_reported():
    folded = fold_events([_failure("a", "2026-08-23T02:14:00Z")], total_matched=215)
    assert "1 of 215" in folded["truncated"]


def test_untruncated_results_carry_no_warning():
    folded = fold_events([_failure("a", "2026-08-23T02:14:00Z")], total_matched=1)
    assert "truncated" not in folded


def test_empty_result_is_explicit():
    folded = fold_events([])
    assert folded["returned"] == 0
    assert folded["events"] == []
    assert "No documents matched" in folded["note"]


def test_histogram_under_the_limit_is_untouched():
    slots = [{"at": f"h{i}", "count": i} for i in range(5)]
    kept, note = cap_histogram(slots, 10)
    assert kept == slots
    assert note is None


def test_histogram_keeps_the_busiest_slots_in_time_order():
    slots = [{"at": f"h{i:02d}", "count": count} for i, count in enumerate([1, 90, 2, 80, 3, 70])]
    kept, note = cap_histogram(slots, 3)

    assert [slot["count"] for slot in kept] == [90, 80, 70]
    assert [slot["at"] for slot in kept] == ["h01", "h03", "h05"]  # chronological, not by count
    assert "3 busiest of 6" in note
