#!/usr/bin/env python3
"""
Turn the lab's ground truth into the alerts a detector would have raised.

`generator.py` plants six scenarios and records where they are; this script
writes one alert JSON per scenario, in the shape `sec_agent.agent.Alert`
expects. The alerts carry only what a rule could actually know: the pivot it
fired on, its own window, and the numbers it measured — those are read back
from Elasticsearch, not copied from the answer key. Whether anything succeeded,
and whether it matters, is left for the agent to find out.

Usage:
    python make_alerts.py                       # writes siem/alerts/*.json
    python make_alerts.py --scenario S1_brute_force
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run: pip install requests")

TIMESTAMP_FIELD = "@timestamp"
EXCLUDES = ["labels.scenario"]


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Elasticsearch: measure what the rule would have measured
# --------------------------------------------------------------------------


def search(host: str, index: str, body: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(f"{host}/{index}/_search", json=body, timeout=30)
    if not response.ok:
        sys.exit(f"Search failed: {response.status_code} {response.text[:400]}")
    return response.json()


def measure(
    host: str,
    index: str,
    filters: dict[str, str],
    start: datetime,
    end: datetime,
    distinct_field: str | None = None,
) -> tuple[int, int | None, list[str], list[dict[str, Any]]]:
    """Return `(matched, distinct, doc_ids, samples)` for the rule's own window."""
    body: dict[str, Any] = {
        "size": 5,
        "query": {
            "bool": {
                "filter": [
                    *({"term": {k: v}} for k, v in filters.items()),
                    {"range": {TIMESTAMP_FIELD: {"gte": iso(start), "lte": iso(end)}}},
                ]
            }
        },
        "sort": [{TIMESTAMP_FIELD: "asc"}],
        "_source": {"excludes": EXCLUDES},
        "track_total_hits": True,
    }
    if distinct_field:
        body["aggs"] = {"distinct": {"cardinality": {"field": distinct_field}}}

    response = search(host, index, body)
    hits = response["hits"]["hits"]
    distinct = response["aggregations"]["distinct"]["value"] if distinct_field else None
    return (
        response["hits"]["total"]["value"],
        distinct,
        [hit["_id"] for hit in hits],
        [hit["_source"] for hit in hits[:3]],
    )


# --------------------------------------------------------------------------
# Scenario -> alert
#
# Each spec says which slice of the timeline the rule looked at and which
# pivot it fired on. Everything the rule "knows" is derived from that slice.
# --------------------------------------------------------------------------


def spec_for(scenario: dict[str, Any]) -> dict[str, Any] | None:
    """Describe the rule that would have fired on this scenario."""
    sid = scenario["id"]
    start, end = parse(scenario["window_start"]), parse(scenario["window_end"])

    if sid == "S1_brute_force":
        return {
            "rule_id": "auth-0001",
            "rule_name": "Repeated authentication failures against a single account",
            "rule_type": "threshold",
            "severity": "high",
            "risk_score": 73,
            "confidence": 0.6,
            "title": f"{scenario['user']}: burst of failed logins from {scenario['source_ip']}",
            "description": (
                "A single source address failed to authenticate against one account far more "
                "often than the rule's threshold allows within five minutes."
            ),
            "query": (
                f'event.outcome:"failure" and user.name:"{scenario["user"]}" '
                f'and source.ip:"{scenario["source_ip"]}"'
            ),
            "query_language": "kql",
            # The rule evaluates a five-minute bucket that starts when the
            # failures do, so it stops short of anything that came after.
            "window": (start, start + timedelta(minutes=3)),
            "filters": {
                "user.name": scenario["user"],
                "source.ip": scenario["source_ip"],
                "event.outcome": "failure",
            },
            "signal_name": "failed_login_count",
            "threshold": {"failed_login_count": 25, "window": "5m"},
            "entities": {"users": [scenario["user"]], "source_ips": [scenario["source_ip"]]},
            "mitre": ["T1110.001"],
            "context": {"notes": "Account belongs to the sales team; no ticket references it."},
        }

    if sid == "S2_password_spray":
        return {
            "rule_id": "auth-0002",
            "rule_name": "One source authenticating against many distinct accounts",
            "rule_type": "threshold",
            "severity": "medium",
            "risk_score": 61,
            "confidence": 0.5,
            "title": f"{scenario['source_ip']} touched many accounts in one hour",
            "description": (
                "A single source address attempted authentication against a large number of "
                "distinct accounts, each only a couple of times."
            ),
            "query": f'event.outcome:"failure" and source.ip:"{scenario["source_ip"]}"',
            "query_language": "kql",
            "window": (start, end),
            "filters": {"source.ip": scenario["source_ip"], "event.outcome": "failure"},
            "signal_name": "failed_login_count",
            "distinct_field": "user.name",
            "threshold": {"distinct_user_count": 15, "window": "1h"},
            "entities": {"source_ips": [scenario["source_ip"]]},
            "mitre": ["T1110.003"],
            "context": {"known_corp_ranges": ["10.10.0.0/16"]},
        }

    if sid == "S3_impossible_travel":
        return {
            "rule_id": "auth-0003",
            "rule_name": "Successful logins from two countries in quick succession",
            "rule_type": "correlation",
            "severity": "high",
            "risk_score": 70,
            "confidence": 0.55,
            "title": f"{scenario['user']} authenticated from {' and '.join(scenario['countries'])}",
            "description": (
                "Two successful authentications for the same account came from different "
                "countries, closer together in time than travel between them allows."
            ),
            "query": f'event.outcome:"success" and user.name:"{scenario["user"]}"',
            "query_language": "kql",
            "window": (start - timedelta(minutes=1), end + timedelta(minutes=1)),
            "filters": {"user.name": scenario["user"], "event.outcome": "success"},
            "signal_name": "successful_login_count",
            "distinct_field": "source.geo.country_iso_code",
            "threshold": {"distinct_country_count": 1, "window": "1h"},
            "entities": {"users": [scenario["user"]], "source_ips": scenario["source_ips"]},
            "mitre": ["T1078.004"],
            "context": {"user_department": "finance"},
        }

    if sid == "S4_offhours_admin":
        return {
            "rule_id": "auth-0004",
            "rule_name": "Privileged account active outside business hours",
            "rule_type": "new_terms",
            "severity": "medium",
            "risk_score": 55,
            "confidence": 0.4,
            "title": f"{scenario['user']} logged in at an unusual hour",
            "description": (
                "An administrative account authenticated in the middle of the night, an hour "
                "at which it has no recorded history."
            ),
            "query": f'event.outcome:"success" and user.name:"{scenario["user"]}"',
            "query_language": "kql",
            "window": (start - timedelta(minutes=1), end + timedelta(minutes=1)),
            "filters": {"user.name": scenario["user"], "event.outcome": "success"},
            "signal_name": "successful_login_count",
            "threshold": {"business_hours_utc": "06:00-18:00"},
            "entities": {"users": [scenario["user"]], "source_ips": [scenario["source_ip"]]},
            "mitre": ["T1078.003"],
            "context": {
                "user_is_privileged": True,
                "asset_criticality": "high",
                "known_corp_ranges": ["10.10.0.0/16"],
            },
        }

    if sid == "S5_dormant_account":
        return {
            "rule_id": "auth-0005",
            "rule_name": "Account with no recent history authenticates successfully",
            "rule_type": "new_terms",
            "severity": "medium",
            "risk_score": 58,
            "confidence": 0.5,
            "title": f"First activity in the retention window for {scenario['user']}",
            "description": (
                "An account that has not appeared in the authentication logs at all "
                "authenticated successfully from outside the corporate ranges."
            ),
            "query": f'event.outcome:"success" and user.name:"{scenario["user"]}"',
            "query_language": "kql",
            "window": (start - timedelta(minutes=5), end + timedelta(minutes=5)),
            "filters": {"user.name": scenario["user"]},
            "signal_name": "event_count",
            "threshold": {"prior_events_in_baseline": 0},
            "entities": {"users": [scenario["user"]], "source_ips": [scenario["source_ip"]]},
            "mitre": ["T1078.002"],
            "context": {"notes": "Not present in the current HR export."},
        }

    if sid == "S6_service_account_misuse":
        return {
            "rule_id": "auth-0006",
            "rule_name": "Service account authenticating in an unfamiliar way",
            "rule_type": "new_terms",
            "severity": "medium",
            "risk_score": 60,
            "confidence": 0.45,
            "title": f"{scenario['user']} authenticated from a new host",
            "description": (
                "An automation account authenticated from a host and with a method it has "
                "not used before in the baseline period."
            ),
            "query": f'event.outcome:"success" and user.name:"{scenario["user"]}"',
            "query_language": "kql",
            "window": (start - timedelta(minutes=1), end + timedelta(minutes=1)),
            "filters": {"user.name": scenario["user"], "event.outcome": "success"},
            "signal_name": "successful_login_count",
            "distinct_field": "host.name",
            "threshold": {"new_host_or_method": "not seen in 7d baseline"},
            "entities": {"users": [scenario["user"]], "source_ips": [scenario["source_ip"]]},
            "mitre": ["T1078.001"],
            "context": {"user_is_service_account": True, "known_corp_ranges": ["10.10.0.0/16"]},
        }

    return None


def build_alert(host: str, index: str, scenario: dict[str, Any]) -> dict[str, Any] | None:
    spec = spec_for(scenario)
    if spec is None:
        return None

    start, end = spec["window"]
    matched, distinct, doc_ids, samples = measure(
        host, index, spec["filters"], start, end, spec.get("distinct_field")
    )

    signals: dict[str, Any] = {spec["signal_name"]: matched}
    if distinct is not None:
        signals[f"distinct_{spec['distinct_field'].replace('.', '_')}_count"] = distinct

    entity = scenario.get("user") or scenario["source_ip"]
    return {
        "schema_version": "1.0",
        "alert_id": scenario["id"].lower().replace("_", "-"),
        "dedup_key": f"{spec['rule_id']}:{entity}:{iso(start)}",
        "created_at": iso(end + timedelta(minutes=2)),
        "producer": "kibana-rule",
        "title": spec["title"],
        "description": spec["description"],
        "severity": spec["severity"],
        "confidence": spec["confidence"],
        "risk_score": spec["risk_score"],
        "data_source": {"index": index, "timestamp_field": TIMESTAMP_FIELD, "ecs_version": "8.11"},
        "window": {"start": iso(start), "end": iso(end), "baseline_days": 7},
        "entities": spec["entities"],
        "detection": {
            "rule_id": spec["rule_id"],
            "rule_name": spec["rule_name"],
            "rule_type": spec["rule_type"],
            "query": spec["query"],
            "query_language": spec["query_language"],
            "signals": signals,
            "threshold": spec["threshold"],
            "mitre": spec["mitre"],
        },
        "evidence": {
            "index": index,
            "doc_ids": doc_ids,
            "sample": samples,
            "total_matched": matched,
        },
        "context": spec["context"],
        "related_alert_ids": [],
        "raw": {},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="http://localhost:9200")
    parser.add_argument("--index", default="auth-logs")
    parser.add_argument("--truth", default=str(Path(__file__).with_name("ground_truth.json")))
    parser.add_argument("--out-dir", default=str(Path(__file__).with_name("alerts")))
    parser.add_argument("--scenario", help="Only build this scenario id, e.g. S1_brute_force")
    args = parser.parse_args()

    truth_path = Path(args.truth)
    if not truth_path.exists():
        sys.exit(f"Ground truth not found: {truth_path}. Run generator.py first.")
    truth = json.loads(truth_path.read_text(encoding="utf-8"))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for scenario in truth["scenarios"]:
        if args.scenario and scenario["id"] != args.scenario:
            continue
        alert = build_alert(args.host, args.index, scenario)
        if alert is None:
            print(f"  no rule defined for {scenario['id']}, skipped")
            continue
        path = out_dir / f"{scenario['id']}.json"
        path.write_text(json.dumps(alert, indent=2) + "\n", encoding="utf-8")
        signals = alert["detection"]["signals"]
        print(f"  {path.name}: {signals}")

    print(f"\nAlerts written to {out_dir.resolve()}")


if __name__ == "__main__":
    main()
