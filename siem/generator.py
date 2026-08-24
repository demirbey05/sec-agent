#!/usr/bin/env python3
"""
Synthetic authentication log generator for a local Elasticsearch SIEM lab.

Produces 7 days of "normal" login traffic plus six deliberately planted
attack scenarios, so you always know the correct answer when you ask your
agent a question.

Usage:
    pip install requests
    python generate_auth_logs.py --recreate
    python generate_auth_logs.py --host http://localhost:9200 --index auth-logs

Everything is deterministic for a given --seed, so re-running with the same
seed reproduces the same baseline noise.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run: pip install requests")


# --------------------------------------------------------------------------
# Static world: users, hosts, IP pools
# --------------------------------------------------------------------------

CORP_USERS = [
    "ayse.demir", "mehmet.kaya", "zeynep.arslan", "burak.yilmaz", "elif.sahin",
    "can.ozturk", "deniz.aydin", "selin.kurt", "emre.dogan", "irem.celik",
    "kerem.polat", "nese.gunes", "onur.tas", "pinar.koc", "serkan.bulut",
    "tugce.erdem", "umut.acar", "yasemin.oz", "berk.sezer", "ceren.aksoy",
    "furkan.kilic", "gizem.tekin", "hakan.uysal", "ilayda.bas", "kaan.soylu",
    "leyla.duran", "mert.ergin", "nil.ozkan", "ozan.karaca", "sude.altin",
    "taner.bilir", "veli.sarp", "yunus.ergun", "aylin.mert", "baris.turan",
    "cemre.avci", "dilara.ince", "efe.balci", "gokce.yalcin", "halil.ergul",
]

SERVICE_ACCOUNTS = ["svc-backup", "svc-jenkins", "svc-monitoring"]
ADMIN_USERS = ["kadmin", "root.ops"]

HOSTS = [
    ("vpn-gw-01", "vpn"),
    ("vpn-gw-02", "vpn"),
    ("sso-idp-01", "okta"),
    ("sso-idp-02", "okta"),
    ("bastion-01", "sshd"),
    ("app-web-01", "webapp"),
    ("app-web-02", "webapp"),
]

USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36", "Chrome", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/17.5", "Safari", "macOS"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36", "Chrome", "Linux"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148", "Safari", "iOS"),
    ("OpenSSH_9.6p1", "OpenSSH", "Linux"),
]

FAILURE_REASONS = ["invalid_password", "unknown_user", "mfa_denied", "account_locked"]

# ---- Scenario constants. These are your answer key; keep them stable. ----

BRUTE_FORCE_IP = "185.220.101.44"
BRUTE_FORCE_TARGET = "mehmet.kaya"
BRUTE_FORCE_ATTEMPTS = 214

SPRAY_IP = "91.219.236.17"
SPRAY_USER_COUNT = 50

TRAVEL_USER = "ayse.demir"
TRAVEL_IP_HOME = "88.240.12.9"      # TR
TRAVEL_IP_FOREIGN = "177.36.44.201"  # BR

OFFHOURS_USER = "kadmin"
OFFHOURS_IP = "10.10.40.55"

DORMANT_USER = "eski.calisan"
DORMANT_IP = "94.103.87.12"

SVC_ABUSE_USER = "svc-backup"
SVC_ABUSE_IP = "10.10.99.201"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def corp_ip(rng: random.Random) -> str:
    return f"10.10.{rng.choice([10, 20, 30, 40])}.{rng.randint(2, 250)}"


def home_ip(rng: random.Random) -> str:
    """Turkish-ISP-looking residential addresses."""
    return f"{rng.choice([78, 85, 88, 176, 213])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(2, 250)}"


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_doc(
    ts: datetime,
    *,
    user: str,
    action: str,
    outcome: str,
    src_ip: str,
    rng: random.Random,
    host: tuple[str, str] | None = None,
    country: str = "TR",
    city: str = "Istanbul",
    asn_org: str = "Turk Telekom",
    reason: str | None = None,
    method: str = "password",
    mfa: bool = True,
    user_agent: tuple[str, str, str] | None = None,
    scenario: str | None = None,
) -> dict:
    host_name, service = host or rng.choice(HOSTS)
    ua, ua_name, ua_os = user_agent or rng.choice(USER_AGENTS)

    doc = {
        "@timestamp": iso(ts),
        "message": f"{action} for user {user} from {src_ip} via {service}",
        "event": {
            "id": str(uuid.UUID(int=rng.getrandbits(128))),
            "category": "authentication",
            "action": action,
            "outcome": outcome,
            "dataset": "auth.login",
        },
        "user": {
            "name": user,
            "id": f"uid-{abs(hash(user)) % 100000:05d}",
            "roles": ["admin"] if user in ADMIN_USERS else (["service"] if user.startswith("svc-") else ["employee"]),
        },
        "source": {
            "ip": src_ip,
            "port": rng.randint(1024, 65535),
            "geo": {"country_iso_code": country, "city_name": city},
            "as": {"organization": {"name": asn_org}},
        },
        "host": {"name": host_name, "hostname": host_name},
        "service": {"name": service},
        "network": {"protocol": "https" if service != "sshd" else "ssh"},
        "auth": {"method": method, "mfa_used": mfa},
        "user_agent": {"original": ua, "name": ua_name, "os": {"name": ua_os}},
    }
    if reason:
        doc["event"]["reason"] = reason
    if scenario:
        doc["labels"] = {"scenario": scenario}
    return doc


def business_hour(rng: random.Random) -> int:
    """Weighted toward 09:00-18:00 local, with a long tail."""
    buckets = (
        [7, 8] * 2
        + [9, 10, 11] * 8
        + [12, 13] * 5
        + [14, 15, 16, 17] * 8
        + [18, 19] * 3
        + [20, 21, 22] * 1
        + [0, 1, 2, 3, 4, 5, 6, 23]
    )
    return rng.choice(buckets)


# --------------------------------------------------------------------------
# Baseline traffic
# --------------------------------------------------------------------------

def generate_baseline(now: datetime, days: int, rng: random.Random) -> list[dict]:
    docs: list[dict] = []
    all_users = CORP_USERS + SERVICE_ACCOUNTS + ADMIN_USERS

    def emit(doc: dict) -> None:
        # Never write events in the future; "now" is the edge of the world.
        if doc["@timestamp"] <= iso(now):
            docs.append(doc)

    # day_offset 0 == today, so the most recent hours are populated too.
    for day_offset in range(days, -1, -1):
        day = (now - timedelta(days=day_offset)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        weekend = day.weekday() >= 5

        for user in all_users:
            if user.startswith("svc-"):
                # Service accounts: steady hourly automation, no MFA, corp IP.
                for hour in range(0, 24, 2):
                    ts = day + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                    emit(make_doc(
                        ts, user=user, action="login_success", outcome="success",
                        src_ip=corp_ip(rng), rng=rng, host=("bastion-01", "sshd"),
                        method="ssh_key", mfa=False,
                        user_agent=USER_AGENTS[4], country="TR", city="Ankara",
                        asn_org="Internal",
                    ))
                continue

            sessions = rng.randint(0, 2) if weekend else rng.randint(2, 6)
            for _ in range(sessions):
                ts = day + timedelta(
                    hours=business_hour(rng),
                    minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                remote = rng.random() < 0.35
                ip = home_ip(rng) if remote else corp_ip(rng)
                asn = "Turk Telekom" if remote else "Internal"
                city = rng.choice(["Istanbul", "Ankara", "Izmir"])

                # A realistic sprinkle of honest typos.
                if rng.random() < 0.07:
                    emit(make_doc(
                        ts, user=user, action="login_failed", outcome="failure",
                        src_ip=ip, rng=rng, reason="invalid_password",
                        city=city, asn_org=asn,
                    ))
                    ts += timedelta(seconds=rng.randint(5, 40))

                emit(make_doc(
                    ts, user=user, action="login_success", outcome="success",
                    src_ip=ip, rng=rng, city=city, asn_org=asn,
                ))
                emit(make_doc(
                    ts + timedelta(minutes=rng.randint(20, 480)),
                    user=user, action="logout", outcome="success",
                    src_ip=ip, rng=rng, city=city, asn_org=asn,
                ))

    return docs


# --------------------------------------------------------------------------
# Planted scenarios
# --------------------------------------------------------------------------

def generate_scenarios(now: datetime, rng: random.Random) -> tuple[list[dict], list[dict]]:
    docs: list[dict] = []
    truth: list[dict] = []

    # -- S1: brute force, single user, single IP, ends in a success ----------
    start = (now - timedelta(days=2)).replace(hour=2, minute=14, second=0, microsecond=0)
    ua = ("python-requests/2.32.3", "python-requests", "Linux")
    for i in range(BRUTE_FORCE_ATTEMPTS):
        docs.append(make_doc(
            start + timedelta(milliseconds=i * 850),
            user=BRUTE_FORCE_TARGET, action="login_failed", outcome="failure",
            src_ip=BRUTE_FORCE_IP, rng=rng, host=("vpn-gw-01", "vpn"),
            reason="invalid_password", country="NL", city="Amsterdam",
            asn_org="Hostkey B.V.", mfa=False, user_agent=ua, scenario="S1_brute_force",
        ))
    breach_ts = start + timedelta(milliseconds=BRUTE_FORCE_ATTEMPTS * 850 + 3000)
    docs.append(make_doc(
        breach_ts, user=BRUTE_FORCE_TARGET, action="login_success", outcome="success",
        src_ip=BRUTE_FORCE_IP, rng=rng, host=("vpn-gw-01", "vpn"),
        country="NL", city="Amsterdam", asn_org="Hostkey B.V.",
        mfa=False, user_agent=ua, scenario="S1_brute_force",
    ))
    truth.append({
        "id": "S1_brute_force",
        "description": "Sustained password guessing against one account from one IP, ending in a successful login.",
        "source_ip": BRUTE_FORCE_IP,
        "user": BRUTE_FORCE_TARGET,
        "failed_count": BRUTE_FORCE_ATTEMPTS,
        "succeeded": True,
        "window_start": iso(start),
        "window_end": iso(breach_ts),
    })

    # -- S2: password spraying, many users, few tries each -------------------
    spray_start = (now - timedelta(hours=36)).replace(minute=5, second=0, microsecond=0)
    spray_users = CORP_USERS[:SPRAY_USER_COUNT] if len(CORP_USERS) >= SPRAY_USER_COUNT else CORP_USERS
    spray_ua = ("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)", "MSIE", "Windows")
    cursor = spray_start
    for user in spray_users:
        for _ in range(rng.randint(1, 2)):
            docs.append(make_doc(
                cursor, user=user, action="login_failed", outcome="failure",
                src_ip=SPRAY_IP, rng=rng, host=("sso-idp-01", "okta"),
                reason="invalid_password", country="RU", city="Moscow",
                asn_org="Petersburg Internet Network", mfa=False,
                user_agent=spray_ua, scenario="S2_password_spray",
            ))
            cursor += timedelta(seconds=rng.randint(20, 55))
    truth.append({
        "id": "S2_password_spray",
        "description": "One IP tries a small number of passwords against many distinct accounts.",
        "source_ip": SPRAY_IP,
        "distinct_users": len(spray_users),
        "succeeded": False,
        "window_start": iso(spray_start),
        "window_end": iso(cursor),
    })

    # -- S3: impossible travel ----------------------------------------------
    t1 = (now - timedelta(hours=18)).replace(minute=3, second=0, microsecond=0)
    t2 = t1 + timedelta(minutes=11)
    docs.append(make_doc(
        t1, user=TRAVEL_USER, action="login_success", outcome="success",
        src_ip=TRAVEL_IP_HOME, rng=rng, host=("sso-idp-02", "okta"),
        country="TR", city="Istanbul", asn_org="Turk Telekom",
        scenario="S3_impossible_travel",
    ))
    docs.append(make_doc(
        t2, user=TRAVEL_USER, action="login_success", outcome="success",
        src_ip=TRAVEL_IP_FOREIGN, rng=rng, host=("sso-idp-02", "okta"),
        country="BR", city="Sao Paulo", asn_org="Claro S.A.", mfa=False,
        scenario="S3_impossible_travel",
    ))
    truth.append({
        "id": "S3_impossible_travel",
        "description": "Same account authenticates successfully from two countries minutes apart.",
        "user": TRAVEL_USER,
        "source_ips": [TRAVEL_IP_HOME, TRAVEL_IP_FOREIGN],
        "countries": ["TR", "BR"],
        "gap_minutes": 11,
        "window_start": iso(t1),
        "window_end": iso(t2),
    })

    # -- S4: off-hours admin activity ---------------------------------------
    t = (now - timedelta(days=1)).replace(hour=3, minute=12, second=0, microsecond=0)
    docs.append(make_doc(
        t, user=OFFHOURS_USER, action="login_success", outcome="success",
        src_ip=OFFHOURS_IP, rng=rng, host=("bastion-01", "sshd"),
        method="password", mfa=False, user_agent=USER_AGENTS[4],
        city="Ankara", asn_org="Internal", scenario="S4_offhours_admin",
    ))
    docs.append(make_doc(
        t + timedelta(minutes=47), user=OFFHOURS_USER, action="logout", outcome="success",
        src_ip=OFFHOURS_IP, rng=rng, host=("bastion-01", "sshd"),
        user_agent=USER_AGENTS[4], city="Ankara", asn_org="Internal",
        scenario="S4_offhours_admin",
    ))
    truth.append({
        "id": "S4_offhours_admin",
        "description": "Privileged account logs in at 03:12 UTC, far outside its normal pattern, without MFA.",
        "user": OFFHOURS_USER,
        "source_ip": OFFHOURS_IP,
        "window_start": iso(t),
        "window_end": iso(t + timedelta(minutes=47)),
    })

    # -- S5: dormant account wakes up ---------------------------------------
    t = now - timedelta(hours=4)
    docs.append(make_doc(
        t, user=DORMANT_USER, action="login_success", outcome="success",
        src_ip=DORMANT_IP, rng=rng, host=("vpn-gw-02", "vpn"),
        country="RU", city="Saint Petersburg", asn_org="Petersburg Internet Network",
        mfa=False, scenario="S5_dormant_account",
    ))
    truth.append({
        "id": "S5_dormant_account",
        "description": "Account with no other activity in the retention window suddenly logs in from abroad.",
        "user": DORMANT_USER,
        "source_ip": DORMANT_IP,
        "window_start": iso(t),
        "window_end": iso(t),
    })

    # -- S6: service account used interactively from a new host -------------
    t = (now - timedelta(hours=9)).replace(minute=41, second=0, microsecond=0)
    for i in range(4):
        docs.append(make_doc(
            t + timedelta(minutes=i * 3), user=SVC_ABUSE_USER,
            action="login_success", outcome="success", src_ip=SVC_ABUSE_IP,
            rng=rng, host=("app-web-02", "webapp"), method="password", mfa=False,
            user_agent=USER_AGENTS[0], city="Istanbul", asn_org="Internal",
            scenario="S6_service_account_misuse",
        ))
    truth.append({
        "id": "S6_service_account_misuse",
        "description": "Automation account authenticates with a password from a browser on an unusual host, instead of its normal ssh_key on bastion-01.",
        "user": SVC_ABUSE_USER,
        "source_ip": SVC_ABUSE_IP,
        "window_start": iso(t),
        "window_end": iso(t + timedelta(minutes=9)),
    })

    return docs, truth


# --------------------------------------------------------------------------
# Elasticsearch I/O
# --------------------------------------------------------------------------

def recreate_index(host: str, index: str, mapping_path: Path) -> None:
    if not mapping_path.exists():
        sys.exit(f"Mapping file not found: {mapping_path}")
    body = json.loads(mapping_path.read_text(encoding="utf-8"))

    requests.delete(f"{host}/{index}", timeout=30)
    resp = requests.put(f"{host}/{index}", json=body, timeout=30)
    if not resp.ok:
        sys.exit(f"Failed to create index: {resp.status_code} {resp.text}")
    print(f"Created index '{index}' with explicit mapping.")


def bulk_index(host: str, index: str, docs: list[dict], chunk_size: int = 500) -> None:
    total = len(docs)
    for start in range(0, total, chunk_size):
        chunk = docs[start:start + chunk_size]
        lines = []
        for doc in chunk:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
        payload = "\n".join(lines) + "\n"  # trailing newline is mandatory

        resp = requests.post(
            f"{host}/_bulk",
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            timeout=120,
        )
        if not resp.ok:
            sys.exit(f"Bulk request failed: {resp.status_code} {resp.text[:500]}")
        result = resp.json()
        if result.get("errors"):
            first = next(
                (item["index"] for item in result["items"] if item["index"].get("error")),
                None,
            )
            sys.exit(f"Bulk indexing error: {json.dumps(first, indent=2)[:800]}")
        print(f"  indexed {min(start + chunk_size, total)}/{total}")

    requests.post(f"{host}/{index}/_refresh", timeout=30)


# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="http://localhost:9200")
    parser.add_argument("--index", default="auth-logs")
    parser.add_argument("--days", type=int, default=7, help="days of baseline traffic")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--recreate", action="store_true", help="drop and recreate the index first")
    parser.add_argument(
        "--mapping",
        default=str(Path(__file__).with_name("auth-logs-mapping.json")),
        help="path to the index mapping JSON",
    )
    parser.add_argument(
        "--no-scenario-labels",
        action="store_true",
        help="strip labels.scenario so nothing in the data gives the answer away",
    )
    parser.add_argument("--truth-out", default="ground_truth.json")
    args = parser.parse_args()

    try:
        health = requests.get(f"{args.host}/_cluster/health", timeout=10)
        health.raise_for_status()
    except Exception as exc:
        sys.exit(f"Cannot reach Elasticsearch at {args.host}: {exc}")

    if args.recreate:
        recreate_index(args.host, args.index, Path(args.mapping))

    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)

    print("Generating baseline traffic...")
    docs = generate_baseline(now, args.days, rng)
    print(f"  {len(docs)} baseline events")

    print("Planting attack scenarios...")
    scenario_docs, truth = generate_scenarios(now, rng)
    print(f"  {len(scenario_docs)} scenario events across {len(truth)} scenarios")

    docs.extend(scenario_docs)
    docs.sort(key=lambda d: d["@timestamp"])

    if args.no_scenario_labels:
        for doc in docs:
            doc.pop("labels", None)

    print(f"Indexing {len(docs)} documents into '{args.index}'...")
    bulk_index(args.host, args.index, docs)

    truth_path = Path(args.truth_out)
    truth_path.write_text(
        json.dumps(
            {"generated_at": iso(now), "index": args.index, "seed": args.seed, "scenarios": truth},
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"\nDone. Ground truth written to {truth_path.resolve()}")
    print(f"Verify: curl '{args.host}/{args.index}/_count'")


if __name__ == "__main__":
    main()