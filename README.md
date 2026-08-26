# sec-agent

An agent built with [Pydantic AI](https://ai.pydantic.dev/) that triages
authentication alerts against Elasticsearch, and a self-contained SIEM lab to
try it on.

The agent treats an alert as a *claim*, not a fact. It re-measures the numbers
the detector reported, asks what the entity normally looks like, checks what
happened just outside the alert window, and returns a structured verdict that
is free to disagree with the rule that fired.

---

## 1. Setup

```bash
uv sync
cp .env.example .env   # fill in the key for the model you picked
```

The model comes from `SEC_AGENT_MODEL`, written as `provider:model`. It decides
which key is read, so only one needs to be set:

| `SEC_AGENT_MODEL` | Key required |
| --- | --- |
| `openrouter:openai/gpt-oss-120b` (default, free tier) | `OPENROUTER_API_KEY` |
| `anthropic:claude-opus-5` | `ANTHROPIC_API_KEY` |
| `anthropic:claude-sonnet-5` | `ANTHROPIC_API_KEY` |

Keys are read from `.env` and passed to the provider explicitly, so nothing has
to be exported into the shell.

---

## 2. Bring up the lab

The agent needs authentication logs to triage. `siem/` brings up a throwaway
Elasticsearch, fills it with seven days of synthetic traffic, and plants six
attack scenarios whose answers are recorded in `ground_truth.json`.

```bash
cd siem
docker compose up -d                     # Elasticsearch :9200, Kibana :5601
uv run python generator.py --recreate    # ~2.5k events into `auth-logs`
uv run python make_alerts.py             # one alert JSON per scenario
cd ..
```

`generator.py` anchors everything to *now*, so the timestamps move every time
you regenerate. **Re-run `make_alerts.py` afterwards** — it reads the numbers
each rule would have measured back out of Elasticsearch, so the alerts stay
honest about what a detector could actually know.

Check it worked:

```bash
curl 'http://localhost:9200/auth-logs/_count'
```

---

## 3. Run the alerts, one at a time

Each alert is a single JSON file under `siem/alerts/`. Pass one to the CLI:

```bash
uv run sec-agent siem/alerts/S1_brute_force.json
```

All six, one per scenario:

```bash
# Sustained password guessing against one account, ending in a success.
# The rule fires on 213 failures and stops there — the successful login four
# seconds past the window is the agent's to find.
uv run sec-agent siem/alerts/S1_brute_force.json

# One IP tries a few passwords against 40 distinct accounts. Nothing succeeded.
uv run sec-agent siem/alerts/S2_password_spray.json

# Same account authenticates successfully from TR and BR, 11 minutes apart.
uv run sec-agent siem/alerts/S3_impossible_travel.json

# Privileged account logs in at 03:12 UTC without MFA, from a corporate range.
uv run sec-agent siem/alerts/S4_offhours_admin.json

# An account with no activity at all in the retention window suddenly logs in.
uv run sec-agent siem/alerts/S5_dormant_account.json

# Automation account authenticates with a password from a browser, instead of
# its usual ssh_key on bastion-01.
uv run sec-agent siem/alerts/S6_service_account_misuse.json
```

Or loop over all of them:

```bash
for alert in siem/alerts/*.json; do
  echo "=== $alert ==="
  uv run sec-agent "$alert"
done
```

Read alerts from stdin with `-`:

```bash
cat siem/alerts/S1_brute_force.json | uv run sec-agent -
```

### What comes back

A verdict rendered for a human, or `--json` for the full `TriageVerdict`:

```bash
uv run sec-agent siem/alerts/S3_impossible_travel.json --json
```

```
TRUE POSITIVE  [HIGH]  confidence 0.85  ESCALATE
Alert: ...

<what happened, in two or three sentences>

Timeline
  2026-08-24T18:03:00+00:00  Successful login from 88.240.12.9 (TR)  [AgXS...]
  2026-08-24T18:14:00+00:00  Successful login from 177.36.44.201 (BR)  [BgXS...]

Scope
  user.name = ayse.demir

Recommended actions
  1. ...

Queries run (6)
  [4 hits] Establish whether the account was used after the BR login
```

Compare it against `siem/ground_truth.json` — the agent never sees that file,
and `labels.scenario` is stripped from every tool result so the answer key
cannot leak into the model's context.

---

## 4. Watch it work: `--trace`

By default the agent is a black box that prints a verdict. `--trace` turns the
run into a live commentary — the model's reasoning, every tool call with its
arguments, and every result as it comes back:

```bash
uv run sec-agent siem/alerts/S1_brute_force.json --trace
```

```
✻ Thinking
The rule claims 213 failures. Before trusting that, measure it, then look at
what happened immediately after the window closed…

● aggregate_events(group_by=event.outcome, filters={"user.name": "mehmet.kaya"})
  ⎿ {
      "total_events": 214,
      "buckets": [{"key": "failure", "count": 213}, {"key": "success", "count": 1}]
    }

● search_events(filters={"user.name": "mehmet.kaya"}, size=20, newest_first=true)
  ⎿ {
      "returned": 20,
      "total_matched": 215,
      "shape": {"event.outcome": "failure", "source.ip": "185.220.101.44", …},
      "events": [["IQXSOKAB…", "2026-08-23T02:16:59.310Z"], …],
      "outliers": [{"_id": "IgXSOKAB…", "@timestamp": "2026-08-23T02:17:04.900Z",
                    "event.outcome": "success"}]
    }
     … +12 more lines

─── 7 model requests · 48213 in / 5104 out tokens ───
```

Colours are dropped automatically when stdout is not a terminal, so
`--trace > run.log` produces clean text you can diff between models.

Use it when a verdict looks wrong: the query that misled the model is usually
right there in the transcript. Tool failures (a bad index, a query
Elasticsearch rejected) show up in red — those are `ModelRetry`s the agent is
expected to recover from on its own.

---

## 5. Change the model

Three ways, in increasing order of permanence.

**For one run** — `--model`, as `provider:model`:

```bash
uv run sec-agent siem/alerts/S2_password_spray.json --model anthropic:claude-opus-5
uv run sec-agent siem/alerts/S2_password_spray.json --model anthropic:claude-sonnet-5
uv run sec-agent siem/alerts/S2_password_spray.json --model openrouter:qwen/qwen3-235b-a22b
```

**For the shell session** — an environment variable:

```bash
SEC_AGENT_MODEL=anthropic:claude-opus-5 uv run sec-agent siem/alerts/S1_brute_force.json
```

**Permanently** — uncomment the line in `.env`:

```dotenv
SEC_AGENT_MODEL=anthropic:claude-opus-5
```

The provider prefix picks the key: `anthropic:` reads `ANTHROPIC_API_KEY`,
`openrouter:` reads `OPENROUTER_API_KEY`. If the key for the model you chose is
missing, the CLI says so before spending a single token.

Running the same alert under two models and diffing the traces is the fastest
way to see where a cheaper model stops digging:

```bash
uv run sec-agent siem/alerts/S1_brute_force.json --trace --model openrouter:openai/gpt-oss-120b > gpt-oss.log
uv run sec-agent siem/alerts/S1_brute_force.json --trace --model anthropic:claude-opus-5 > opus.log
diff gpt-oss.log opus.log
```

### Reasoning depth

`--effort` controls how hard the model thinks: `low`, `medium`, `high`
(default), `xhigh`, `max`.

```bash
uv run sec-agent siem/alerts/S4_offhours_admin.json --effort low    # cheap and fast
uv run sec-agent siem/alerts/S1_brute_force.json   --effort max     # Anthropic only
```

On Anthropic it maps to `anthropic_effort` with adaptive thinking; everywhere
else to Pydantic AI's unified `thinking` level, which OpenRouter forwards as
`reasoning.effort`. `max` has no equivalent outside Anthropic and becomes
`xhigh`, the closest level available.

---

## 6. All CLI options

| Flag | Meaning |
| --- | --- |
| `alert` | Path to the alert JSON, or `-` to read it from stdin |
| `--trace` | Stream reasoning, tool calls and results as the run happens |
| `--json` | Print the verdict as JSON instead of the human rendering |
| `--model` | Model for this run, as `provider:model` |
| `--effort` | `low` \| `medium` \| `high` \| `xhigh` \| `max` |
| `--es-url` | Point the tools at a different Elasticsearch cluster |
| `--index` | Add an index to the tools' allowlist (repeatable) |
| `--compaction` | Message-history compaction profile, by name (see §8) |
| `--compaction-config` | Read profiles from a file other than `./compaction.toml` |

Environment equivalents (`.env` or the shell): `SEC_AGENT_MODEL`,
`SEC_AGENT_EFFORT`, `SEC_AGENT_MAX_TOKENS`, `SEC_AGENT_RETRIES`,
`SEC_AGENT_ES_URL`, `SEC_AGENT_COMPACTION`, `SEC_AGENT_COMPACTION_CONFIG`.

Exit codes: `0` verdict printed, `1` runtime failure (e.g. Elasticsearch
unreachable), `2` bad arguments or a missing key, `130` interrupted.

---

## 7. How it works

The agent has three tools, all confined to `TriageDeps.allowed_indices`:

| Tool | Answers |
| --- | --- |
| `search_events` | "Show me the raw documents" — filtered, time-bounded, sorted |
| `aggregate_events` | "How many, grouped by what" — with optional cardinality and a time histogram |
| `entity_baseline` | "Is this unusual *for them*?" — one entity's normal profile before the alert |

### Folded results

Authentication logs repeat themselves. In a password-guessing burst, twenty-two
of a login event's twenty-six fields are identical across every document, so
returning fifty of them in full costs about 10,000 tokens to restate the same
facts fifty times — and buries the one document that *differs*.

`search_events` therefore folds its results (`src/sec_agent/compact.py`): the
shared fields are stated once under `shape`, and any document departing from
them is listed in `outliers` with only the fields it departs on.

```
● search_events(filters={"user.name": "mehmet.kaya"}, size=50, newest_first=true)
  ⎿ returned 50 of 215 · 49 conforming · 1 outlier
     shape:    {"event.outcome": "failure", "event.reason": "invalid_password",
                "source.ip": "185.220.101.44", "user_agent.name": "python-requests", …}
     events:   [["IQXSOKAB…", "02:16:59.310"], ["IAXSOKAB…", "02:16:58.121"], …]
     outliers: [{"_id": "IgXSOKAB…", "@timestamp": "02:17:04.900",
                 "event.outcome": "success", "event.reason": "<absent>"}]
```

That is ~1,000 tokens instead of ~10,700, and the successful login five seconds
past the alert window — the whole answer to S1 — is now the one thing that
stands out rather than the needle in the haystack.

The fold is **lossless and deterministic**: `shape` plus each document's
deviations reconstructs the originals byte-for-byte, and no second model is
involved. A summarising LLM here would be cheaper to write and strictly worse —
it would make every verdict rest on an unverified paraphrase, which is the
failure mode `INSTRUCTIONS` exists to prevent, and the lone outlier is exactly
what a summariser rounds away.

Two fields are dropped outright at the Elasticsearch level, alongside the
`labels.scenario` answer key: `event.id` (a random UUID; `_id` already
identifies the document) and `source.port` (an ephemeral client port). Both
differ on every event, so they defeat folding while telling a triage analyst
nothing.

Date histograms are capped at `TriageDeps.max_time_slots` (120 slots, shared
across the groups requested), keeping the busiest slots in chronological order
and saying so — a seven-day hourly breakdown over ten groups is otherwise ~1,700
mostly-idle buckets.

Output is validated against the `TriageVerdict` schema: a verdict
(`true_positive`, `benign_true_positive`, `false_positive`, `inconclusive`), the
agent's own severity and confidence, a timeline citing document ids, every
query it ran and why, and what a responder should do next. If the run cannot
produce that shape, it fails loudly rather than returning prose.

### Layout

| File | Contents |
| --- | --- |
| `src/sec_agent/settings.py` | Environment/`.env` config, and which key each provider needs |
| `src/sec_agent/agent.py` | Alert/verdict schemas, model wiring, dependencies, tools, instructions |
| `src/sec_agent/compact.py` | Lossless folding of repetitive tool results before the model sees them |
| `src/sec_agent/compaction.py` | Message-history compaction profiles, read from `compaction.toml` |
| `src/sec_agent/cli.py` | The `sec-agent` command line interface |
| `src/sec_agent/bench.py` | The `sec-agent-bench` harness that prices the profiles |
| `src/sec_agent/trace.py` | The `--trace` renderer over Pydantic AI's event stream |
| `compaction.toml` | The compaction profiles themselves |
| `siem/docker-compose.yml` | Dev-only Elasticsearch + Kibana, security disabled |
| `siem/generator.py` | Synthetic log generator and the answer key |
| `siem/make_alerts.py` | Ground truth → the alerts a detector would have raised |
| `siem/alerts/` | One alert JSON per planted scenario |
| `tests/` | Tests using `FunctionModel` — no API calls |

---

## 8. Compaction profiles

Section 7 covered the *tool-result* fold: `search_events` states shared fields
once, so a result costs ~1,000 tokens instead of ~10,700. That happens before a
result ever enters the conversation and is always on.

A second, independent mechanism operates on the conversation itself. Even folded
results accumulate — every prior tool call and its result is resent on every
subsequent request — and Pydantic AI's harness ships
[compaction strategies](https://pydantic.dev/docs/ai/harness/compaction/) that
rewrite that history just before each request goes out. They are configured, not
coded, in **`compaction.toml`**:

```toml
default_profile = "none"

[profiles.none]
description = "No history compaction. The full transcript is resent every request."
strategies = []

[profiles.clear_tool_results]
description = "Blank the content of older tool results, keeping the last 2 pairs."

  [[profiles.clear_tool_results.strategies]]
  type = "ClearToolResults"
  max_tokens = 20_000
  keep_pairs = 2
```

A profile is a named list of strategies. Each entry's `type` names a harness
class and the remaining keys are handed to its constructor verbatim, so a
strategy gains a new option without any code change here. `tiers` and
`fallback_chain` nest, so `TieredCompaction` is expressed directly:

```toml
[[profiles.tiered.strategies]]
type = "TieredCompaction"
target_tokens = 20_000

  [[profiles.tiered.strategies.tiers]]
  type = "ClearToolResults"
  max_tokens = 1
  keep_pairs = 2

  [[profiles.tiered.strategies.tiers]]
  type = "SummarizingCompaction"
  max_messages = 1
  keep_messages = 8
```

The seven profiles shipped:

| Profile | Cost | What it does |
| --- | --- | --- |
| `none` | — | Baseline: the full transcript is resent every request |
| `clear_tool_results` | zero-LLM | Blanks the content of older tool results, keeping the last 2 pairs |
| `sliding_window` | zero-LLM | Drops the oldest whole messages down to a tail of 8 |
| `deduplicate` | zero-LLM | Blanks any tool result superseded by an identical later call |
| `clamp` | zero-LLM | Head/tail-truncates a single oversized part |
| `summarize` | one LLM call | Compresses older messages into a structured summary |
| `tiered` | escalates | Clamp, then clear, and summarize only if still over budget |

Pick one per run:

```bash
uv run sec-agent siem/alerts/S1_brute_force.json --compaction tiered
SEC_AGENT_COMPACTION=clear_tool_results uv run sec-agent siem/alerts/S1_brute_force.json
```

`deduplicate` is worth a note. `DeduplicateFileReads` is written for an agent
that re-reads files, and this one has none — but it does re-run queries, so the
config points its `file_key` at a named resolver that keys on the tool name plus
its normalised arguments. The same `search_events` twice, verbatim, then keeps
only the newer copy of the answer.

**The thresholds in `compaction.toml` are deliberately aggressive.** A triage run
is six or seven requests and tens of thousands of tokens, not the hundreds of
thousands these strategies ship defaults for. At default settings none of them
would ever fire on this corpus and the benchmark would measure nothing. They are
tuned to trigger, not to be run in production — scale them up, or switch to
`max_fraction`, once you know what your histories really look like.

---

## 9. What is compaction actually worth: `sec-agent-bench`

Compaction is not free in either direction. Clearing an old tool result saves
the tokens it occupied on every later request, but a model that can no longer
see the document it was about may go and fetch it again. Summarizing saves more
and costs a whole model call to do it. Whether either is a win is an empirical
question about *this* agent on *this* corpus.

`sec-agent-bench` runs every alert under every profile and measures three things
at once:

```bash
uv run sec-agent-bench                                  # all profiles, all alerts
uv run sec-agent-bench --profile none --profile tiered  # just two
uv run sec-agent-bench --repeat 3 --out results.json    # average, and keep the raw records
```

```
profile                    in     out    total    Δtok   $/alert      Δ$  peak ctx  reqs    sec   checks   cited
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
*none                  48,213   5,104   53,317       —   0.00280       —    21,904   7.0   41.2     48/48     100
 clear_tool_results    31,880   4,970   36,850     -31   0.00201     -28    12,110   7.2   38.7     46/48      92
 …
```

- **spend** — `in`/`out`/`total` tokens and the dollar cost of them, priced
  through [`genai-prices`](https://github.com/pydantic/genai-prices). The
  summarizing strategy folds its own model call into the run's usage, so an
  LLM-backed profile is billed for the summary it wrote.
- **pressure** — `peak ctx`, the largest estimated history sent during a run,
  measured with harness's own `ReportContextUsage` registered *after* the
  profile so it reads the compacted history. This is what compaction targets;
  total tokens is what it costs.
- **fidelity** — `checks` and `cited`, below.

### The fidelity checks

This is the column that matters. A profile that halves the cost and starts
returning `inconclusive`, or stops citing documents, has not made triage cheaper
— it has stopped doing triage. Eight checks run against the `TriageVerdict`
structure and `siem/ground_truth.json`:

| Check | Fails when |
| --- | --- |
| `alert_id` | The verdict does not say which alert it is about |
| `decided` | It returned `inconclusive` — every scenario in the corpus really happened |
| `positive` | It called planted activity a `false_positive` |
| `user_in_scope` | The scenario's account is missing from `scope.users` |
| `ip_in_scope` | The scenario's source address is missing from `scope.source_ips` |
| `timeline` | The timeline is empty |
| `grounded` | A timeline step cites no document id |
| `queries_recorded` | No queries were recorded |

`grounded` is the one compaction breaks first, and the reason it is worth
measuring at all: blank the tool result that carried a document id and the model
can still *describe* what happened — it just can no longer prove it, which is
the exact failure `INSTRUCTIONS` exists to prevent. A profile that saves 40% and
drops `cited` from 100% to 60% has traded auditability for tokens, and the table
shows you the trade instead of hiding it.

`benign_true_positive` deliberately passes `positive`: whether an off-hours admin
login from a corporate range is legitimate is a judgement the agent is allowed
to make. These are structural consistency checks, not a semantic grade — no
model is ever asked to grade another model's prose.

Runs that fail outright, and every individual fidelity failure, are listed under
the table with the profile and alert that produced them. `--out` writes the full
per-run records — including the per-request context readings — as JSON.

---

## 10. Troubleshooting

**`Elasticsearch at http://localhost:9200 is unreachable`**
The lab is not up. `cd siem && docker compose up -d`, then wait for
`curl localhost:9200/_cluster/health` to answer.

**The alert's window contains no events**
`generator.py` re-anchors timestamps to *now* on every run. Re-run
`make_alerts.py` after regenerating, or the alerts point at a window the data
no longer covers.

**`Exceeded maximum output retries (2)`**
The model returned responses with no actionable output — thinking text but no
tool call — more times than the retry budget allows. Common with smaller
OpenRouter models that write their tool calls into the reasoning channel as
prose. Raise `SEC_AGENT_RETRIES`, raise `SEC_AGENT_MAX_TOKENS` (a long run can
exhaust the budget on reasoning alone), lower `--effort`, or switch to a model
with sturdier tool calling. Re-run with `--trace` to see where it stalled.

**`Error: ANTHROPIC_API_KEY is not set (put it in .env)`**
The model prefix and the key you have do not match. Either set that key, or
switch `SEC_AGENT_MODEL` to a provider you do have a key for.

---

## 11. Development

```bash
uv run pytest        # tests (no API key needed — FunctionModel, no network)
uv run ruff check .  # lint
uv run ruff format . # format
```

### Adding a tool

Add it inside `build_agent` in `agent.py`:

```python
@agent.tool
def check_dependencies(ctx: RunContext[TriageDeps]) -> str:
    """Scan dependencies for known vulnerabilities."""
    ...
```

The docstring becomes the tool description sent to the model, and the JSON
schema is derived from the type hints. Raise `ModelRetry` for errors the model
can correct on its own — a malformed query, a disallowed index — and a plain
exception for the ones it cannot.
