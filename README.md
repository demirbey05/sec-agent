# sec-agent

An agent built with [Pydantic AI](https://ai.pydantic.dev/) that triages
authentication alerts against Elasticsearch, and a self-contained SIEM lab to
try it on.

## Setup

```bash
uv sync
cp .env.example .env   # fill in the key for the model you picked
```

The model comes from `SEC_AGENT_MODEL`, written as `provider:model`. It decides
which key is read, so only one needs to be set:

| `SEC_AGENT_MODEL` | Key |
| --- | --- |
| `openrouter:openai/gpt-oss-120b` (default, free tier) | `OPENROUTER_API_KEY` |
| `anthropic:claude-opus-5` | `ANTHROPIC_API_KEY` |

Keys are read from `.env` and passed to the provider explicitly, so nothing has
to be exported into the shell.

## The lab

The agent needs authentication logs to triage. `siem/` brings up a throwaway
Elasticsearch, fills it with seven days of synthetic traffic, and plants six
attack scenarios whose answers are recorded in `ground_truth.json`.

```bash
cd siem
docker compose up -d              # Elasticsearch :9200, Kibana :5601
uv run python generator.py --recreate   # ~2.5k events into `auth-logs`
uv run python make_alerts.py            # one alert JSON per scenario
```

`generator.py` anchors everything to *now*, so the timestamps move every time
you regenerate. Re-run `make_alerts.py` afterwards — it reads the numbers each
rule would have measured back out of Elasticsearch, so the alerts stay honest
about what a detector could actually know.

The planted scenarios: brute force ending in a success, password spray,
impossible travel, off-hours admin login, a dormant account waking up, and a
service account authenticating the wrong way.

## Usage

```bash
uv run sec-agent siem/alerts/S1_brute_force.json

# Machine-readable output
uv run sec-agent siem/alerts/S3_impossible_travel.json --json

# A cheaper/faster run
uv run sec-agent siem/alerts/S4_offhours_admin.json --effort low

# A different model for one run
uv run sec-agent siem/alerts/S2_password_spray.json --model anthropic:claude-opus-5
```

`--effort` controls reasoning depth: `low`, `medium`, `high` (default),
`xhigh`, `max`. On Anthropic it maps to `anthropic_effort` with adaptive
thinking; everywhere else to Pydantic AI's unified `thinking` level, which
OpenRouter forwards as `reasoning.effort` (`max` becomes `xhigh`, the closest
level outside Anthropic). `--model` overrides the model for one run; `--es-url`
points at a different cluster; `--index` adds an index to the tools' allowlist.

Compare the verdict against `siem/ground_truth.json` — the agent never sees it.
The alerts carry the detector's claim; the agent is expected to disagree with it
when the data says otherwise. `S1` is the clearest example: the rule fires on
213 failures in a three-minute window and stops there, so the successful login
four seconds past the window is the agent's to find.

## Layout

| File | Contents |
| --- | --- |
| `src/sec_agent/settings.py` | Environment/`.env` config, and which key each provider needs |
| `src/sec_agent/agent.py` | Alert/verdict schemas, model wiring, dependencies, tools, instructions |
| `src/sec_agent/cli.py` | The `sec-agent` command line interface |
| `siem/docker-compose.yml` | Dev-only Elasticsearch + Kibana, security disabled |
| `siem/generator.py` | Synthetic log generator and the answer key |
| `siem/make_alerts.py` | Ground truth → the alerts a detector would have raised |
| `tests/` | Tests using `FunctionModel` — no API calls |

The agent has three tools: `search_events` (raw documents), `aggregate_events`
(counts grouped by a field) and `entity_baseline` (what one user, IP or host
normally looks like before the alert). All three are confined to
`TriageDeps.allowed_indices`, and `labels.scenario` — the lab's answer key — is
stripped from every result.

Output is validated against the `TriageVerdict` schema: a verdict
(`true_positive`, `benign_true_positive`, `false_positive`, `inconclusive`), the
agent's own severity and confidence, a timeline citing document ids, the queries
it ran, and what a responder should do next.

## Development

```bash
uv run pytest        # tests (no API key needed)
uv run ruff check .  # lint
uv run ruff format . # format
```

## Adding a tool

Add it inside `build_agent` in `agent.py`:

```python
@agent.tool
def check_dependencies(ctx: RunContext[SecurityDeps]) -> str:
    """Scan dependencies for known vulnerabilities."""
    ...
```

The docstring becomes the tool description sent to the model, and the JSON schema
is derived from the type hints. Raise `ModelRetry` for errors the model can correct.
