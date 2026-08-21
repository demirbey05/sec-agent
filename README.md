# sec-agent

An agent built with [Pydantic AI](https://ai.pydantic.dev/) that reviews a
codebase for security vulnerabilities. It uses Anthropic Claude Opus 5.

## Setup

```bash
uv sync
cp .env.example .env   # fill in ANTHROPIC_API_KEY
```

## Usage

```bash
# Review the working directory
uv run sec-agent

# Review another directory with a custom task
uv run sec-agent "Focus on the authentication flow" --root ../other-project

# Machine-readable output
uv run sec-agent --json

# A cheaper/faster run
uv run sec-agent --effort low
```

`--effort` controls reasoning depth: `low`, `medium`, `high` (default),
`xhigh`, `max`.

## Layout

| File | Contents |
| --- | --- |
| `src/sec_agent/settings.py` | Environment/`.env` config via `pydantic-settings` |
| `src/sec_agent/agent.py` | Agent definition, dependencies, tools, output schema |
| `src/sec_agent/cli.py` | The `sec-agent` command line interface |
| `tests/` | Tests using `FunctionModel` — no API calls |

The agent has two tools, `list_files` and `read_file`. Both are confined to the
`SecurityDeps.root` directory — paths that escape it are rejected.

Output is validated against the `SecurityReport` schema: a summary plus a list of
`Finding` objects (title, severity, file/line, description, recommendation).

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
