"""Definition of the security analysis agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.models.anthropic import AnthropicModelSettings

from .settings import settings

Severity = Literal["info", "low", "medium", "high", "critical"]

# Define the data model for the agent's dependencies
@dataclass
class SecurityDeps:
    """Dependencies carried through a single agent run."""

    root: Path = field(default_factory=Path.cwd)
    """Root directory the file tools are not allowed to escape."""

    max_file_bytes: int = 200_000

    def resolve(self, relative_path: str) -> Path:
        """Safely resolve `relative_path` inside the root directory."""
        root = self.root.resolve()
        candidate = (root / relative_path).resolve()
        if not candidate.is_relative_to(root):
            raise ModelRetry(f"{relative_path!r} is outside the root directory; access denied.")
        return candidate

# Define the data model for a single security finding
class Finding(BaseModel):
    """A single security finding."""

    title: str = Field(description="Short title of the finding")
    severity: Severity
    file: str | None = Field(default=None, description="File path relative to the root directory")
    line: int | None = Field(default=None, description="1-indexed line number")
    description: str = Field(description="What is wrong and why it matters")
    recommendation: str = Field(description="Concrete suggested fix")


# Define the data model for the agent's output
class SecurityReport(BaseModel):
    """The agent's structured output."""

    summary: str = Field(description="One or two sentence summary of the review")
    findings: list[Finding] = Field(default_factory=list)


# System Instructions
INSTRUCTIONS = """\
You are an application security analyst. You review the given codebase and
report real, exploitable security vulnerabilities.

Rules:
- Base every finding on code you actually read in the files; do not speculate.
- For each finding you must be able to describe a concrete exploit scenario; if
  you cannot, do not report it.
- Style preferences, formatting, and anything unrelated to security are not findings.
- Order findings from most to least severe.
- If you find no issues, return an empty `findings` list and say so in the summary.
"""


def build_agent(
    *,
    model: str | None = None,
    effort: str | None = None,
) -> Agent[SecurityDeps, SecurityReport]:
    """Build the agent and register its tools."""
    agent = Agent(
        model or settings.model,
        deps_type=SecurityDeps,
        output_type=SecurityReport,
        instructions=INSTRUCTIONS,
        retries=settings.retries,
        model_settings=AnthropicModelSettings(
            max_tokens=settings.max_tokens,
            # Adaptive thinking: the model decides how much to think.
            anthropic_thinking={"type": "adaptive"},
            anthropic_effort=effort or settings.effort,
        ),
    )

    @agent.tool
    def list_files(ctx: RunContext[SecurityDeps], glob: str = "**/*.py") -> list[str]:
        """List files under the root directory matching a glob pattern.

        Args:
            glob: A glob pattern such as `**/*.py`.
        """
        root = ctx.deps.root.resolve()
        return sorted(
            str(p.relative_to(root))
            for p in root.glob(glob)
            if p.is_file() and ".venv" not in p.parts and ".git" not in p.parts
        )

    @agent.tool
    def read_file(ctx: RunContext[SecurityDeps], path: str) -> str:
        """Read a file inside the root directory, prefixed with line numbers.

        Args:
            path: File path relative to the root directory.
        """
        target = ctx.deps.resolve(path)
        if not target.is_file():
            raise ModelRetry(f"{path!r} not found. Use `list_files` first to see what exists.")
        if target.stat().st_size > ctx.deps.max_file_bytes:
            raise ModelRetry(f"{path!r} is too large ({target.stat().st_size} bytes).")

        text = target.read_text(encoding="utf-8", errors="replace")
        return "\n".join(f"{i:>5}\t{line}" for i, line in enumerate(text.splitlines(), start=1))

    return agent
