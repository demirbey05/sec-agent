"""Application settings loaded from the environment."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from a `.env` file or the environment.

    Agent-specific settings use the `SEC_AGENT_` prefix; the API key matches
    `ANTHROPIC_API_KEY`, the name the Anthropic SDK reads on its own.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SEC_AGENT_",
        extra="ignore",
    )

    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    """The Anthropic SDK also reads this from the environment; we only check that it is set."""

    model: str = "anthropic:claude-opus-5"
    """Pydantic-AI model identifier."""

    effort: str = "high"
    """Reasoning depth / token spend: low | medium | high | xhigh | max."""

    max_tokens: int = 16_000

    es_url: str = "http://localhost:9200"
    """Base URL of the Elasticsearch cluster the triage tools query."""

    retries: int = 2


settings = Settings()
