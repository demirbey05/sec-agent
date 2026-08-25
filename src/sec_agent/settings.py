"""Application settings loaded from the environment."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROVIDER_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}
"""Which environment variable each supported provider authenticates with."""


def provider_of(model: str) -> str:
    """The provider half of a `provider:model` identifier."""
    provider, separator, _ = model.partition(":")
    return provider if separator else "anthropic"


class Settings(BaseSettings):
    """Settings loaded from a `.env` file or the environment.

    Agent-specific settings use the `SEC_AGENT_` prefix; API keys keep the names
    their own SDKs use, so an existing shell environment works unchanged.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SEC_AGENT_",
        extra="ignore",
    )

    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    openrouter_api_key: str | None = Field(default=None, validation_alias="OPENROUTER_API_KEY")

    model: str = "openrouter:openai/gpt-oss-120b"
    """Pydantic-AI model identifier, `provider:model`."""

    effort: str = "high"
    """Reasoning depth / token spend: low | medium | high | xhigh | max."""

    max_tokens: int = 16_000

    es_url: str = "http://localhost:9200"
    """Base URL of the Elasticsearch cluster the triage tools query."""

    retries: int = 2

    def api_key_for(self, model: str | None = None) -> tuple[str | None, str | None]:
        """Return `(env var name, key)` for the provider a model belongs to.

        The name is `None` for a provider we do not manage a key for, in which
        case the provider's own SDK is left to find its credentials.
        """
        variable = PROVIDER_KEY_VARS.get(provider_of(model or self.model))
        if variable is None:
            return None, None
        return variable, getattr(self, variable.lower(), None)


settings = Settings()
