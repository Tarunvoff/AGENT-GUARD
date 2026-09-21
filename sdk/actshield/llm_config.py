"""LLM provider configuration for ActShield AI Secura reasoning engine.

Reads from environment variables. No hardcoded values.

Variables:
    AGENTGUARD_LLM_PROVIDER   : 'ollama' or 'local' (default: 'local')
    AGENTGUARD_LLM_MODEL      : model name (default: 'qwen2.5:7b')
    AGENTGUARD_OLLAMA_BASE_URL: Ollama server URL (default: 'http://localhost:11434')
    AGENTGUARD_LLM_TIMEOUT    : request timeout seconds (default: 30)
    AGENTGUARD_LLM_MAX_TOKENS : max response tokens (default: 2048)
    AGENTGUARD_LLM_TEMPERATURE: sampling temperature (default: 0.1)
"""

import os
from typing import Literal
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """Runtime configuration for the AI Secura LLM reasoning engine."""

    provider: Literal["ollama", "local"] = Field(
        default="local",
        description="LLM provider: 'ollama' for real AI reasoning, 'local' for deterministic heuristic adapter",
    )
    model: str = Field(
        default="qwen2.5:7b",
        description="Model identifier (e.g. 'qwen2.5:7b', 'ai-secura')",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the Ollama server",
    )
    timeout_seconds: int = Field(
        default=60,
        ge=5,
        le=300,
        description="HTTP request timeout in seconds for Ollama calls",
    )
    max_tokens: int = Field(
        default=512,
        ge=256,
        le=8192,
        description="Maximum tokens the model may generate per analysis",
    )
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Sampling temperature. Low values produce deterministic, consistent security analysis.",
    )
    num_ctx: int = Field(
        default=8192,
        ge=2048,
        description="Ollama context window size in tokens",
    )
    repair_on_invalid_json: bool = Field(
        default=True,
        description="Attempt exactly one JSON repair request if the initial response is malformed",
    )
    fallback_to_local_on_error: bool = Field(
        default=True,
        description="Return an ai_unavailable=True analysis when Ollama is unreachable",
    )

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            provider=os.environ.get("AGENTGUARD_LLM_PROVIDER", "local"),  # type: ignore[arg-type]
            model=os.environ.get("AGENTGUARD_LLM_MODEL", "qwen2.5:7b"),
            ollama_base_url=os.environ.get("AGENTGUARD_OLLAMA_BASE_URL", "http://localhost:11434"),
            timeout_seconds=int(os.environ.get("AGENTGUARD_LLM_TIMEOUT", "30")),
            max_tokens=int(os.environ.get("AGENTGUARD_LLM_MAX_TOKENS", "2048")),
            temperature=float(os.environ.get("AGENTGUARD_LLM_TEMPERATURE", "0.1")),
            num_ctx=int(os.environ.get("AGENTGUARD_LLM_NUM_CTX", "8192")),
        )

    @property
    def ollama_generate_url(self) -> str:
        return f"{self.ollama_base_url.rstrip('/')}/api/generate"

    @property
    def ollama_tags_url(self) -> str:
        return f"{self.ollama_base_url.rstrip('/')}/api/tags"

    @property
    def is_ollama(self) -> bool:
        return self.provider == "ollama"

