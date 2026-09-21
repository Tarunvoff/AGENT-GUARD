"""Configuration module for ActShield SDK."""

import re
from typing import Any, Callable, Dict, List, Optional, Pattern
from pydantic import BaseModel, Field


DEFAULT_SECRET_PATTERNS: List[Pattern[str]] = [
    re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}"),
    re.compile(r"(?i)(api[_\-]?key|secret|token|password|passwd|auth[_\-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"),
    re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,})"),
    re.compile(r"(?i)(ghp_[a-zA-Z0-9]{36})"),
    re.compile(r"(?i)(xox[baprs]-[a-zA-Z0-9\-]{10,})"),
]

SENSITIVE_KEY_NAMES = {
    "api_key", "apikey", "secret", "password", "passwd", "token", 
    "access_token", "auth_token", "private_key", "secret_key", 
    "credentials", "authorization"
}


def default_redact_function(data: Any) -> Any:
    """Recursively redacts secrets and sensitive key values."""
    if isinstance(data, str):
        result = data
        for pattern in DEFAULT_SECRET_PATTERNS:
            result = pattern.sub(r"\1[REDACTED]", result)
        return result
    elif isinstance(data, dict):
        redacted_dict: Dict[str, Any] = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEY_NAMES:
                redacted_dict[k] = "[REDACTED]"
            else:
                redacted_dict[k] = default_redact_function(v)
        return redacted_dict
    elif isinstance(data, list):
        return [default_redact_function(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(default_redact_function(item) for item in data)
    return data


class ActShieldConfig(BaseModel):
    """Runtime configuration for actshield."""
    
    app_name: str = Field(default="ActShield", description="Application or service name")
    environment: str = Field(default="production", description="Runtime environment (development, staging, production)")
    enforcement_mode: str = Field(default="STRICT", description="Control plane enforcement mode (STRICT, MONITOR, AUDIT)")
    enforce_monotonic_delegation: bool = Field(

        default=True,
        description="Whether an agent is strictly forbidden from delegating authority it was not granted"
    )
    block_tainted_sink_access: bool = Field(
        default=True,
        description="Whether tainted untrusted context is blocked from invoking critical sensitive tools"
    )
    default_risk_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Risk score above which actions are blocked or require human approval"
    )
    redact_secrets: bool = Field(
        default=True,
        description="Whether to sanitize secret patterns from emitted events, context, and trace payloads"
    )
    custom_redactor: Optional[Callable[[Any], Any]] = Field(
        default=None,
        description="Custom redaction callable if specified"
    )

    def sanitize(self, data: Any) -> Any:
        """Sanitize data using configured redactor."""
        if not self.redact_secrets:
            return data
        if self.custom_redactor:
            return self.custom_redactor(data)
        return default_redact_function(data)


# Backward compatibility alias
AgentGuardConfig = ActShieldConfig



