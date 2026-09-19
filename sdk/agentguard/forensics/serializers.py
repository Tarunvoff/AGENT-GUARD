"""JSON serializers for forensic exports.

All forensic data exported to reports/forensics/ uses stable schemas.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def _default_serializer(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def to_json(data: Any, indent: int = 2) -> str:
    """Serialize forensic data to JSON string."""
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    return json.dumps(data, indent=indent, default=_default_serializer)


def export_json(
    data: Any,
    filepath: str,
    indent: int = 2,
) -> str:
    """Export forensic data to a JSON file. Creates directory if needed."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    content = to_json(data, indent=indent)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def sanitize_for_export(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive fields before export.

    Strips: credentials, tokens, raw passwords, internal paths.
    """
    SENSITIVE_KEYS = {
        "password", "secret", "token", "api_key", "credential",
        "authorization", "bearer", "private_key",
    }
    if not isinstance(data, dict):
        return data
    result = {}
    for key, value in data.items():
        if any(s in key.lower() for s in SENSITIVE_KEYS):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = sanitize_for_export(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_for_export(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    return result
