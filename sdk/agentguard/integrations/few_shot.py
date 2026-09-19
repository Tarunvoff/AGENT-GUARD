"""Deterministic few-shot example selector for AI Secura prompts.

Selects up to MAX_EXAMPLES relevant examples based on:
  - Protocol (mcp, http, rag, tool, api)
  - Taint state (TAINTED, CLEAN)
  - Resource sensitivity (CRITICAL, HIGH, MEDIUM, LOW)
  - Attack category hint

No vector database. Pure rule-based selection from the examples directory.
"""

import json
import pathlib
from typing import Any, Dict, List, Optional

_EXAMPLES_DIR = pathlib.Path(__file__).parent / "prompts" / "examples"
MAX_EXAMPLES = 4


def _load_example(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _score_example(ex: Dict[str, Any], context: Dict[str, Any]) -> int:
    """Return relevance score (higher = more relevant)."""
    score = 0
    ex_tags = set(ex.get("tags", []))

    # Protocol match
    provenance = context.get("context_provenance", [])
    src = " ".join(str(p) for p in provenance).lower()
    tool_name = str(context.get("tool", {}).get("name", "")).lower()
    if "mcp" in src and "mcp" in ex_tags:
        score += 3
    if "http" in src or "api" in src:
        if "http" in ex_tags or "api" in ex_tags:
            score += 3
    if "rag" in src and "rag" in ex_tags:
        score += 3

    # Taint state match
    taint_states = context.get("taint_states", [])
    has_taint = any(t in ("TAINTED", "UNTRUSTED") for t in taint_states)
    if has_taint and "tainted" in ex_tags:
        score += 2
    if not has_taint and "clean" in ex_tags:
        score += 2

    # Sensitivity match
    sensitivity = str(context.get("resource", {}).get("sensitivity", "")).upper()
    if sensitivity in ("CRITICAL", "HIGH") and "critical_sink" in ex_tags:
        score += 2
    if sensitivity in ("LOW", "MEDIUM") and "low_risk" in ex_tags:
        score += 1

    # Attack category match
    ex_threat = ex.get("expected_output", {}).get("attack_technique", "")
    det_policy = context.get("deterministic_policy", {})
    reason_codes = " ".join(det_policy.get("reason_codes", []))
    if "injection" in reason_codes.lower() and "injection" in ex_threat:
        score += 2
    if "authority" in reason_codes.lower() and "escalation" in ex_threat:
        score += 2

    return score


def select_few_shot_examples(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return up to MAX_EXAMPLES ordered by relevance to context."""
    if not _EXAMPLES_DIR.exists():
        return []

    examples = []
    for path in sorted(_EXAMPLES_DIR.glob("*.json")):
        ex = _load_example(path)
        if ex:
            ex["_score"] = _score_example(ex, context)
            examples.append(ex)

    examples.sort(key=lambda e: e["_score"], reverse=True)
    return [
        {k: v for k, v in ex.items() if k != "_score"}
        for ex in examples[:MAX_EXAMPLES]
    ]


def format_examples_for_prompt(examples: List[Dict[str, Any]]) -> str:
    """Format selected examples as a few-shot block for the system prompt."""
    if not examples:
        return ""
    lines = ["\n\n### FEW-SHOT EXAMPLES\n"]
    for i, ex in enumerate(examples, 1):
        lines.append(f"#### Example {i}: {ex.get('description', '')}\n")
        lines.append("Input:\n```json")
        lines.append(json.dumps(ex.get("input", {}), indent=2))
        lines.append("```\n")
        lines.append("Expected Output:\n```json")
        lines.append(json.dumps(ex.get("expected_output", {}), indent=2))
        lines.append("```\n")
    return "\n".join(lines)
