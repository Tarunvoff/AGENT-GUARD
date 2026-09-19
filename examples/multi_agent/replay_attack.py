"""Replay engine for reproducible attack evidence and verification."""

import json
import os
import sys
from typing import Any, Dict, Optional

# Ensure repository root is on sys.path
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from agentguard.client import AgentGuard
from examples.multi_agent.attack_scenario import run_attack_scenario


def load_attack_fixture(fixture_name: str) -> Dict[str, Any]:
    """Load a serialized attack fixture JSON file."""
    if not fixture_name.endswith(".json"):
        fixture_name = f"{fixture_name}.json"
    
    fixture_path = os.path.join(_repo_root, "examples", "attacks", fixture_name)
    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Attack fixture not found: {fixture_path}")

    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def replay_attack(fixture_name: str) -> bool:
    """Replay an attack scenario from fixture and verify deterministic defense."""
    fixture = load_attack_fixture(fixture_name)
    print(f"\n[REPLAY] Replaying Attack Fixture: {fixture.get('attack_id', fixture_name)}")
    print(f"  Type:        {fixture.get('attack_type')}")
    print(f"  Entry Point: {fixture.get('entry_point')}")
    print(f"  Target:      {fixture.get('target_capability')}")
    print(f"  Payload:     {fixture.get('payload')[:80]}...")

    guard = AgentGuard()
    res = run_attack_scenario(
        guard=guard,
        attack_type=fixture.get("attack_type", "indirect_prompt_injection"),
        custom_payload=fixture.get("payload"),
    )

    expected_decision = fixture.get("expected_decision", "BLOCK")
    is_success = (res.security_decision == expected_decision and res.blocked is True and res.customer_read_calls == 0)

    print(f"\n[REPLAY RESULT]")
    print(f"  Enforcement Decision: {res.security_decision} (Expected: {expected_decision})")
    print(f"  Attack Blocked:       {res.blocked}")
    print(f"  Customer DB Calls:    {res.customer_read_calls} (Verified 0)")
    print(f"  Replay Status:        {'PASS - DETERMINISTIC DEFENSE VERIFIED' if is_success else 'FAIL'}")

    return is_success


if __name__ == "__main__":
    fixtures = [
        "indirect_prompt_injection",
        "authority_impersonation",
        "tool_chain_escalation",
        "taint_laundering",
        "semantic_escalation",
    ]
    if len(sys.argv) > 1 and sys.argv[1] in ("--all", "-a"):
        print("=== REPLAYING ALL ATTACK FIXTURES ===")
        all_passed = True
        for fix in fixtures:
            passed = replay_attack(fix)
            if not passed:
                all_passed = False
        print(f"\n[SUMMARY] Replay All: {'ALL 5 FIXTURES PASSED' if all_passed else 'SOME FIXTURES FAILED'}")
        sys.exit(0 if all_passed else 1)
    else:
        target = sys.argv[1] if len(sys.argv) > 1 else "indirect_prompt_injection"
        success = replay_attack(target)
        sys.exit(0 if success else 1)

