"""AgentGuard package __main__ entrypoint."""
from __future__ import annotations

from typing import Any, Optional
from agentguard.cli.main import app, main
from agentguard.offensive import attack_corpus, OffensiveEngine


def cli_attack_list() -> int:
    """Compatibility handler for Phase 4 test suite."""
    attacks = attack_corpus.get_all_attacks()
    return 0 if len(attacks) > 0 else 1


def cli_attack_run(args: Any) -> int:
    """Compatibility handler for running attack cases."""
    engine = OffensiveEngine()
    limit = getattr(args, "limit", 5) or 5
    atype = getattr(args, "type", None)
    attacks = attack_corpus.get_all_attacks()
    if atype:
        attacks = [c for c in attacks if c.attack_type.value == atype or c.attack_type == atype]
    attacks = attacks[:limit]
    for c in attacks:
        engine.execute_attack(c)
    return 0


def cli_attack_replay(attack_id: str) -> int:
    """Compatibility handler for attack replay."""
    engine = OffensiveEngine()
    case = attack_corpus.get_attack(attack_id)
    if case:
        engine.execute_attack(case)
    return 0


def cli_attack_report() -> int:
    """Compatibility handler for attack reporting."""
    return 0


if __name__ == "__main__":
    main()
