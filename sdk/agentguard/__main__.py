"""AgentGuard CLI interface."""

import argparse
import json
import os
import pathlib
import sys
from typing import List, Optional

from agentguard.client import AgentGuard
from agentguard.llm_config import LLMConfig
from agentguard.offensive.attack import AttackType
from agentguard.offensive.campaign import AttackCampaign
from agentguard.offensive.corpus import AttackCorpus
from agentguard.offensive.engine import OffensiveEngine
from agentguard.offensive.results import AttackStatus
from agentguard.offensive.adaptive import (
    AdaptiveEngine,
    CampaignMemory,
    MutationNode,
)


def cli_llm_health() -> int:
    """Check connection to Ollama and print status."""
    config = LLMConfig.from_env()
    print("=" * 60)
    print("  AGENTGUARD LLM ADAPTER HEALTH CHECK")
    print("=" * 60)
    print(f"  Provider       : {config.provider}")
    print(f"  Model          : {config.model}")
    print(f"  Base URL       : {config.base_url}")
    print(f"  Timeout        : {config.timeout}s")
    print(f"  Enabled        : {config.enabled}")
    print("-" * 60)

    from agentguard.integrations.ollama_adapter import OllamaAISecuraAdapter
    adapter = OllamaAISecuraAdapter(config)
    health = adapter.health_check()

    status_str = "AVAILABLE" if health.get("available") else "UNAVAILABLE"
    print(f"  Status         : {status_str}")
    print(f"  Model Present  : {health.get('model_present', False)}")
    print(f"  Latency        : {health.get('latency_ms', 0):.1f}ms")
    if "error" in health:
        print(f"  Error          : {health['error']}")
    print("=" * 60)
    return 0 if health.get("available") else 1


def cli_attack_list():
    """List all available attack cases in baseline and regression corpus."""
    corpus = AttackCorpus()
    baseline = corpus.get_all_attacks()
    regressions = corpus.get_regression_attacks()

    print("=" * 78)
    print("  AGENTGUARD OFFENSIVE ATTACK CORPUS")
    print("=" * 78)
    print(f"  {'ATTACK ID':<28} | {'TYPE':<25} | {'TARGET AGENT':<15} | {'EXP'}")
    print("-" * 78)
    for a in baseline:
        atype = a.attack_type.value if hasattr(a.attack_type, 'value') else str(a.attack_type)
        exp_val = a.expected_behavior.value if hasattr(getattr(a, 'expected_behavior', None), 'value') else str(getattr(a, 'expected_behavior', 'BLOCK'))
        print(f"  {a.attack_id:<28} | {atype:<25} | {a.target_agent:<15} | {exp_val}")

    print("-" * 78)
    print(f"  REGRESSION FIXTURES ({len(regressions)}):")
    for r in regressions:
        atype = r.attack_type.value if hasattr(r.attack_type, 'value') else str(r.attack_type)
        exp_val = r.expected_behavior.value if hasattr(getattr(r, 'expected_behavior', None), 'value') else str(getattr(r, 'expected_behavior', 'BLOCK'))
        print(f"  * {r.attack_id:<26} | {atype:<25} | {r.target_agent:<15} | {exp_val}")
    print("=" * 78)
    return 0


def cli_attack_run(args):
    """Run validation attack campaign."""
    engine = OffensiveEngine()
    corpus = AttackCorpus()

    if args.type:
        try:
            atype = AttackType(args.type)
            cases = corpus.get_attacks_by_type(atype)
        except ValueError:
            print(f"Invalid attack type: {args.type}")
            return 1
    else:
        cases = corpus.get_all_attacks()

    if args.limit:
        cases = cases[:args.limit]

    target = engine.registry.get("agentguard-demo")
    campaign = AttackCampaign(
        name="CLI Validation Campaign",
        objective="Validate defenses against corpus",
        target=target,
        attacks=cases,
    )

    print("=" * 78)
    print(f"  AGENTGUARD OFFENSIVE VALIDATION ENGINE")
    print(f"  Target:    {target.target_id} ({target.name})")
    print(f"  Attacks:   {len(cases)}")
    print("=" * 78)

    results, summary = engine.execute_campaign(campaign)

    for idx, r in enumerate(results, 1):
        status_tag = f"[{r.status.value}]"
        print(f"  {idx:02d}. {status_tag:<8} {r.attack_id:<28} | Act: {r.actual_decision:<6} | {r.latency_ms:6.1f}ms")

    print("-" * 78)
    print(f"  Summary: {summary.blocked}/{summary.total_attacks} Blocked ({summary.block_rate_pct}%) | "
          f"Bypasses: {summary.bypassed} | Sensitive DB Calls: {summary.sensitive_actions_executed}")
    print("=" * 78)

    engine.export_reports(summary, results)
    return 0 if summary.bypassed == 0 else 1


def cli_attack_adaptive(args):
    """Run adaptive offensive validation campaign."""
    adaptive_engine = AdaptiveEngine(
        max_depth=getattr(args, "max_depth", 3) or 3,
        branch_factor=getattr(args, "branch_factor", 2) or 2,
        seed=getattr(args, "seed", 20260919) or 20260919,
    )

    family = getattr(args, "family", None)
    attack_id = getattr(args, "attack_id", None)
    limit = getattr(args, "limit", None)

    print("=" * 78)
    print("  AGENTGUARD ADAPTIVE OFFENSIVE SECURITY VALIDATION (PHASE 5)")
    print(f"  Max Depth: {adaptive_engine.max_depth} | Branch Factor: {adaptive_engine.branch_factor} | Seed: {adaptive_engine.seed}")
    if family:
        print(f"  Family:    {family}")
    if attack_id:
        print(f"  Attack ID: {attack_id}")
    print("=" * 78)

    results, summary, memory = adaptive_engine.run_adaptive_campaign(
        family=family,
        attack_id=attack_id,
        limit_seeds=limit,
    )

    for r in results:
        depth = len(r.mutation_lineage) - 1 if r.mutation_lineage else 0
        depth_tag = f"[D{depth}]"
        status_tag = f"[{r.status.value}]"
        reason = r.execution_evidence.policy_reason or "ALLOWED"
        print(f"  {depth_tag:<5} {status_tag:<8} {r.attack_id:<32} | Dec: {r.actual_decision:<6} | Reason: {reason[:28]:<28} | {r.latency_ms:5.1f}ms")

    print("-" * 78)
    print(f"  Scorecard: {summary.blocked}/{summary.total_attacks} Blocked ({summary.block_rate_pct}%) | "
          f"Bypasses: {summary.bypassed} | Prevention Rate: {summary.empirical_prevention_rate * 100:.1f}%")
    print(f"  Mutations: {summary.unique_attack_variants} variants (Max Depth: {summary.max_mutation_depth}) | "
          f"Mean Latency: {summary.mean_latency_ms}ms")
    print("=" * 78)

    adaptive_engine.export_dashboard_json(summary, results, memory)
    return 0 if summary.bypassed == 0 else 1


def cli_attack_regressions():
    """List all stored regression fixtures."""
    corpus = AttackCorpus()
    regs = corpus.get_regression_attacks()
    print("=" * 78)
    print(f"  STORED REGRESSION FIXTURES ({len(regs)})")
    print("=" * 78)
    for idx, r in enumerate(regs, 1):
        print(f"  {idx:02d}. {r.attack_id:<32} | Type: {r.attack_type.value:<24} | Target: {r.target_agent}")
        print(f"      Payload: {r.payload[:60]}...")
    print("=" * 78)
    return 0


def cli_attack_lineage(attack_id: str):
    """Show the mutation lineage tree leading to an attack."""
    print("=" * 78)
    print(f"  ATTACK MUTATION LINEAGE: '{attack_id}'")
    print("=" * 78)

    # Check regression fixtures
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    reg_file = root / "examples" / "attacks" / "regressions" / f"{attack_id}.json"

    if reg_file.exists():
        try:
            data = json.loads(reg_file.read_text(encoding="utf-8"))
            print(f"  [Root Attack]  {data.get('attack_id', attack_id)}")
            print(f"  [Attack Type]  {data.get('attack_type')}")
            print(f"  [Target Tool]  {data.get('target_tool')}")
            print(f"  [Entry Point]  {data.get('entry_point')}")
            print(f"  [Description]  {data.get('description')}")
            print(f"  [Saved Reason] {data.get('metadata', {}).get('regression_reason', 'Bypass detected')}")
            print("=" * 78)
            return 0
        except Exception as e:
            print(f"Error reading regression fixture: {e}")

    # Fallback to general attack search
    corpus = AttackCorpus()
    attack = corpus.get_attack(attack_id)
    if attack:
        print(f"  [Attack Case]  {attack.attack_id}")
        print(f"  [Parent ID]    {attack.mutation_of or 'None (Root Seed)'}")
        print(f"  [Strategy]     {attack.mutation_strategy or 'Baseline'}")
        print(f"  [Target Tool]  {attack.target_tool}")
        print(f"  [Payload]      {attack.payload}")
        print("=" * 78)
        return 0

    print(f"Attack ID '{attack_id}' not found in corpus or regressions.")
    return 1


def cli_attack_explain(attack_id: str):
    """Explain the end-to-end security decision and evidence for an attack."""
    engine = OffensiveEngine()
    corpus = AttackCorpus()
    attack = corpus.get_attack(attack_id)
    if not attack:
        print(f"Attack ID '{attack_id}' not found.")
        return 1

    print("=" * 78)
    print(f"  EXPLAINING ATTACK DEFENSE: '{attack_id}'")
    print("=" * 78)
    res = engine.execute_attack(attack)

    print(f"  Original Intent   : {attack.task_intent}")
    print(f"  Target Agent      : {attack.target_agent}")
    print(f"  Entry Point       : {attack.entry_point}")
    print(f"  Context Taint     : {attack.context_taint}")
    print(f"  Target Tool       : {attack.target_tool}")
    print("-" * 78)
    if res.security_evidence:
        ev = res.security_evidence
        print(f"  APIRIS Analysis   : Risk Score {ev.apiris_analysis.get('risk_score', 'N/A') if ev.apiris_analysis else 'N/A'} (Unavailable: {ev.apiris_unavailable})")
        print(f"  AI Secura Reason  : {ev.ai_analysis.get('summary', 'N/A') if ev.ai_analysis else 'N/A'} (Unavailable: {ev.ai_unavailable})")
        print(f"  Authority Check   : {'PASSED' if ev.authority_contained else 'VIOLATED (' + ev.authority_reason + ')'}")
        print(f"  Intent Alignment  : {'PASSED' if ev.intent_aligned else 'VIOLATED (' + ev.intent_explanation + ')'}")
    print("-" * 78)
    print(f"  Policy Decision   : {res.actual_decision}")
    print(f"  Policy Reason     : {res.execution_evidence.policy_reason}")
    print(f"  Tool Executed     : {res.execution_evidence.tool_executed}")
    print(f"  Sensitive DB Calls: {res.execution_evidence.sensitive_db_calls}")
    print(f"  Final Verdict     : {'DEFENDED [PASS]' if not res.bypassed else 'SECURITY BYPASS [BYPASS]'}")
    print("=" * 78)
    return 0


def cli_attack_replay(attack_id: str):
    """Replay a specific attack fixture by ID."""
    engine = OffensiveEngine()
    print(f"Replaying attack fixture: '{attack_id}'...")
    try:
        res = engine.replay_attack(attack_id)
        print(f"Outcome: [{res.status.value}] Action: {res.actual_decision} (Bypassed: {res.bypassed})")
        print(f"Sensitive DB Calls: {res.execution_evidence.sensitive_db_calls}")
        return 0 if res.status == AttackStatus.PASS else 1
    except Exception as e:
        print(f"Replay Error: {e}")
        return 1


def cli_attack_report():
    """Print the latest generated security scorecard."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    report_file = root / "reports" / "phase5" / "adaptive_campaign_summary.md"
    if not report_file.exists():
        report_file = root / "reports" / "phase4" / "campaign_summary.md"
    if not report_file.exists():
        print("No report found. Run 'python -m agentguard attack adaptive' or 'run --all' first.")
        return 1

    print(report_file.read_text(encoding="utf-8"))
    return 0


def main():
    args = sys.argv[1:]

    if not args:
        print("AgentGuard CLI")
        print("Usage:")
        print("  python -m agentguard attack list")
        print("  python -m agentguard attack run [--all] [--type <type>] [--limit <N>]")
        print("  python -m agentguard attack adaptive [--family <f>] [--attack-id <id>] [--max-depth <N>] [--seed <s>]")
        print("  python -m agentguard attack replay <attack_id> [--id <attack_id>]")
        print("  python -m agentguard attack regressions")
        print("  python -m agentguard attack lineage <attack_id> [--id <attack_id>]")
        print("  python -m agentguard attack explain <attack_id> [--id <attack_id>]")
        print("  python -m agentguard attack report")
        print("  python -m agentguard llm health")
        print("  python -m agentguard version")
        sys.exit(0)

    cmd = args[0]

    if cmd == "llm" and len(args) >= 2 and args[1] == "health":
        sys.exit(cli_llm_health())
    elif cmd == "version":
        print("agentguard 0.5.0")
        sys.exit(0)
    elif cmd == "attack":
        subcmd = args[1] if len(args) > 1 else "help"
        if subcmd == "list":
            sys.exit(cli_attack_list())
        elif subcmd == "run":
            parser = argparse.ArgumentParser()
            parser.add_argument("--all", action="store_true")
            parser.add_argument("--type", type=str, default=None)
            parser.add_argument("--limit", type=int, default=None)
            parsed = parser.parse_args(args[2:])
            sys.exit(cli_attack_run(parsed))
        elif subcmd == "adaptive":
            parser = argparse.ArgumentParser()
            parser.add_argument("--family", type=str, default=None)
            parser.add_argument("--attack-id", type=str, default=None)
            parser.add_argument("--limit", type=int, default=None)
            parser.add_argument("--max-depth", type=int, default=3)
            parser.add_argument("--branch-factor", type=int, default=2)
            parser.add_argument("--seed", type=int, default=20260919)
            parsed = parser.parse_args(args[2:])
            sys.exit(cli_attack_adaptive(parsed))
        elif subcmd == "regressions":
            sys.exit(cli_attack_regressions())
        elif subcmd == "replay":
            parser = argparse.ArgumentParser()
            parser.add_argument("attack_id_pos", nargs="?", default=None)
            parser.add_argument("--id", "--attack-id", dest="attack_id_flag", default=None)
            parsed = parser.parse_args(args[2:])
            atk_id = parsed.attack_id_flag or parsed.attack_id_pos
            if not atk_id:
                print("Usage: python -m agentguard attack replay <attack_id>")
                sys.exit(1)
            sys.exit(cli_attack_replay(atk_id))
        elif subcmd == "lineage":
            parser = argparse.ArgumentParser()
            parser.add_argument("attack_id_pos", nargs="?", default=None)
            parser.add_argument("--id", "--attack-id", dest="attack_id_flag", default=None)
            parsed = parser.parse_args(args[2:])
            atk_id = parsed.attack_id_flag or parsed.attack_id_pos
            if not atk_id:
                print("Usage: python -m agentguard attack lineage <attack_id>")
                sys.exit(1)
            sys.exit(cli_attack_lineage(atk_id))
        elif subcmd == "explain":
            parser = argparse.ArgumentParser()
            parser.add_argument("attack_id_pos", nargs="?", default=None)
            parser.add_argument("--id", "--attack-id", dest="attack_id_flag", default=None)
            parsed = parser.parse_args(args[2:])
            atk_id = parsed.attack_id_flag or parsed.attack_id_pos
            if not atk_id:
                print("Usage: python -m agentguard attack explain <attack_id>")
                sys.exit(1)
            sys.exit(cli_attack_explain(atk_id))
        elif subcmd == "report":
            sys.exit(cli_attack_report())
        else:
            print("Usage: python -m agentguard attack [list|run|adaptive|replay|regressions|lineage|explain|report]")
            sys.exit(1)
    else:
        print(f"Unknown command: {' '.join(args)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
