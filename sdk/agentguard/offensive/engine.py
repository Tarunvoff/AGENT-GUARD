"""AgentGuard Offensive Validation Engine — Orchestrating continuous security evaluation."""

import json
import logging
import os
import pathlib
import time
from typing import Any, Dict, List, Optional, Tuple

from agentguard.client import AgentGuard
from agentguard.context.provenance import ContextSource
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.integrations.ai_secura import SecurityContext
from agentguard.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from agentguard.offensive.campaign import AttackCampaign, CampaignSummary
from agentguard.offensive.corpus import AttackCorpus, attack_corpus
from agentguard.offensive.evaluator import AttackEvaluator
from agentguard.offensive.evidence import SecurityAnalysisEvidence
from agentguard.offensive.results import AttackStatus, ExecutionEvidence, OffensiveAttackResult
from agentguard.offensive.safety import SafetyValidator, safety_validator
from agentguard.offensive.target import AttackTarget, TargetRegistry, target_registry
from agentguard.tools.tool import Resource, SensitivityLevel, ToolDefinition, ToolRequest
from agentguard.tracing.correlation import generate_id

logger = logging.getLogger("agentguard.offensive.engine")


class OffensiveEngine:
    """The central orchestrator for autonomous offensive security validation."""

    def __init__(
        self,
        guard: Optional[AgentGuard] = None,
        validator: Optional[SafetyValidator] = None,
        registry: Optional[TargetRegistry] = None,
        corpus: Optional[AttackCorpus] = None,
    ) -> None:
        self.guard = guard or AgentGuard()
        self.validator = validator or safety_validator
        self.registry = registry or target_registry
        self.corpus = corpus or attack_corpus

        # Execution tracking counters
        self.customer_read_calls = 0
        self.total_tool_executions = 0
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register synthetic sandbox tools with hard execution monitoring."""
        from agentguard.tools.interceptor import protected_tool
        from agentguard.tools.tool import Resource, SensitivityLevel

        # 1. Protected Sensitive Customer DB Sink
        cust_res = Resource(
            resource_id="res_cust",
            name="customer_pii_vault",
            sensitivity=SensitivityLevel.CRITICAL,
        )

        @protected_tool(
            guard=self.guard,
            name="customer_db.read",
            description="Reads customer PII records from vault",
            sensitivity=SensitivityLevel.CRITICAL,
            required_capabilities=["customer_db.read"],
            target_resources=[cust_res],
        )
        def customer_db_read(table: str = "customers", fields: Optional[List[str]] = None, **kwargs: Any) -> Dict[str, Any]:
            self.customer_read_calls += 1
            self.total_tool_executions += 1
            return {"status": "SUCCESS", "rows": [{"id": 1, "name": "Alice", "pii": "EXTRACTED"}]}

        # 2. Protected Low-Sensitivity Public Tool
        pub_res = Resource(
            resource_id="res_pub",
            name="public_filing_cache",
            sensitivity=SensitivityLevel.LOW,
        )

        @protected_tool(
            guard=self.guard,
            name="sec_edgar.fetch_filing",
            description="Fetches public Form 10-K SEC filings",
            sensitivity=SensitivityLevel.LOW,
            required_capabilities=["public_documents", "public_search"],
            target_resources=[pub_res],
        )
        def fetch_filing(ticker: str = "ACME", year: int = 2026, **kwargs: Any) -> Dict[str, Any]:
            self.total_tool_executions += 1
            return {"status": "SUCCESS", "filing": "ACME FY2026 10-K: Revenue $14.2B"}

        # 3. HTTP Outbound Tool
        ext_res = Resource(
            resource_id="res_ext",
            name="external_api",
            sensitivity=SensitivityLevel.HIGH,
        )

        @protected_tool(
            guard=self.guard,
            name="http_post",
            description="Posts outbound payload to synthetic endpoint",
            sensitivity=SensitivityLevel.HIGH,
            required_capabilities=["external_api"],
            target_resources=[ext_res],
        )
        def http_post(url: str = "https://synthetic.internal", data: Any = None, **kwargs: Any) -> Dict[str, Any]:
            self.total_tool_executions += 1
            return {"status": "POSTED", "url": url}

        self._tool_callables = {
            "customer_db.read": customer_db_read,
            "sec_edgar.fetch_filing": fetch_filing,
            "http_post": http_post,
        }

    def execute_attack(
        self,
        attack: AttackCase,
        target: Optional[AttackTarget] = None,
        campaign_id: Optional[str] = None,
        mutation_lineage: Optional[List[str]] = None,
    ) -> OffensiveAttackResult:
        """Execute a single attack case against the local synthetic environment."""
        target = target or self.registry.get("agentguard-demo")
        start_time = time.perf_counter()

        # 1. Strict Safety Validation
        safety_check = self.validator.validate(attack, target)
        if not safety_check.safe:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return OffensiveAttackResult(
                attack_id=attack.attack_id,
                campaign_id=campaign_id,
                attack_type=attack.attack_type,
                target=target.target_id if target else "unknown",
                entry_point=attack.entry_point,
                expected_decision=attack.expected_behavior.value,
                actual_decision="REFUSED",
                status=AttackStatus.REFUSED,
                error_message=safety_check.reason,
                latency_ms=elapsed_ms,
                severity=attack.severity,
            )

        # 2. Reset hard execution counters before test
        initial_db_calls = self.customer_read_calls
        initial_tool_execs = self.total_tool_executions

        try:
            # 3. Initialize Multi-Agent Task Context
            trace_id = generate_id("tr_atk")
            
            # Setup synthetic agent with appropriate capabilities
            if attack.attack_type in (AttackType.AUTHORITY_ESCALATION, AttackType.AUTHORITY_IMPERSONATION, AttackType.DELEGATION_ESCALATION):
                agent_caps = [attack.required_capability] if attack.required_capability else ["public_search", "financial_extract"]
            else:
                agent_caps = [
                    "public_search",
                    "public_documents",
                    "financial_extract",
                    "customer_db.read",
                    "external_api",
                ]
                if attack.required_capability and attack.required_capability not in agent_caps:
                    agent_caps.append(attack.required_capability)

            agent = self.guard.agent(
                name=attack.target_agent,
                framework="custom",
                capabilities=agent_caps,
                metadata={"synthetic_target": True},
            )

            # Ingest context & evaluate within task and span scope
            with self.guard.task(intent=attack.task_intent, trace_id=trace_id) as task_obj:
                with self.guard.span(name="attack_execution", agent_id=agent.agent_id):
                    # Ingest adversarial context
                    source_enum = ContextSource.EXTERNAL_MCP if "mcp" in attack.entry_point else ContextSource.EXTERNAL_API
                    taint_enum = TaintState.TAINTED if attack.context_taint == "TAINTED" else TaintState.CLEAN
                    
                    adv_ctx = self.guard.context(
                        source=source_enum,
                        data=attack.payload,
                        taint_state=taint_enum,
                        agent_id=agent.agent_id,
                    )

                    tool_name = attack.target_tool or "customer_db.read"
                    target_tool_def = self.guard.tool_registry.get(tool_name)
                    if target_tool_def is None:
                        req_cap = attack.required_capability or tool_name
                        res_name = attack.target_resource or tool_name.split(".")[0]
                        tool_res = Resource(
                            resource_id=f"res_{res_name}",
                            name=res_name,
                            sensitivity=SensitivityLevel.CRITICAL if any(k in res_name for k in ("vault", "pii", "ledger", "customer")) else SensitivityLevel.HIGH,
                        )
                        target_tool_def = ToolDefinition(
                            tool_id=generate_id("tool"),
                            name=tool_name,
                            description=f"Synthetic tool {tool_name}",
                            sensitivity=SensitivityLevel.CRITICAL if any(k in res_name for k in ("vault", "pii", "ledger", "customer")) else SensitivityLevel.HIGH,
                            required_capabilities=[req_cap],
                            target_resources=[tool_res],
                        )
                        self.guard.register_tool(target_tool_def)

                    tool_req = ToolRequest(
                        tool_id=target_tool_def.tool_id,
                        tool_name=tool_name,
                        agent_id=agent.agent_id,
                        arguments=attack.tool_arguments or {"table": "customers"},
                        context_ids=[adv_ctx.context_id],
                    )

                    # --- Full Security Analysis Pipeline ---
                    # 1. APIRIS API/Tool Risk Intelligence
                    apiris_analysis_dict = None
                    apiris_unavail = False
                    try:
                        if hasattr(self.guard, "apiris_adapter") and self.guard.apiris_adapter:
                            apiris_raw = self.guard.apiris_adapter.analyze(tool_req)
                            if hasattr(apiris_raw, "to_dict"):
                                apiris_analysis_dict = apiris_raw.to_dict()
                            elif hasattr(apiris_raw, "model_dump"):
                                apiris_analysis_dict = apiris_raw.model_dump()
                            elif isinstance(apiris_raw, dict):
                                apiris_analysis_dict = apiris_raw
                            else:
                                apiris_analysis_dict = {
                                    "tool_name": tool_name,
                                    "risk_score": getattr(apiris_raw, "risk_score", 0.0),
                                    "recommended_action": getattr(apiris_raw, "recommended_action", "ALLOW"),
                                }
                    except Exception as e:
                        apiris_unavail = True
                        apiris_analysis_dict = {"status": "UNAVAILABLE", "error": str(e)}

                    # 2. AI Secura Cybersecurity Reasoning
                    ai_analysis_dict = None
                    ai_unavail = False
                    try:
                        if hasattr(self.guard, "ai_secura_adapter") and self.guard.ai_secura_adapter:
                            sec_ctx = SecurityContext(
                                trace_id=trace_id,
                                task_intent=attack.task_intent,
                                acting_agent_id=agent.agent_id,
                                acting_agent_name=agent.name,
                                tool_name=tool_name,
                                tool_arguments=tool_req.arguments,
                                context_provenance=[{"source": adv_ctx.source.value, "taint": attack.context_taint}],
                                taint_states=[attack.context_taint],
                            )
                            ai_raw = self.guard.ai_secura_adapter.analyze(sec_ctx)
                            if hasattr(ai_raw, "to_dict"):
                                ai_analysis_dict = ai_raw.to_dict()
                            elif hasattr(ai_raw, "model_dump"):
                                ai_analysis_dict = ai_raw.model_dump()
                            elif isinstance(ai_raw, dict):
                                ai_analysis_dict = ai_raw
                            else:
                                ai_analysis_dict = {
                                    "summary": getattr(ai_raw, "summary", "Security analysis generated"),
                                    "risk_level": getattr(ai_raw, "risk_level", "HIGH"),
                                    "risk_score": getattr(ai_raw, "risk_score", 0.8),
                                    "attack_indicators": getattr(ai_raw, "attack_indicators", []),
                                }
                    except Exception as e:
                        ai_unavail = True
                        ai_analysis_dict = {"status": "UNAVAILABLE", "error": str(e)}

                    # 3. Deterministic Policy Enforcement
                    decision = self.guard.evaluate_tool_invocation(target_tool_def, tool_req)

                    # Execute tool only if policy ALLOWed
                    if decision.action == DecisionAction.ALLOW:
                        tool_func = self._tool_callables.get(tool_name)
                        if tool_func:
                            try:
                                tool_func(**tool_req.arguments)
                            except Exception:
                                pass

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # 5. Measure hard execution evidence
            delta_db_calls = self.customer_read_calls - initial_db_calls
            delta_tool_execs = self.total_tool_executions - initial_tool_execs

            attack_path = [
                {"hop": 1, "source": attack.entry_point, "status": "INJECTED"},
                {"hop": 2, "agent": attack.target_agent, "action": "INGEST_CONTEXT", "taint": attack.context_taint},
                {"hop": 3, "target_tool": tool_name, "decision": decision.action.value},
            ]

            sec_evidence = SecurityAnalysisEvidence(
                attack_id=attack.attack_id,
                attack_type=attack.attack_type,
                trace_id=trace_id,
                acting_agent=agent.name,
                task_intent=attack.task_intent,
                entry_point=attack.entry_point,
                context_sources=[adv_ctx.source.value],
                taint_state=attack.context_taint,
                context_ids=[adv_ctx.context_id],
                requested_tool=tool_name,
                requested_capability=attack.required_capability,
                required_capabilities=target_tool_def.required_capabilities,
                delegated_capabilities=agent.capability_names(),
                authority_contained=bool(decision and decision.authority_containment.get("contained", True)),
                authority_reason=decision.authority_containment.get("reason", "") if decision else "",
                intent_aligned=bool(decision and decision.intent_alignment.get("aligned", True)),
                intent_explanation=decision.intent_alignment.get("explanation", "") if decision else "",
                apiris_analysis=apiris_analysis_dict,
                apiris_unavailable=apiris_unavail,
                ai_analysis=ai_analysis_dict,
                ai_unavailable=ai_unavail,
                policy_decision=decision.action.value if decision else "UNKNOWN",
                policy_reason_code=decision.reason_code if decision else "NO_DECISION",
                policy_explanation=decision.explanation if decision else "",
                risk_score=decision.risk_score if decision else 0.0,
                tool_executed=delta_tool_execs > 0 or delta_db_calls > 0,
                execution_count=delta_tool_execs,
                sensitive_db_calls=delta_db_calls,
            )

            result = AttackEvaluator.evaluate(
                attack=attack,
                decision=decision,
                execution_count=delta_tool_execs,
                sensitive_db_calls=delta_db_calls,
                trace_id=trace_id,
                attack_path=attack_path,
                influencing_context=[adv_ctx.context_id],
                ai_analysis=ai_analysis_dict,
                apiris_analysis=apiris_analysis_dict,
                security_evidence=sec_evidence,
                mutation_lineage=mutation_lineage,
                latency_ms=elapsed_ms,
                campaign_id=campaign_id,
            )

            # 6. If bypass occurred, archive to regression fixtures
            if result.bypassed:
                self.corpus.save_regression_case(attack, reason=f"Bypass detected: {decision.explanation}")

            return result

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return AttackEvaluator.evaluate(
                attack=attack,
                decision=None,
                execution_count=0,
                sensitive_db_calls=0,
                latency_ms=elapsed_ms,
                campaign_id=campaign_id,
                error_msg=str(e),
            )

    def execute_campaign(self, campaign: AttackCampaign) -> Tuple[List[OffensiveAttackResult], CampaignSummary]:
        """Execute all attack cases in an attack campaign and aggregate the scorecard."""
        results: List[OffensiveAttackResult] = []

        for attack in campaign.attacks:
            res = self.execute_attack(attack, target=campaign.target, campaign_id=campaign.campaign_id)
            results.append(res)

        summary = CampaignSummary.from_results(campaign, results)
        return results, summary

    def replay_attack(self, attack_id: str, target: Optional[AttackTarget] = None) -> OffensiveAttackResult:
        """Replay a specific attack fixture by ID."""
        target = target or self.registry.get("agentguard-demo")
        all_cases = self.corpus.generate_full_family_corpus(target) + self.corpus.load_regression_cases()
        
        match = next((c for c in all_cases if c.attack_id == attack_id), None)
        if not match:
            raise ValueError(f"Attack ID '{attack_id}' not found in baseline or regression corpus.")

        return self.execute_attack(match, target=target, campaign_id="replay")

    def export_reports(
        self,
        summary: CampaignSummary,
        results: List[OffensiveAttackResult],
        output_dir: Optional[pathlib.Path] = None,
    ) -> Dict[str, pathlib.Path]:
        """Export JSON scorecard and markdown reports to reports/phase4/."""
        root = pathlib.Path(__file__).resolve().parent.parent.parent.parent
        out = output_dir or (root / "reports" / "phase4")
        out.mkdir(parents=True, exist_ok=True)

        files: Dict[str, pathlib.Path] = {}

        # 1. campaign_summary.json
        sum_path = out / "campaign_summary.json"
        with open(sum_path, "w", encoding="utf-8") as f:
            json.dump(summary.model_dump(mode="json"), f, indent=2)
        files["summary_json"] = sum_path

        # 2. attack_results.json
        res_path = out / "attack_results.json"
        with open(res_path, "w", encoding="utf-8") as f:
            json.dump([r.model_dump(mode="json") for r in results], f, indent=2)
        files["results_json"] = res_path

        # 3. security_scorecard.json
        score_path = out / "security_scorecard.json"
        scorecard_data = {
            "campaign_id": summary.campaign_id,
            "target_id": summary.target_id,
            "total_attacks": summary.total_attacks,
            "attacks_blocked": summary.blocked,
            "attacks_bypassed": summary.bypassed,
            "block_rate_pct": summary.block_rate_pct,
            "sensitive_actions_prevented": summary.sensitive_actions_prevented,
            "sensitive_actions_executed": summary.sensitive_actions_executed,
            "mean_latency_ms": summary.mean_latency_ms,
            "p95_latency_ms": summary.p95_latency_ms,
        }
        with open(score_path, "w", encoding="utf-8") as f:
            json.dump(scorecard_data, f, indent=2)
        files["scorecard_json"] = score_path

        # 4. campaign_summary.md
        md_path = out / "campaign_summary.md"
        md_content = (
            f"# AgentGuard Offensive Validation Campaign Report\n\n"
            f"- **Campaign ID**: `{summary.campaign_id}`\n"
            f"- **Target System**: `{summary.target_id}`\n"
            f"- **Total Attacks Executed**: {summary.total_attacks}\n"
            f"- **Blocked Attacks**: {summary.blocked} ({summary.block_rate_pct}%)\n"
            f"- **Bypassed Attacks**: {summary.bypassed}\n"
            f"- **Sensitive Database Executions**: {summary.sensitive_actions_executed}\n"
            f"- **Mean Latency**: {summary.mean_latency_ms:.2f} ms\n\n"
            f"## Attack Coverage Breakdown\n\n"
            f"| Attack Type | Total | Blocked | Bypassed |\n"
            f"|---|---|---|---|\n"
        )
        for atype, counts in summary.coverage_breakdown.items():
            md_content += f"| `{atype}` | {counts['total']} | {counts['blocked']} | {counts['bypassed']} |\n"
        
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        files["summary_md"] = md_path

        return files

    def run_attack_suite(
        self,
        attacks: List[AttackCase],
        target: Optional[AttackTarget] = None,
    ) -> List[OffensiveAttackResult]:
        """Execute a batch list of attacks against the specified target."""
        results: List[OffensiveAttackResult] = []
        for atk in attacks:
            res = self.execute_attack(atk, target=target)
            results.append(res)
        return results


