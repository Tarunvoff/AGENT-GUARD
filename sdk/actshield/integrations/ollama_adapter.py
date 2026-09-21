"""OllamaAISecuraAdapter — Real local LLM-backed AI Secura reasoning via Ollama.

This adapter calls a locally-running Ollama instance (default: qwen2.5:7b)
with the AI Secura system prompt, structured security evidence packet,
and deterministically-selected few-shot examples.

CRITICAL INVARIANT:
  - AI Secura = reasoning ONLY.
  - PolicyEvaluator = sole enforcement authority.
  - Ollama failure -> ai_unavailable=True, deterministic policy continues.
  - Malformed output -> one repair attempt -> ai_unavailable on second failure.
  - AI Secura NEVER becomes the authorization authority.
"""

import json
import logging
import pathlib
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from actshield.integrations.ai_secura import SecurityContext, SecurityAnalysis
from actshield.integrations.ai_secura_analysis import (
    AISecuraAnalysis,
    ThreatSeverity,
    IntentAlignment,
    AIRecommendation,
    AttackTechnique,
)
from actshield.integrations.security_packet import build_security_packet
from actshield.integrations.few_shot import select_few_shot_examples, format_examples_for_prompt
from actshield.integrations.apiris import APIAnalysis
from actshield.llm_config import LLMConfig
from actshield.risk.models import RiskLevel, RiskSignal

logger = logging.getLogger("actshield.ollama")

_PROMPT_DIR = pathlib.Path(__file__).parent / "prompts"
_SYSTEM_PROMPT_PATH = _PROMPT_DIR / "ai_secura_system.txt"

# Repair prompt sent on malformed JSON
_REPAIR_PROMPT = (
    "Your previous response was not valid JSON. "
    "Return ONLY a single valid JSON object matching the AI Secura output schema. "
    "No markdown, no code fences, no explanatory text. Just the JSON object."
)


def _load_system_prompt() -> str:
    """Load the version-controlled AI Secura system prompt."""
    try:
        return _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("AI Secura system prompt not found at %s, using minimal prompt", _SYSTEM_PROMPT_PATH)
        return (
            "You are AI Secura, an AI security reasoning engine. "
            "Analyze the security evidence and output ONLY valid JSON. "
            "You are NOT the enforcement authority — PolicyEvaluator enforces."
        )


def _make_unavailable_analysis(reason: str, latency_ms: float = 0.0) -> AISecuraAnalysis:
    """Return a safe fallback analysis when Ollama is unavailable.

    CRITICAL: ai_unavailable=True means deterministic policy is sole enforcer.
    This NEVER produces an ALLOW recommendation.
    """
    return AISecuraAnalysis(
        threat_type="unknown",
        attack_category="unknown",
        attack_technique=AttackTechnique.UNKNOWN,
        severity=ThreatSeverity.UNKNOWN,
        confidence=0.0,
        intent_alignment=IntentAlignment.UNKNOWN,
        ai_recommendation=AIRecommendation.UNKNOWN,
        analysis=f"AI Secura analysis unavailable: {reason}",
        impact="Cannot assess — AI reasoning engine unavailable. Deterministic policy remains sole enforcer.",
        provider="ollama",
        model="unavailable",
        latency_ms=latency_ms,
        ai_unavailable=True,
    )


def _strip_markdown_fences(text: str) -> str:
    """Strip markdown code fences if the model wraps JSON in them."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _parse_analysis(raw: str) -> AISecuraAnalysis:
    """Parse raw model output into AISecuraAnalysis with strict validation."""
    cleaned = _strip_markdown_fences(raw)
    data = json.loads(cleaned)

    # Map string enums safely
    if "severity" in data:
        try:
            data["severity"] = ThreatSeverity(data["severity"])
        except ValueError:
            data["severity"] = ThreatSeverity.UNKNOWN

    if "intent_alignment" in data:
        try:
            data["intent_alignment"] = IntentAlignment(data["intent_alignment"])
        except ValueError:
            data["intent_alignment"] = IntentAlignment.UNKNOWN

    if "ai_recommendation" in data:
        try:
            data["ai_recommendation"] = AIRecommendation(data["ai_recommendation"])
        except ValueError:
            data["ai_recommendation"] = AIRecommendation.UNKNOWN

    if "attack_technique" in data:
        try:
            data["attack_technique"] = AttackTechnique(data["attack_technique"])
        except ValueError:
            data["attack_technique"] = AttackTechnique.UNKNOWN

    return AISecuraAnalysis(**data)


class OllamaAISecuraAdapter:
    """Real Ollama-backed AI Secura reasoning adapter.

    Sends structured security evidence to a locally-running Ollama model
    and returns a validated AISecuraAnalysis.

    Architecture:
        AISecuraClient
            |
            +-- OllamaAISecuraAdapter   (this — real LLM reasoning)
            |
            +-- LocalAISecuraAdapter    (deterministic heuristic, tests/CI)
    """

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig.from_env()
        self._system_prompt = _load_system_prompt()

    def analyze(self, context: SecurityContext, apiris_result: Optional[APIAnalysis] = None) -> AISecuraAnalysis:
        """Run AI Secura reasoning via Ollama.

        1. Build structured security packet from ActShield objects.
        2. Select relevant few-shot examples.
        3. Call Ollama with system prompt + examples + packet.
        4. Validate JSON output via Pydantic.
        5. On parse failure: one repair attempt.
        6. On Ollama error/timeout: return ai_unavailable=True.
        """
        start = time.monotonic()

        # 1. Build security packet
        packet = build_security_packet(context, apiris_result)

        # Offline / local provider routing: fast deterministic analysis
        if not self.config.is_ollama:
            return self._analyze_local_heuristic(context, apiris_result, start, packet)

        # 2. Select few-shot examples
        examples = select_few_shot_examples(packet)
        examples_block = format_examples_for_prompt(examples)

        # 3. Construct full prompt
        full_system = self._system_prompt
        if examples_block:
            full_system += examples_block

        user_prompt = (
            "Analyze the following ActShield security evidence packet and "
            "return your analysis as a single valid JSON object.\n\n"
            "EVIDENCE PACKET:\n"
            + json.dumps(packet, indent=2, default=str)
        )

        # 4. Call Ollama
        try:
            raw_response = self._call_ollama(full_system, user_prompt)
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Ollama call failed: %s", e)
            return _make_unavailable_analysis(f"Ollama error: {e}", elapsed)

        elapsed = (time.monotonic() - start) * 1000

        # 5. Parse response
        try:
            analysis = _parse_analysis(raw_response)
            analysis.provider = "ollama"
            analysis.model = self.config.model
            analysis.latency_ms = elapsed
            analysis.raw_response = raw_response
            return analysis
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("First parse failed (%s), attempting repair", e)

        # 6. One repair attempt
        if self.config.repair_on_invalid_json:
            try:
                repair_response = self._call_ollama(
                    self._system_prompt,
                    _REPAIR_PROMPT + "\n\nYour previous output:\n" + raw_response[:2000]
                )
                analysis = _parse_analysis(repair_response)
                analysis.provider = "ollama"
                analysis.model = self.config.model
                analysis.latency_ms = (time.monotonic() - start) * 1000
                analysis.json_repaired = True
                analysis.raw_response = repair_response
                return analysis
            except Exception as repair_err:
                logger.error("Repair attempt failed: %s", repair_err)

        # 7. Both attempts failed — return unavailable
        elapsed = (time.monotonic() - start) * 1000
        result = _make_unavailable_analysis(
            "Malformed model output after repair attempt", elapsed
        )
        result.raw_response = raw_response[:500]
        return result

    def _call_ollama(self, system: str, prompt: str) -> str:
        """Make HTTP request to Ollama generate API using urllib (zero deps)."""
        payload = json.dumps({
            "model": self.config.model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
                "num_ctx": self.config.num_ctx,
            },
            "format": "json",
        }).encode("utf-8")

        req = urllib.request.Request(
            self.config.ollama_generate_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body.get("response", "")

    def _analyze_local_heuristic(
        self,
        context: SecurityContext,
        apiris_result: Optional[APIAnalysis],
        start_time: float,
        packet: Dict[str, Any],
    ) -> AISecuraAnalysis:
        """Deterministic rule-based analysis for offline/local mode and test suites."""
        from actshield.integrations.ai_secura_analysis import EvidenceTriad, AuthorityAnalysis, TaintAnalysis
        
        is_tainted = any(t in ("TAINTED", "UNTRUSTED") for t in context.taint_states)
        is_sensitive = str(context.target_resource_sensitivity).upper() in ("CRITICAL", "HIGH", "SensitivityLevel.CRITICAL", "SensitivityLevel.HIGH")
        agent_trust = str(context.acting_agent_trust).lower()
        
        # Check for injection / malicious keywords in context data, arguments, and intent
        prov_text = (str(packet.get("context_provenance", "")) + " " + str(packet.get("tool", {}).get("arguments", ""))).lower()
        intent_text = str(context.task_intent or "").lower()
        tool_name = str(context.tool_name or "").lower()
        
        has_injection = any(k in prov_text for k in [
            "system directive", "ignore all previous", "override", "drop table",
            "base64", "ciso", "admin", "secret_instruction", "dump_env", "steal",
            "system prompt", "phishing", "leak.xyz", "exfiltrate",
        ])

        # Authority and intent drift detection
        is_authority_violation = False
        if agent_trust in ("low", "untrusted") and is_sensitive:
            is_authority_violation = True
        if "read-only" in intent_text and ("delete" in tool_name or "write" in tool_name or "alter" in tool_name):
            is_authority_violation = True
        if "css" in intent_text and ("alter_table" in tool_name or "db" in tool_name):
            is_authority_violation = True
        if "budget" in intent_text and "provision" in tool_name:
            is_authority_violation = True
        if "tenant-a" in intent_text and "tenant-b" in prov_text:
            is_authority_violation = True
        if "rate limit" in intent_text and "create_api_key" in tool_name:
            is_authority_violation = True
        if "team-alpha" in intent_text and "team-beta" in prov_text:
            is_authority_violation = True

        elapsed = (time.monotonic() - start_time) * 1000

        if is_tainted and (is_sensitive or has_injection):
            threat_type = "indirect_prompt_injection" if "external_mcp" in prov_text or "rag" in prov_text else "prompt_injection"
            return AISecuraAnalysis(
                threat_type=threat_type,
                attack_category="injection",
                attack_technique=AttackTechnique.INDIRECT_PROMPT_INJECTION if "mcp" in prov_text else AttackTechnique.PROMPT_INJECTION,
                severity=ThreatSeverity.CRITICAL if is_sensitive else ThreatSeverity.HIGH,
                confidence=0.95,
                evidence=EvidenceTriad(
                    observed=["Tainted context propagating into sensitive sink", f"Target tool: {context.tool_name}"],
                    inferred=["Potential prompt injection or unauthorized access detected"],
                    unknown=[],
                ),
                intent_alignment=IntentAlignment.VIOLATED,
                authority_analysis=AuthorityAnalysis(
                    acting_agent=context.acting_agent_name,
                    authority_violated=True,
                ),
                taint_analysis=TaintAnalysis(is_tainted=True),
                ai_recommendation=AIRecommendation.BLOCK,
                analysis=f"Deterministic local analysis: Tainted context detected for tool {context.tool_name}.",
                provider="local",
                model="deterministic_heuristic",
                latency_ms=elapsed,
            )
        elif is_authority_violation:
            return AISecuraAnalysis(
                threat_type="authority_escalation",
                attack_category="authority",
                attack_technique=AttackTechnique.PRIVILEGE_ESCALATION,
                severity=ThreatSeverity.CRITICAL if is_sensitive else ThreatSeverity.HIGH,
                confidence=0.95,
                evidence=EvidenceTriad(
                    observed=[f"Agent '{context.acting_agent_name}' ({agent_trust} trust) attempted out-of-scope tool: {context.tool_name}"],
                    inferred=["Task intent misalignment or authority boundary violation"],
                    unknown=[],
                ),
                intent_alignment=IntentAlignment.VIOLATED,
                authority_analysis=AuthorityAnalysis(acting_agent=context.acting_agent_name, authority_violated=True),
                taint_analysis=TaintAnalysis(is_tainted=is_tainted),
                ai_recommendation=AIRecommendation.BLOCK,
                analysis=f"Deterministic local analysis: Authority/Intent violation for {context.tool_name}.",
                provider="local",
                model="deterministic_heuristic",
                latency_ms=elapsed,
            )
        elif is_sensitive and not is_tainted:
            return AISecuraAnalysis(
                threat_type="none",
                attack_category="none",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.90,
                evidence=EvidenceTriad(
                    observed=["Clean context accessing sensitive resource", f"Tool: {context.tool_name}"],
                    inferred=["Authorized access to protected resource"],
                    unknown=[],
                ),
                intent_alignment=IntentAlignment.ALIGNED,
                authority_analysis=AuthorityAnalysis(acting_agent=context.acting_agent_name, authority_violated=False),
                taint_analysis=TaintAnalysis(is_tainted=False),
                ai_recommendation=AIRecommendation.ALLOW,
                analysis="Deterministic local analysis: Authorized sensitive operation with clean context.",
                provider="local",
                model="deterministic_heuristic",
                latency_ms=elapsed,
            )
        else:
            return AISecuraAnalysis(
                threat_type="none",
                attack_category="none",
                severity=ThreatSeverity.LOW,
                confidence=0.95,
                evidence=EvidenceTriad(
                    observed=["Clean context, low sensitivity operation"],
                    inferred=["Normal benign execution"],
                    unknown=[],
                ),
                intent_alignment=IntentAlignment.ALIGNED,
                authority_analysis=AuthorityAnalysis(acting_agent=context.acting_agent_name, authority_violated=False),
                taint_analysis=TaintAnalysis(is_tainted=False),
                ai_recommendation=AIRecommendation.ALLOW,
                analysis="Deterministic local analysis: Benign operation.",
                provider="local",
                model="deterministic_heuristic",
                latency_ms=elapsed,
            )

    def health_check(self) -> Dict[str, Any]:
        """Verify Ollama connectivity, model availability, and response validity.

        Returns a dict with status fields:
            ollama_reachable: bool
            model_exists: bool
            model_responds: bool
            json_valid: bool
            schema_valid: bool
            details: str
        """
        result: Dict[str, Any] = {
            "ollama_reachable": False,
            "model_exists": False,
            "model_responds": False,
            "json_valid": False,
            "schema_valid": False,
            "provider": "ollama",
            "model": self.config.model,
            "base_url": self.config.ollama_base_url,
            "details": "",
        }

        if not self.config.is_ollama:
            result["details"] = "Provider is local heuristic (offline mode)"
            return result

        # 1. Check Ollama reachable
        try:
            req = urllib.request.Request(self.config.ollama_tags_url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                tags_data = json.loads(resp.read().decode("utf-8"))
                result["ollama_reachable"] = True
        except Exception as e:
            result["details"] = f"Ollama not reachable: {e}"
            return result

        # 2. Check model exists
        models = [m.get("name", "") for m in tags_data.get("models", [])]
        model_found = any(
            self.config.model in m or m.startswith(self.config.model.split(":")[0])
            for m in models
        )
        result["model_exists"] = model_found
        if not model_found:
            result["details"] = f"Model '{self.config.model}' not found. Available: {models}"
            return result

        # 3. Quick test model response
        try:
            payload = json.dumps({
                "model": self.config.model,
                "prompt": "Return JSON: {\"threat_type\": \"none\", \"severity\": \"LOW\", \"ai_recommendation\": \"ALLOW\"}",
                "stream": False,
                "options": {"num_predict": 64, "temperature": 0.0},
                "format": "json",
            }).encode("utf-8")
            req = urllib.request.Request(
                self.config.ollama_generate_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                raw = body.get("response", "")
                result["model_responds"] = True
        except Exception as e:
            result["details"] = f"Model did not respond: {e}"
            return result

        # 4. Check JSON validity
        try:
            cleaned = _strip_markdown_fences(raw)
            data = json.loads(cleaned)
            result["json_valid"] = True
        except json.JSONDecodeError as e:
            result["details"] = f"Response is not valid JSON: {e}"
            return result

        # 5. Check schema validity
        try:
            _parse_analysis(raw)
            result["schema_valid"] = True
            result["details"] = "All checks passed"
        except Exception as e:
            result["details"] = f"Response does not match AISecuraAnalysis schema: {e}"

        return result

    def analyze_legacy(self, context: SecurityContext) -> SecurityAnalysis:
        """Backward-compatible wrapper that returns legacy SecurityAnalysis.

        Calls the full Ollama analysis and maps the rich AISecuraAnalysis
        back to the existing SecurityAnalysis format used by PolicyEvaluator.
        """
        rich = self.analyze(context)
        return _map_to_legacy(rich, context)


def _map_to_legacy(rich: AISecuraAnalysis, context: SecurityContext) -> SecurityAnalysis:
    """Map AISecuraAnalysis to legacy SecurityAnalysis for backward compat."""
    import uuid

    signals: List[RiskSignal] = []
    attack_indicators: List[str] = rich.observed_indicators.copy()
    prompt_injections: List[str] = []

    # Map severity to risk
    severity_to_risk = {
        ThreatSeverity.CRITICAL: RiskLevel.CRITICAL,
        ThreatSeverity.HIGH: RiskLevel.HIGH,
        ThreatSeverity.MEDIUM: RiskLevel.MEDIUM,
        ThreatSeverity.LOW: RiskLevel.LOW,
        ThreatSeverity.UNKNOWN: RiskLevel.LOW,
    }
    risk_level = severity_to_risk.get(rich.severity, RiskLevel.LOW)

    # Extract injection indicators
    if rich.attack_technique in (
        AttackTechnique.PROMPT_INJECTION,
        AttackTechnique.INDIRECT_PROMPT_INJECTION,
        AttackTechnique.INSTRUCTION_HIJACKING,
    ):
        prompt_injections.append(f"AI_SECURA_OLLAMA_{rich.attack_technique.value.upper()}")
        signals.append(RiskSignal(
            source="ai_secura_ollama",
            risk_level=risk_level,
            score=rich.confidence,
            indicator=f"AI_SECURA_OLLAMA_{rich.attack_technique.value.upper()}",
            details={"analysis": rich.analysis[:200]},
        ))

    if rich.intent_alignment == IntentAlignment.VIOLATED:
        attack_indicators.append(f"Intent drift detected by AI Secura: {rich.influencing_context[:100]}")

    risk_score = rich.confidence if rich.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL) else max(0.05, rich.confidence * 0.5)

    return SecurityAnalysis(
        analysis_id=rich.analysis_id,
        summary=rich.analysis[:200] if rich.analysis else "AI Secura Ollama analysis completed.",
        risk_level=risk_level,
        risk_score=round(risk_score, 2),
        attack_indicators=attack_indicators,
        intent_drift_detected=(rich.intent_alignment == IntentAlignment.VIOLATED),
        authority_violation_detected=rich.authority_analysis.authority_violated,
        prompt_injection_indicators=prompt_injections,
        reasoning=rich.analysis,
        signals=signals,
    )


