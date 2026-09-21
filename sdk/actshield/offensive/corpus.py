"""Attack corpus loader managing baseline fixtures, attack families, and regression cases."""

import json
import pathlib
from typing import Dict, List, Optional

from actshield.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from actshield.offensive.strategies import (
    PromptInjectionStrategy,
    AuthorityEscalationStrategy,
    ToolPoisoningStrategy,
    ContextManipulationStrategy,
    MCPInjectionStrategy,
    DataExfiltrationStrategy,
    DelegationEscalationStrategy,
)
from actshield.offensive.target import AttackTarget, target_registry


class AttackCorpus:
    """Central repository for loading, organizing, and persisting attack fixtures."""

    def __init__(
        self,
        fixtures_dir: Optional[pathlib.Path] = None,
        regressions_dir: Optional[pathlib.Path] = None,
    ) -> None:
        # Default paths
        root = pathlib.Path(__file__).resolve().parent.parent.parent.parent
        self.fixtures_dir = fixtures_dir or (root / "examples" / "attacks")
        self.regressions_dir = regressions_dir or (root / "examples" / "attacks" / "regressions")
        self.regressions_dir.mkdir(parents=True, exist_ok=True)

    def load_baseline_fixtures(self) -> List[AttackCase]:
        """Load the 5 existing baseline attack fixtures from examples/attacks/."""
        cases: List[AttackCase] = []
        if not self.fixtures_dir.exists():
            return cases

        for json_path in sorted(self.fixtures_dir.glob("*.json")):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                # Map legacy format to AttackCase
                atype_str = data.get("attack_type", "custom")
                try:
                    atype = AttackType(atype_str)
                except ValueError:
                    atype = AttackType.CUSTOM

                case = AttackCase(
                    attack_id=data.get("attack_id", json_path.stem),
                    name=data.get("attack_id", json_path.stem).replace("_", " ").title(),
                    attack_type=atype,
                    description=data.get("description", "Baseline attack fixture"),
                    entry_point=data.get("entry_point", "mcp_response"),
                    target_agent=data.get("target_agent", "DataAgent"),
                    payload=data.get("payload", ""),
                    target_tool=data.get("target_capability", "customer_db.read"),
                    target_resource="customer_pii_vault",
                    expected_behavior=ExpectedBehavior.BLOCK if data.get("expected_decision") == "BLOCK" else ExpectedBehavior.ALLOW,
                    severity="HIGH",
                    safety_class=SafetyClass.LOCAL_SYNTHETIC,
                )
                cases.append(case)
            except Exception:
                pass

        return cases

    def generate_full_family_corpus(self, target: Optional[AttackTarget] = None) -> List[AttackCase]:
        """Generate comprehensive attack cases spanning all core attack families."""
        target = target or target_registry.get("ActShield-demo")
        all_cases: List[AttackCase] = []

        # 1. Include baseline fixtures
        all_cases.extend(self.load_baseline_fixtures())

        # 2. Generate from all strategies
        strategies = [
            PromptInjectionStrategy(),
            AuthorityEscalationStrategy(),
            ToolPoisoningStrategy(),
            ContextManipulationStrategy(),
            MCPInjectionStrategy(),
            DataExfiltrationStrategy(),
            DelegationEscalationStrategy(),
        ]

        for strat in strategies:
            strat_cases = strat.generate(target, count=5)
            # Avoid duplicate IDs
            for c in strat_cases:
                if not any(existing.attack_id == c.attack_id for existing in all_cases):
                    all_cases.append(c)

        return all_cases

    def get_all_attacks(self, target: Optional[AttackTarget] = None) -> List[AttackCase]:
        """Convenience alias returning the full baseline and generated attack corpus."""
        return self.generate_full_family_corpus(target=target)

    def get_regression_attacks(self) -> List[AttackCase]:
        """Convenience alias returning all regression attack cases."""
        return self.load_regression_cases()

    def get_attack(self, attack_id: str) -> Optional[AttackCase]:
        """Retrieve a specific attack case by ID from full corpus or regression store."""
        for a in self.get_all_attacks():
            if a.attack_id == attack_id:
                return a
        for r in self.get_regression_attacks():
            if r.attack_id == attack_id:
                return r
        return None

    def get_attacks_by_type(self, attack_type: AttackType) -> List[AttackCase]:
        """Retrieve all attack cases matching a specific AttackType."""
        return [a for a in self.get_all_attacks() if a.attack_type == attack_type]

    def save_regression_case(self, attack: AttackCase, reason: str = "Bypass detected") -> pathlib.Path:
        """Persist a discovered bypass attack case to permanent regression fixtures."""
        self.regressions_dir.mkdir(parents=True, exist_ok=True)
        file_path = self.regressions_dir / f"{attack.attack_id}.json"
        
        data = attack.model_dump(mode="json")
        data["regression_reason"] = reason
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        return file_path

    def load_regression_cases(self) -> List[AttackCase]:
        """Load all permanent regression attack fixtures."""
        regressions: List[AttackCase] = []
        if not self.regressions_dir.exists():
            return regressions

        for json_path in sorted(self.regressions_dir.glob("*.json")):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                regressions.append(AttackCase(**data))
            except Exception:
                pass

        return regressions


# Global default corpus instance
attack_corpus = AttackCorpus()


