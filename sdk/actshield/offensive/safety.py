"""Safety validator ensuring offensive validation never attacks real or external targets."""

import re
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

from actshield.offensive.attack import AttackCase, SafetyClass
from actshield.offensive.target import AttackTarget, TargetRegistry, target_registry


class SafetyValidationResult(BaseModel):
    """Outcome of safety validation against an attack case."""
    safe: bool = Field(..., description="True if attack is strictly safe to execute in local sandbox")
    reason: str = Field(default="", description="Explanation if rejected or verified")
    violations: List[str] = Field(default_factory=list, description="List of detected safety violations")


class SafetyValidator:
    """Strict guard ensuring offensive operations remain contained in the local synthetic sandbox."""

    # Patterns indicating potentially dangerous or external targeting
    _EXTERNAL_IP_PATTERN = re.compile(r"\b(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])\.(?:\d{1,3}\.){2}(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])\b")
    _DANGEROUS_OS_CMDS = [
        "rm -rf /", ":(){ :|:& };:", "mkfs", "dd if=", "format c:", "drop database master",
        "shutdown -h", "reboot -f", "del /f /s /q c:\\", "chmod -r 777 /",
    ]
    _DISALLOWED_SCHEMES = ["ssh://", "telnet://", "ftp://"]

    def __init__(self, registry: Optional[TargetRegistry] = None) -> None:
        self.registry = registry or target_registry

    def validate(self, attack: AttackCase, target: Optional[AttackTarget] = None) -> SafetyValidationResult:
        """Validate an AttackCase before execution."""
        violations: List[str] = []

        # 1. Target Registration & Sandbox Check
        if target is not None:
            if not target.is_safe_for_validation():
                violations.append(f"Target '{target.target_id}' is not registered as a safe local synthetic target.")
        
        # 2. Safety Class Check
        if attack.safety_class == SafetyClass.UNSAFE_EXTERNAL:
            violations.append("Attack safety_class is marked UNSAFE_EXTERNAL.")

        payload_lower = (attack.payload + " " + str(attack.tool_arguments)).lower()

        # 3. External IP Address Detection (excluding localhost/loopback)
        for ip in self._EXTERNAL_IP_PATTERN.findall(payload_lower):
            if not (ip.startswith("127.") or ip == "0.0.0.0" or ip == "10.0.0.1"):
                violations.append(f"External IP address '{ip}' detected in attack payload.")

        # 4. Destructive OS / System Commands
        for cmd in self._DANGEROUS_OS_CMDS:
            if cmd in payload_lower:
                violations.append(f"Destructive system command pattern '{cmd}' detected.")

        # 5. Dangerous Protocols
        for scheme in self._DISALLOWED_SCHEMES:
            if scheme in payload_lower:
                violations.append(f"Disallowed network protocol scheme '{scheme}' detected.")

        # 6. Real Credential Harvesters
        if "/etc/shadow" in payload_lower or "c:\\windows\\system32\\config\\sam" in payload_lower:
            # Synthetic mock references are allowed, but check for destructive read commands
            if "bash_exec" in str(attack.target_tool) and "cat /etc/shadow" in payload_lower:
                violations.append("Direct OS credential file harvest attempted.")

        is_safe = len(violations) == 0
        reason = "Attack passed all synthetic sandbox safety checks." if is_safe else "; ".join(violations)

        return SafetyValidationResult(
            safe=is_safe,
            reason=reason,
            violations=violations,
        )


# Global default validator instance
safety_validator = SafetyValidator()

