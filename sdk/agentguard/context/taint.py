"""Taint tracking models and propagation rules."""

from enum import Enum
from typing import List, Optional


class TaintState(str, Enum):
    """Possible taint states for context and data artifacts.
    
    Separates origin trust from data taint:
    - CLEAN / TRUSTED: Verified safe content without malicious or unverified directives.
    - UNTRUSTED: Originating from an unverified source, but containing clean/benign data.
    - TAINTED: Ingested or influenced by unverified/adversarial prompt injections or unauthorized directives.
    - UNKNOWN: Unclassified context.
    """
    CLEAN = "CLEAN"
    TRUSTED = "TRUSTED"  # Backward compatibility alias for CLEAN
    UNTRUSTED = "UNTRUSTED"
    TAINTED = "TAINTED"
    UNKNOWN = "UNKNOWN"

    @property
    def is_safe(self) -> bool:
        """Indicates whether this taint level can flow to sensitive sinks without restrictions."""
        return self in (TaintState.CLEAN, TaintState.TRUSTED)

    @property
    def is_tainted(self) -> bool:
        """Indicates whether the data is flagged as carrying untrusted/injected payload."""
        return self == TaintState.TAINTED

    @classmethod
    def combine(cls, *states: "TaintState") -> "TaintState":
        """Combine multiple taint states into a single conservative worst-case taint state."""
        state_list = [s for s in states if s is not None]
        if not state_list:
            return cls.UNKNOWN
        
        if cls.TAINTED in state_list:
            return cls.TAINTED
        if cls.UNTRUSTED in state_list:
            return cls.UNTRUSTED
        if cls.UNKNOWN in state_list:
            return cls.UNKNOWN
        if cls.TRUSTED in state_list:
            return cls.TRUSTED
        return cls.CLEAN

