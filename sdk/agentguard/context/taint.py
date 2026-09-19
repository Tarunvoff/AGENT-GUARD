"""Taint tracking models and propagation rules."""

from enum import Enum
from typing import List, Optional


class TaintState(str, Enum):
    """Possible taint states for context and data artifacts."""
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    TAINTED = "TAINTED"
    UNKNOWN = "UNKNOWN"

    @property
    def is_safe(self) -> bool:
        """Indicates whether this taint level can flow to sensitive sinks without restrictions."""
        return self == TaintState.TRUSTED

    @property
    def is_tainted(self) -> bool:
        """Indicates whether the data is flagged as untrusted, tainted, or unknown."""
        return self in (TaintState.UNTRUSTED, TaintState.TAINTED, TaintState.UNKNOWN)

    @classmethod
    def combine(cls, *states: "TaintState") -> "TaintState":
        """Combine multiple taint states into a single conservative worst-case taint state."""
        state_list = [s for s in states if s is not None]
        if not state_list:
            return cls.UNKNOWN
        
        # Priority order: TAINTED > UNTRUSTED > UNKNOWN > TRUSTED
        if cls.TAINTED in state_list:
            return cls.TAINTED
        if cls.UNTRUSTED in state_list:
            return cls.UNTRUSTED
        if cls.UNKNOWN in state_list:
            return cls.UNKNOWN
        return cls.TRUSTED
