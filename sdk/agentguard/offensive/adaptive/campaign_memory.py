"""Campaign Memory and Mutation Lineage Graph for Adaptive Offensive Validation."""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MutationNode(BaseModel):
    """Represents a single node in an adaptive attack mutation lineage tree."""

    mutation_id: str = Field(..., description="Unique ID for this mutation attempt")
    parent_id: Optional[str] = Field(default=None, description="Parent attack/mutation ID")
    root_attack_id: str = Field(..., description="The original baseline attack ID")
    strategy: str = Field(default="baseline", description="Mutation strategy applied")
    depth: int = Field(default=0, description="Mutation depth from baseline root (0 = root)")
    
    input_payload: str = Field(default="", description="Input payload before mutation")
    output_payload: str = Field(default="", description="Output payload after mutation")
    input_hash: str = Field(default="", description="SHA-256 hash of input payload")
    output_hash: str = Field(default="", description="SHA-256 hash of output payload")
    
    defense_reason: str = Field(default="", description="Defensive policy reason code rendered")
    decision: str = Field(default="UNKNOWN", description="Policy decision (BLOCK/ALLOW/etc.)")
    status: str = Field(default="PASS", description="Attack status (PASS/BYPASS/ERROR/REFUSED)")
    sensitive_executions: int = Field(default=0, description="Count of unauthorized sensitive sink calls")
    latency_ms: float = Field(default=0.0, description="Execution latency in milliseconds")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def compute_hash(text: str) -> str:
        """Compute 8-char truncated SHA-256 hash of text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return self.model_dump(mode="json")


class CampaignMemory:
    """Stores the full adaptive exploration graph, lineage trees, and defense responses."""

    def __init__(self, campaign_id: Optional[str] = None) -> None:
        self.campaign_id = campaign_id or f"camp_mem_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        self.nodes: Dict[str, MutationNode] = {}
        self.children_map: Dict[str, List[str]] = {}
        self.bypasses: List[str] = []

    def record_node(
        self,
        mutation_id: str,
        root_attack_id: str,
        parent_id: Optional[str] = None,
        strategy: str = "baseline",
        depth: int = 0,
        input_payload: str = "",
        output_payload: str = "",
        defense_reason: str = "",
        decision: str = "UNKNOWN",
        status: str = "PASS",
        sensitive_executions: int = 0,
        latency_ms: float = 0.0,
    ) -> MutationNode:
        """Record an attack attempt into campaign memory."""
        node = MutationNode(
            mutation_id=mutation_id,
            parent_id=parent_id,
            root_attack_id=root_attack_id,
            strategy=strategy,
            depth=depth,
            input_payload=input_payload,
            output_payload=output_payload,
            input_hash=MutationNode.compute_hash(input_payload),
            output_hash=MutationNode.compute_hash(output_payload),
            defense_reason=defense_reason,
            decision=decision,
            status=status,
            sensitive_executions=sensitive_executions,
            latency_ms=latency_ms,
        )
        self.nodes[mutation_id] = node

        if parent_id:
            if parent_id not in self.children_map:
                self.children_map[parent_id] = []
            self.children_map[parent_id].append(mutation_id)

        if status == "BYPASS" or sensitive_executions > 0:
            if mutation_id not in self.bypasses:
                self.bypasses.append(mutation_id)

        return node

    def get_lineage(self, attack_or_mutation_id: str) -> List[MutationNode]:
        """Return root-to-leaf sequence of MutationNodes for the given attack/mutation ID."""
        lineage: List[MutationNode] = []
        curr_id: Optional[str] = attack_or_mutation_id

        while curr_id and curr_id in self.nodes:
            node = self.nodes[curr_id]
            lineage.append(node)
            curr_id = node.parent_id

        lineage.reverse()
        return lineage

    def get_all_nodes(self) -> List[MutationNode]:
        """Return all recorded mutation nodes."""
        return list(self.nodes.values())

    def get_bypasses(self) -> List[MutationNode]:
        """Return all nodes where a bypass was discovered."""
        return [self.nodes[bid] for bid in self.bypasses if bid in self.nodes]

    def to_dict(self) -> Dict[str, Any]:
        """Export campaign memory to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "total_nodes": len(self.nodes),
            "total_bypasses": len(self.bypasses),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "bypasses": self.bypasses,
        }
