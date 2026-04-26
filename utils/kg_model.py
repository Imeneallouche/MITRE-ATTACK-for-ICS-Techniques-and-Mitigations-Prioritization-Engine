"""
Dataclasses for MITIGATES context (no Neo4j driver dependency).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class MitigationTechniqueEdge:
    """One MITIGATES edge: mitigation m addresses technique t."""

    mitigation_id: str
    mitigation_name: str
    technique_id: str
    technique_name: str
    stix_id: Optional[str] = None


@dataclass
class TechniqueMitigationInfo:
    """Mitigation catalog for a set of chain techniques (from the graph or tests)."""

    edges: List[MitigationTechniqueEdge] = field(default_factory=list)
    mitigation_count_by_technique: Dict[str, int] = field(default_factory=dict)

    def mitigations_by_id(self) -> Dict[str, Set[str]]:
        """mitigation_id -> set of technique ids it addresses (within the queried set)."""
        out: Dict[str, Set[str]] = {}
        for e in self.edges:
            out.setdefault(e.mitigation_id, set()).add(e.technique_id)
        return out

    def mitigation_names_by_id(self) -> Dict[str, str]:
        m: Dict[str, str] = {}
        for e in self.edges:
            m[e.mitigation_id] = e.mitigation_name
        return m
