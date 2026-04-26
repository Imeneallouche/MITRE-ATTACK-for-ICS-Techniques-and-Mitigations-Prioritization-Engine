"""
Reusable utilities for technique and mitigation prioritization (ICS ATT&CK).

Intended for use by the Prioritization Engine, Detection & Correlation Engine,
Knowledge Graph clients, and AegisRec.
"""

from .attack_chain import (
    aggregate_occurrences,
    load_attack_chain_from_json,
    normalize_attack_chain,
)
from .kg_model import MitigationTechniqueEdge, TechniqueMitigationInfo
from .technique_score_loader import load_priority_lookup, load_technique_priority_map
from .mcdm_mitigation_scoring import (
    WSMitigationScoring,
    build_mitigation_rankings,
    compute_chain_weights,
    rankings_to_dataframe,
)

# Optional (requires ``neo4j`` package):
#   from utils.kg_mitigation_repository import KGMitigationRepository

__all__ = [
    "aggregate_occurrences",
    "load_attack_chain_from_json",
    "normalize_attack_chain",
    "load_technique_priority_map",
    "load_priority_lookup",
    "MitigationTechniqueEdge",
    "TechniqueMitigationInfo",
    "WSMitigationScoring",
    "build_mitigation_rankings",
    "compute_chain_weights",
    "rankings_to_dataframe",
]
