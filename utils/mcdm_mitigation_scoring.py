"""
Weighted Sum Model (WSM) for mitigation ranking against an attack chain.

Follows the paper's MCDM formulation: criteria = techniques (here: techniques in
the attack chain with non-zero global mitigation count), alternatives =
mitigations that address at least one of those techniques.

For technique j, each mitigation in the full framework that mitigates j
receives the same "performance" for column j: m_ij = 1 / N_j, where N_j is the
number of mitigations in the knowledge graph for j (not limited to the chain).

The weight w_j is derived from the technique priority score (MCDM output),
optionally scaled by how often j appears in the attack chain, then
re-normalized over the criteria that participate in the sum (techniques with
N_j > 0 and present in the chain).

Final WSM score for mitigation i:  S_i = sum_j  w_j * m_ij
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from .kg_model import TechniqueMitigationInfo
from .attack_chain import aggregate_occurrences

logger = logging.getLogger(__name__)


@dataclass
class WSMitigationScoring:
    """One row in the final rankings."""

    rank: int
    mitigation_id: str
    mitigation_name: str
    wsm_score: float
    chain_coverage: int
    techniques_covered: str
    contribution_by_technique_json: str
    explanation: str
    stix_id: Optional[str] = None


def _resolve_missing_score(
    missing_policy: str,
    priority_by_tid: Dict[str, float],
) -> float:
    vals = [v for v in priority_by_tid.values() if not math.isnan(v)]
    if not vals:
        return 0.0
    if missing_policy == "min":
        return min(vals)
    if missing_policy == "mean":
        return float(sum(vals) / len(vals))
    if missing_policy == "max":
        return max(vals)
    if missing_policy == "zero":
        return 0.0
    raise ValueError(f"Unknown missing_policy: {missing_policy}")


def compute_chain_weights(
    attack_chain: List[str],
    priority_by_tid: Dict[str, float],
    n_mitigations_by_technique: Dict[str, int],
    missing_policy: str = "mean",
) -> Tuple[Dict[str, float], List[str], Dict[str, int], List[str]]:
    """
    Build per-technique weights w_j for the attack chain (sum to 1 over active criteria).

    - Occurrence: if technique T appears k times in the chain, it gets k times
      the base priority (emphasis in multi-stage attack).
    - Base priority: from ``priority_by_tid``; missing ids use ``missing_policy``.
    - Techniques with N_j=0: excluded from the criterion set; weight redistributed
      to remaining techniques (and warning logged).
    - Renormalize so sum(w_j) over remaining j = 1.

    Returns
    -------
    weights
        technique_id -> w_j
    warnings
    """
    warnings: List[str] = []
    if not attack_chain:
        raise ValueError("attack_chain is empty")

    _, occ = aggregate_occurrences(attack_chain)
    default_p = _resolve_missing_score(missing_policy, priority_by_tid)

    raw: Dict[str, float] = {}
    for tid, k in occ.items():
        p = priority_by_tid.get(tid, default_p)
        if tid not in priority_by_tid:
            warnings.append(
                f"Technique {tid} not in priority file; used default priority ({missing_policy}={p:.6f})"
            )
        raw[tid] = float(p) * int(k)

    # Drop techniques with no mitigations in the graph
    active: List[str] = [tid for tid in raw if n_mitigations_by_technique.get(tid, 0) > 0]
    for tid, k in occ.items():
        if n_mitigations_by_technique.get(tid, 0) == 0:
            warnings.append(
                f"Technique {tid} has N=0 mitigations in knowledge graph; excluded from WSM columns"
            )

    if not active:
        raise ValueError(
            "No attack-chain technique has N_j>0 mitigations; cannot run WSM. "
            "Check graph and technique ids."
        )

    s = sum(raw[t] for t in active)
    if s <= 0:
        warnings.append("Sum of raw weights is zero; using uniform weights over active techniques")
        w = {t: 1.0 / len(active) for t in active}
    else:
        w = {t: raw[t] / s for t in active}

    return w, warnings, {t: int(occ[t]) for t in occ}, active


def compute_wsm_for_mitigations(
    ctx: TechniqueMitigationInfo,
    chain_technique_ids: List[str],
    weights: Dict[str, float],
) -> List[Dict[str, Any]]:
    """
    For each distinct mitigation, compute S_i and coverage.

    m_ij = (1 / N_j) if mitigation i mitigates j, else 0; N_j from ctx.
    """
    n_map = ctx.mitigation_count_by_technique
    by_mid = ctx.mitigations_by_id()
    names = ctx.mitigation_names_by_id()
    stix_by: Dict[str, Optional[str]] = {}
    for e in ctx.edges:
        stix_by[e.mitigation_id] = e.stix_id

    chain_set = set(chain_technique_ids)
    out: List[Dict[str, Any]] = []

    for mid, techs in by_mid.items():
        in_chain = sorted(techs & chain_set)
        if not in_chain:
            continue

        score = 0.0
        contrib: Dict[str, float] = {}
        for tid in in_chain:
            n_j = n_map.get(tid, 0)
            if n_j <= 0:
                continue
            w_j = weights.get(tid, 0.0)
            m_ij = 1.0 / float(n_j)
            c = w_j * m_ij
            score += c
            contrib[tid] = c

        out.append(
            {
                "mitigation_id": mid,
                "mitigation_name": names.get(mid, mid),
                "wsm_score": score,
                "chain_coverage": len(in_chain),
                "techniques_covered": in_chain,
                "contribution_by_technique": contrib,
                "stix_id": stix_by.get(mid),
            }
        )

    out.sort(key=lambda r: (-r["wsm_score"], -r["chain_coverage"], r["mitigation_id"]))
    return out


def _explain_row(
    mitigation_id: str,
    name: str,
    score: float,
    coverage: int,
    techniques: List[str],
    weights: Dict[str, float],
    n_map: Dict[str, int],
    contrib: Dict[str, float],
) -> str:
    parts = [
        "WSM (paper): S = sum over chain techniques T of w_T * (1/N_T),",
        "where w_T is the renormalized MCDM technique priority (optionally times occurrence count in the chain),",
        "and N_T is the count of mitigations in the full knowledge graph for T.",
    ]
    detail = [f"  {t}: w={weights.get(t, 0.0):.4f}, N={n_map.get(t, 0)}, contrib={contrib.get(t, 0.0):.6f}" for t in techniques]
    return " ".join(parts) + " Details: " + " | ".join(detail)


def build_mitigation_rankings(
    ctx: TechniqueMitigationInfo,
    attack_chain: List[str],
    priority_by_tid: Dict[str, float],
    missing_policy: str = "mean",
) -> Tuple[
    List[WSMitigationScoring],
    List[str],
    Dict[str, float],
    Dict[str, int],
    List[str],
]:
    """
    Full pipeline: weights + scores + WSMitigationScoring list + global warnings.

    Also returns ``weights``, ``occurrence_counts``, and ``active_techniques`` for reporting.
    """
    n_map = ctx.mitigation_count_by_technique

    weights, warnings, occ, active = compute_chain_weights(
        attack_chain, priority_by_tid, n_map, missing_policy=missing_policy
    )

    rows = compute_wsm_for_mitigations(ctx, active, weights)

    ranked: List[WSMitigationScoring] = []
    for i, r in enumerate(rows, start=1):
        techs: List[str] = r["techniques_covered"]
        contrib: Dict[str, float] = r["contribution_by_technique"]
        expl = _explain_row(
            r["mitigation_id"],
            r["mitigation_name"],
            r["wsm_score"],
            r["chain_coverage"],
            techs,
            weights,
            n_map,
            contrib,
        )
        cj = json.dumps(contrib, sort_keys=True)
        tstr = ", ".join(techs)
        ranked.append(
            WSMitigationScoring(
                rank=i,
                mitigation_id=r["mitigation_id"],
                mitigation_name=r["mitigation_name"],
                wsm_score=float(r["wsm_score"]),
                chain_coverage=int(r["chain_coverage"]),
                techniques_covered=tstr,
                contribution_by_technique_json=cj,
                explanation=expl,
                stix_id=r.get("stix_id"),
            )
        )

    if not ranked:
        warnings.append(
            "No mitigations in the knowledge graph were linked to the attack-chain techniques. "
            "Verify technique ids and MITIGATES edges."
        )

    return ranked, warnings, weights, occ, active


def rankings_to_dataframe(ranked: List[WSMitigationScoring]) -> pd.DataFrame:
    if not ranked:
        return pd.DataFrame(
            columns=[
                "Rank",
                "Mitigation ID",
                "Mitigation Name",
                "WSM Score",
                "Chain Coverage (techniques)",
                "Techniques Covered",
                "Contribution by Technique (JSON)",
                "Explanation",
                "STIX ID",
            ]
        )
    return pd.DataFrame(
        {
            "Rank": [x.rank for x in ranked],
            "Mitigation ID": [x.mitigation_id for x in ranked],
            "Mitigation Name": [x.mitigation_name for x in ranked],
            "WSM Score": [x.wsm_score for x in ranked],
            "Chain Coverage (techniques)": [x.chain_coverage for x in ranked],
            "Techniques Covered": [x.techniques_covered for x in ranked],
            "Contribution by Technique (JSON)": [x.contribution_by_technique_json for x in ranked],
            "Explanation": [x.explanation for x in ranked],
            "STIX ID": [x.stix_id for x in ranked],
        }
    )
