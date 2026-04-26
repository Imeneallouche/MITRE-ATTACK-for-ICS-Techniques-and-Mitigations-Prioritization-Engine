"""
MITRE ATT&CK for ICS — Mitigation prioritization (MCDM / WSM)

Ranks mitigations for a given attack chain using the Weighted Sum Model from
the research paper: criteria = chain techniques (weighted by technique priority
scores), performance m_ij = 1/N_j when mitigation i addresses technique j (N_j
= total mitigations for j in the knowledge graph).

Inputs:
  - Attack chain: sequence of technique IDs (order is preserved; duplicates
    increase emphasis when building weights).
  - ``output/technique_priority_scores.xlsx`` (or equivalent) from
    ``technique_priority_scorer.py``.
  - Neo4j knowledge graph with (Mitigation)-[:MITIGATES]->(Technique).

Configuration: see ``.env.example`` and ``config.py`` (Neo4j and optional path variables).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import pandas as pd

# Allow `python mitigation_priority_scorer.py` from repo root without installing a package
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from config import (
    ConfigurationError,
    get_neo4j_credentials,
    get_paths_mitigation_priority,
    load_environment,
)
from utils.attack_chain import load_attack_chain_from_json, normalize_attack_chain
from utils.kg_mitigation_repository import KGMitigationRepository
from utils.mcdm_mitigation_scoring import (
    build_mitigation_rankings,
    rankings_to_dataframe,
)
from utils.technique_score_loader import load_priority_lookup

logger = logging.getLogger(__name__)


class MitigationPriorityScorer:
    """
    Orchestrate Neo4j lookups and WSM ranking for an attack chain.
    """

    def __init__(
        self,
        repository: KGMitigationRepository,
        priority_scores_path: Union[str, Path],
        priority_sheet: str = "Priority Scores",
    ) -> None:
        self.repository = repository
        self.priority_scores_path = Path(priority_scores_path)
        self.priority_sheet = priority_sheet
        self._priority_by_tid: Dict[str, float] = {}

    def load_technique_priorities(self) -> Dict[str, float]:
        """Load and cache technique id -> Priority_Score_Normalized."""
        self._priority_by_tid = load_priority_lookup(
            self.priority_scores_path,
            sheet_name=self.priority_sheet,
        )
        logger.info(
            "Loaded %s technique priority scores from %s",
            len(self._priority_by_tid),
            self.priority_scores_path,
        )
        return self._priority_by_tid

    def rank_mitigations_for_chain(
        self,
        attack_chain: Sequence[str],
        missing_policy: str = "mean",
    ) -> Tuple[pd.DataFrame, List[str], Dict[str, Any]]:
        """
        Run full pipeline: graph fetch, WSM scores, DataFrame + warnings + debug context.

        Parameters
        ----------
        attack_chain
            Raw technique ids (strings). Normalized and validated.
        missing_policy
            How to fill priority for techniques missing from the Excel file:
            ``mean``, ``min``, ``max``, or ``zero``.
        """
        chain = normalize_attack_chain(attack_chain)
        if not self._priority_by_tid:
            self.load_technique_priorities()

        ctx = self.repository.fetch_mitigation_context(list(dict.fromkeys(chain)))
        ranked, warnings, weights, occ, active = build_mitigation_rankings(
            ctx,
            chain,
            self._priority_by_tid,
            missing_policy=missing_policy,
        )
        df = rankings_to_dataframe(ranked)

        meta: Dict[str, Any] = {
            "attack_chain_normalized": chain,
            "occurrence_counts": occ,
            "active_criteria_technique_ids": active,
            "weights_by_technique": weights,
            "mitigation_count_by_technique": ctx.mitigation_count_by_technique,
        }

        return df, warnings, meta

    def export_results(
        self,
        df: pd.DataFrame,
        output_path: Union[str, Path],
        meta: Optional[Dict[str, Any]] = None,
        warnings: Optional[List[str]] = None,
    ) -> None:
        """Write Excel with rankings, chain/weights context, and methodology notes."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        meth = pd.DataFrame(
            {
                "Step": [
                    "1",
                    "2",
                    "3",
                    "4",
                ],
                "Description": [
                    "Normalize attack chain; count duplicate techniques for weight emphasis.",
                    "Load technique priority scores (MCDM output) from Excel.",
                    "Query Neo4j: (Mitigation)-[:MITIGATES]->(Technique); N_j = count of mitigations per technique in the full graph.",
                    "WSM: S_m = sum_T w_T * (1/N_T) over chain techniques T mitigated by m; w_T renormalized over techniques with N_T>0.",
                ],
            }
        )

        with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Mitigation Rankings", index=False)
            meth.to_excel(writer, sheet_name="Methodology", index=False)

            if meta:
                chain_df = pd.DataFrame(
                    {
                        "position": range(1, len(meta["attack_chain_normalized"]) + 1),
                        "technique_id": meta["attack_chain_normalized"],
                    }
                )
                chain_df.to_excel(writer, sheet_name="Attack Chain", index=False)

                wrows = [
                    {"technique_id": k, "weight": v}
                    for k, v in sorted(
                        meta["weights_by_technique"].items(),
                        key=lambda x: -x[1],
                    )
                ]
                pd.DataFrame(wrows).to_excel(writer, sheet_name="Criterion Weights", index=False)

                nrows = [
                    {"technique_id": k, "n_mitigations_in_graph": v}
                    for k, v in sorted(meta["mitigation_count_by_technique"].items())
                ]
                pd.DataFrame(nrows).to_excel(writer, sheet_name="N per Technique", index=False)

            if warnings:
                pd.DataFrame({"warning": warnings}).to_excel(
                    writer, sheet_name="Warnings", index=False
                )

            for sheet in writer.sheets.values():
                for col in sheet.columns:
                    max_len = 0
                    letter = col[0].column_letter
                    for cell in col:
                        try:
                            max_len = max(max_len, len(str(cell.value)))
                        except Exception:
                            pass
                    sheet.column_dimensions[letter].width = min(max_len + 2, 60)

        logger.info("Wrote %s", output_path)


def main() -> None:
    """Example entry: loads chain from JSON; requires Neo4j configuration (``.env`` / env)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    load_environment()
    try:
        uri, user, password = get_neo4j_credentials()
    except ConfigurationError as e:
        logger.error("%s", e)
        sys.exit(1)

    paths = get_paths_mitigation_priority()
    chain_path = paths["attack_chain"]
    priority_path = paths["priority_scores"]
    out_path = paths["output"]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not chain_path.is_file():
        logger.error("Attack chain file not found: %s (set INPUT_ATTACK_CHAIN_JSON?)", chain_path)
        sys.exit(1)
    if not priority_path.is_file():
        logger.error(
            "Missing %s — run technique_priority_scorer.py first (or set INPUT_TECHNIQUE_PRIORITY_SCORES).",
            priority_path,
        )
        sys.exit(1)

    chain = load_attack_chain_from_json(chain_path)
    repo = KGMitigationRepository(uri=uri, username=user, password=password)
    try:
        scorer = MitigationPriorityScorer(repo, priority_path)
        df, warnings, meta = scorer.rank_mitigations_for_chain(chain)
        scorer.export_results(df, out_path, meta=meta, warnings=warnings)
        print(df.head(15).to_string(index=False))
        if warnings:
            for w in warnings:
                logger.warning("%s", w)
    finally:
        repo.close()


if __name__ == "__main__":
    main()
