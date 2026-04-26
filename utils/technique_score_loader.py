"""
Load technique priority scores produced by `technique_priority_scorer.py`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Union

import pandas as pd

from .attack_chain import normalize_technique_id

logger = logging.getLogger(__name__)

DEFAULT_PRIORITY_SHEET = "Priority Scores"


def load_technique_priority_map(
    path: Union[str, Path],
    sheet_name: str = DEFAULT_PRIORITY_SHEET,
) -> pd.DataFrame:
    """
    Load the priority scores workbook sheet as a DataFrame (full row content).

    Expected columns (from technique_priority_scorer export):
    - Technique ID, Priority_Score_Normalized, Technique Name, ...
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Technique priority file not found: {path}")

    df = pd.read_excel(path, sheet_name=sheet_name, engine="openpyxl")
    return df


def build_technique_id_to_score(
    df: pd.DataFrame,
    technique_col: str = "Technique ID",
    score_col: str = "Priority_Score_Normalized",
) -> Dict[str, float]:
    """
    Map technique id -> priority score. Duplicate ids keep the last row (warned).
    """
    if technique_col not in df.columns or score_col not in df.columns:
        raise KeyError(
            f"Required columns {technique_col!r} and {score_col!r} not in sheet; "
            f"have: {list(df.columns)}"
        )
    m: Dict[str, float] = {}
    dups = 0
    for _, row in df[[technique_col, score_col]].iterrows():
        raw = str(row[technique_col]).strip()
        if not raw or raw.lower() == "nan":
            continue
        try:
            tid = normalize_technique_id(raw)
        except ValueError:
            logger.warning("Skipping non-technique id in priority sheet: %r", raw)
            continue
        if pd.isna(row[score_col]):
            continue
        val = float(row[score_col])
        if tid in m and m[tid] != val:
            dups += 1
        m[tid] = val
    if dups:
        logger.warning("Duplicate technique ids in priority sheet; last value kept (%s rows)", dups)
    return m


def load_priority_lookup(
    path: Union[str, Path],
    sheet_name: str = DEFAULT_PRIORITY_SHEET,
) -> Dict[str, float]:
    """
    Convenience: load Excel and return id -> normalized priority score.
    """
    df = load_technique_priority_map(path, sheet_name=sheet_name)
    return build_technique_id_to_score(df)
