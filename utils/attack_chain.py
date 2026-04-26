"""
Attack chain parsing and normalization.

An attack chain is a sequence of MITRE ATT&CK for ICS technique IDs. The same
technique may appear more than once (repeated stage); occurrences are tracked
so weights can emphasize frequently observed steps.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, List, Sequence, Tuple, Union, Dict

logger = logging.getLogger(__name__)

def normalize_technique_id(raw: str) -> str:
    """
    Strip whitespace and normalize to canonical T######## form (uppercase T).
    """
    s = str(raw).strip()
    if not s:
        raise ValueError("Empty technique id")
    if not s.upper().startswith("T"):
        raise ValueError(f"Not a valid ATT&CK technique id: {raw!r}")
    core = s[1:].strip()
    if not core.isdigit():
        # Allow T0853 style only
        raise ValueError(f"Invalid technique id format: {raw!r}")
    return "T" + core


def normalize_attack_chain(chain: Sequence[Union[str, Any]]) -> List[str]:
    """
    Convert a sequence of raw ids to normalized technique id strings, preserving order.
    """
    out: List[str] = []
    for item in chain:
        if item is None:
            continue
        if isinstance(item, str):
            out.append(normalize_technique_id(item))
        else:
            out.append(normalize_technique_id(str(item)))
    if not out:
        raise ValueError("Attack chain is empty after normalization")
    return out


def aggregate_occurrences(chain: Sequence[str]) -> Tuple[List[str], Dict[str, int]]:
    """
    Return unique technique ids in first-seen order, and count of each id in the chain.
    """
    order: List[str] = []
    seen = set()
    for tid in chain:
        if tid not in seen:
            seen.add(tid)
            order.append(tid)
    counts = Counter(chain)
    return order, dict(counts)


def load_attack_chain_from_json(path: Union[str, Path]) -> List[str]:
    """
    Load technique id list from JSON. Supported shapes:

    - ["T0819", "T0846", ...]
    - {"technique_ids": [...]}
    - {"stages": [{"technique_id": "T08xx"}, ...]}

    Only technique_id / techniqueId keys are read from stages; other fields ignored.
    """
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return normalize_attack_chain(data)

    if isinstance(data, dict):
        if "technique_ids" in data:
            return normalize_attack_chain(data["technique_ids"])
        if "stages" in data:
            ids = []
            for st in data["stages"]:
                if not isinstance(st, dict):
                    continue
                raw = st.get("technique_id") or st.get("techniqueId")
                if raw is not None:
                    ids.append(raw)
            if not ids:
                raise ValueError("No technique_id entries found in 'stages'")
            return normalize_attack_chain(ids)

    raise ValueError(
        "JSON must be a list of ids, an object with technique_ids, or object with stages"
    )
