"""
Central configuration: environment variables and optional ``.env`` in the repo root.

All secrets (Neo4j password, etc.) must come from the environment, never from code.
Load order: existing ``os.environ`` first; then values from ``.env`` (do not override
set variables unless ``load_environment(override=True)``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

# Repository root (directory containing this file)
REPO_ROOT: Path = Path(__file__).resolve().parent


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def load_environment(override: bool = False) -> None:
    """
    Load ``.env`` from :data:`REPO_ROOT` if present.

    Parameters
    ----------
    override
        If True, values from ``.env`` override already-set environment variables.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_path = REPO_ROOT / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=override)


def _strip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _first_non_empty(*names: str) -> Optional[str]:
    for name in names:
        v = _strip(os.environ.get(name))
        if v is not None:
            return v
    return None


def get_neo4j_credentials() -> Tuple[str, str, str]:
    """
    Return ``(uri, user, password)`` for the Neo4j driver.

    Requires ``NEO4J_URI``, ``NEO4J_PASSWORD``, and either ``NEO4J_USER`` or
    ``NEO4J_USERNAME`` (commonly used by Neo4j Aura and self-hosted).
    """
    load_environment()
    uri = _first_non_empty("NEO4J_URI")
    user = _first_non_empty("NEO4J_USER", "NEO4J_USERNAME")
    password = _first_non_empty("NEO4J_PASSWORD")
    missing: list[str] = []
    if not uri:
        missing.append("NEO4J_URI")
    if not user:
        missing.append("NEO4J_USER (or NEO4J_USERNAME)")
    if not password:
        missing.append("NEO4J_PASSWORD")
    if missing:
        raise ConfigurationError(
            "Missing Neo4j configuration: "
            + ", ".join(missing)
            + ". Set environment variables or add them to .env (see .env.example)."
        )
    return uri, user, password


def safe_log_neo4j_target(uri: str) -> str:
    """Return a short, non-credential label for log lines (scheme + host)."""
    try:
        p = urlparse(uri)
        if p.netloc:
            return f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc
    except Exception:
        pass
    return "(configured)"


def resolve_repo_path(
    value: Optional[str],
    default_relative: str,
) -> Path:
    """
    Resolve a path: if ``value`` is set, use it; else ``REPO_ROOT / default_relative``.
    Absolute paths are used as-is.
    """
    load_environment()
    raw = _strip(value) or default_relative
    p = Path(raw)
    if p.is_absolute():
        return p
    return (REPO_ROOT / p).resolve()


def get_paths_technique_statistics() -> dict[str, Path]:
    """Default output for ``technique_statistics.py`` (written for downstream MCDM)."""
    return {
        "output": resolve_repo_path(
            os.getenv("OUTPUT_TECHNIQUE_STATISTICS"),
            "input/technique_statistics.xlsx",
        )
    }


def get_paths_technique_priority() -> dict[str, Path]:
    """Input/output for ``technique_priority_scorer.py``."""
    return {
        "input": resolve_repo_path(
            os.getenv("INPUT_TECHNIQUE_STATISTICS"),
            "input/technique_statistics.xlsx",
        ),
        "output": resolve_repo_path(
            os.getenv("OUTPUT_TECHNIQUE_PRIORITY_SCORES"),
            "output/technique_priority_scores.xlsx",
        ),
    }


def get_paths_mitigation_priority() -> dict[str, Path]:
    """Paths for ``mitigation_priority_scorer.py`` main."""
    return {
        "attack_chain": resolve_repo_path(
            os.getenv("INPUT_ATTACK_CHAIN_JSON"),
            "input/example_attack_chain.json",
        ),
        "priority_scores": resolve_repo_path(
            os.getenv("INPUT_TECHNIQUE_PRIORITY_SCORES"),
            "output/technique_priority_scores.xlsx",
        ),
        "output": resolve_repo_path(
            os.getenv("OUTPUT_MITIGATION_PRIORITY_SCORES"),
            "output/mitigation_priority_scores.xlsx",
        ),
    }
