"""
Neo4j access for mitigation–technique relationships.

Schema (MITRE ATT&CK for ICS Knowledge Graph):
  (m:Mitigation)-[:MITIGATES]->(t:Technique)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError

from .kg_model import MitigationTechniqueEdge, TechniqueMitigationInfo

logger = logging.getLogger(__name__)


class KGMitigationRepository:
    """
    Query mitigations and per-technique mitigation counts for ATT&CK ICS techniques.

    Parameters
    ----------
    driver
        A Neo4j ``Driver`` (preferred for reuse in apps).
    uri, username, password
        If ``driver`` is None, a driver is created with these credentials and closed
        in ``close()``.
    """

    def __init__(
        self,
        driver: Optional[Driver] = None,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self._owns_driver = driver is None
        if driver is not None:
            self._driver: Driver = driver
        else:
            if not uri or username is None or password is None:
                raise ValueError("Either provide driver, or uri, username, and password")
            self._driver = GraphDatabase.driver(uri, auth=(username, password))
        self._log_connected()

    def _log_connected(self) -> None:
        try:
            with self._driver.session() as session:
                v = session.run("RETURN 1 as ok")
                v.single()
            logger.info("KGMitigationRepository: Neo4j connection ok")
        except (ServiceUnavailable, AuthError) as e:
            logger.error("KGMitigationRepository: connection failed: %s", e)
            raise

    def close(self) -> None:
        if self._owns_driver and self._driver is not None:
            self._driver.close()
            self._driver = None
            logger.info("KGMitigationRepository: driver closed")

    @property
    def driver(self) -> Driver:
        return self._driver

    def fetch_mitigation_context(self, technique_ids: List[str]) -> TechniqueMitigationInfo:
        """
        For the given technique ids, return:
        - all (Mitigation)-[MITIGATES]->(Technique) edges where Technique.id is in the list
        - N_j = count of distinct mitigations per technique in the *full* graph
          (same as technique_statistics num_mitigations; needed for 1/N_j in WSM)
        """
        if not technique_ids:
            return TechniqueMitigationInfo()

        tids = list(dict.fromkeys(technique_ids))  # de-dupe, preserve order

        with self._driver.session() as session:
            # Edges in scope
            r_edges = session.run(
                """
                UNWIND $tids AS tid
                MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {id: tid})
                RETURN DISTINCT
                    m.id AS mid,
                    m.name AS mname,
                    coalesce(m.stix_id, '') AS mstix,
                    t.id AS tid,
                    t.name AS tname
                ORDER BY mid, tid
                """,
                tids=tids,
            )
            edges: List[MitigationTechniqueEdge] = []
            for rec in r_edges:
                edges.append(
                    MitigationTechniqueEdge(
                        mitigation_id=str(rec["mid"]),
                        mitigation_name=str(rec["mname"] or "").strip() or str(rec["mid"]),
                        technique_id=str(rec["tid"]),
                        technique_name=str(rec["tname"] or "").strip() or str(rec["tid"]),
                        stix_id=(str(rec["mstix"]) or None) if rec["mstix"] else None,
                    )
                )

            # global N_j: distinct mitigations per technique in entire graph
            r_counts = session.run(
                """
                UNWIND $tids AS tid
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {id: tid})
                RETURN tid AS technique_id, count(DISTINCT m) AS n_mitigations
                """,
                tids=tids,
            )
            n_by: Dict[str, int] = {}
            for rec in r_counts:
                n_by[str(rec["technique_id"])] = int(rec["n_mitigations"] or 0)

        return TechniqueMitigationInfo(
            edges=edges,
            mitigation_count_by_technique=n_by,
        )
