"""Retriever — Queries the vector store and formats results for agents.

Supports hybrid retrieval (semantic + keyword) and source filtering
for MITRE ATT&CK, CVE, and custom threat intel.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.rag.store import VectorStore

logger = logging.getLogger(__name__)


class Retriever:
    """High-level retrieval interface used by pipeline agents.

    Wraps VectorStore with source filtering, result formatting,
    and configurable top-k.
    """

    def __init__(self, store: VectorStore, config: dict[str, Any]) -> None:
        self.store = store
        self.top_k = config.get("top_k", 5)
        self.search_mode = config.get("retrieval_mode", config.get("search_mode", "hybrid"))

    def query(
        self,
        query: str,
        source_filter: str | None = None,
        top_k: int | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve relevant threat intelligence for a query.

        Args:
            query: Natural language query or MITRE technique ID.
            source_filter: Restrict to a configured corpus such as "mitre_attack" or "curated_cve".
            top_k: Override default result count.

        Returns:
            Ranked list of {content, source, relevance_score, metadata} dicts.
        """
        k = top_k or self.top_k
        where = {"source": source_filter} if source_filter else None

        results = self.store.search(query=query, top_k=k, where=where)

        logger.debug(
            "Retrieved %d results for query='%s' (source=%s)",
            len(results),
            query[:50],
            source_filter or "all",
        )
        return results

    def query_mitre(self, technique_id: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Shortcut: retrieve MITRE ATT&CK data for a technique ID."""
        return self.query(
            query=f"MITRE ATT&CK technique {technique_id}",
            source_filter="mitre_attack",
            top_k=top_k,
        )

    def query_cve(self, cve_id: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Shortcut: retrieve CVE details by ID."""
        return self.query(
            query=f"CVE vulnerability {cve_id}",
            source_filter="curated_cve",
            top_k=top_k,
        )
