"""Vector store interface for the Hades RAG pipeline.

Wraps ChromaDB for local, air-gapped threat intelligence retrieval.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class VectorStore:
    """ChromaDB-backed vector store for threat intelligence.

    Manages collections for MITRE ATT&CK, NVD/CVE, and custom
    threat intel documents. Supports hybrid search (semantic + BM25).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.collection_name = config.get("collection_name", "hades_threat_intel")
        self.persist_dir = config.get("persist_dir", "data/embeddings")
        self._client = None
        self._collection = None

    def initialize(self) -> None:
        """Connect to ChromaDB and load or create the collection."""
        try:
            import chromadb
            from chromadb.config import Settings

            self._client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(anonymized_telemetry=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            count = self._collection.count()
            logger.info(
                "VectorStore ready: collection=%s, documents=%d",
                self.collection_name,
                count,
            )
        except ImportError:
            logger.error("chromadb not installed — run: pip install chromadb")
            raise

    def add_documents(
        self,
        documents: list[str],
        metadatas: list[dict[str, str]] | None = None,
        ids: list[str] | None = None,
    ) -> int:
        """Add documents to the collection.

        Returns:
            Number of documents added.
        """
        if self._collection is None:
            raise RuntimeError("VectorStore not initialized — call initialize() first")

        self._collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids or [f"doc_{i}" for i in range(len(documents))],
        )
        return len(documents)

    def search(
        self,
        query: str,
        top_k: int = 5,
        where: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Semantic search over the collection.

        Args:
            query: Natural language query or technique ID.
            top_k: Number of results to return.
            where: Optional metadata filter (e.g., {"source": "mitre_attack"}).

        Returns:
            List of {content, source, relevance_score, metadata} dicts.
        """
        if self._collection is None:
            raise RuntimeError("VectorStore not initialized — call initialize() first")

        results = self._collection.query(
            query_texts=[query],
            n_results=top_k,
            where=where,
        )

        output: list[dict[str, Any]] = []
        for i in range(len(results["documents"][0])):
            output.append({
                "content": results["documents"][0][i],
                "relevance_score": 1.0 - (results["distances"][0][i] if results["distances"] else 0.0),
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
            })
        return output

    @property
    def document_count(self) -> int:
        """Current number of documents in the collection."""
        if self._collection is None:
            return 0
        return self._collection.count()
