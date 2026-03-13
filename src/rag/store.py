"""Vector store interface for the Hades RAG pipeline.

Uses Qdrant for local, air-gapped threat-intelligence retrieval.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class VectorStore:
    """Qdrant-backed vector store for threat intelligence.

    Manages collections for MITRE ATT&CK, curated CVE, and other
    local threat-intelligence corpora. Uses Qdrant local mode by
    default and can connect to a remote self-hosted instance.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.collection_name = config.get("collection_name", "hades_threat_intel")
        self.persist_dir = config.get("persist_dir", "data/qdrant")
        self.url = config.get("url") or os.getenv("QDRANT_URL")
        self.embedding_model = config.get("dense_embedding_model", "BAAI/bge-small-en-v1.5")
        self.sparse_embedding_model = config.get("sparse_embedding_model")
        self.retrieval_mode = config.get("retrieval_mode", "hybrid")
        self._client: Any = None
        self._document_count = 0

    def initialize(self) -> None:
        """Connect to Qdrant and load or create the collection."""
        try:
            from qdrant_client import QdrantClient, models

            if self.url:
                self._client = QdrantClient(url=self.url)
            else:
                self._client = QdrantClient(path=self.persist_dir)

            self._client.set_model(self.embedding_model)

            sparse_vectors_config = None
            if self.retrieval_mode == "hybrid" and self.sparse_embedding_model:
                self._client.set_sparse_model(self.sparse_embedding_model)
                sparse_vectors_config = self._client.get_fastembed_sparse_vector_params(
                    modifier=models.Modifier.IDF
                )

            if not self._client.collection_exists(self.collection_name):
                self._client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=self._client.get_fastembed_vector_params(),
                    sparse_vectors_config=sparse_vectors_config,
                )

            collection_info = self._client.get_collection(self.collection_name)
            self._document_count = int(getattr(collection_info, "points_count", 0) or 0)
            logger.info(
                "VectorStore ready: collection=%s, documents=%d",
                self.collection_name,
                self._document_count,
            )
        except ImportError:
            logger.error(
                "qdrant-client[fastembed] not installed — run: pip install 'qdrant-client[fastembed]'"
            )
            raise

    def add_documents(
        self,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str | int] | None = None,
    ) -> int:
        """Add documents to the collection.

        Returns:
            Number of documents added.
        """
        if self._client is None:
            raise RuntimeError("VectorStore not initialized — call initialize() first")

        self._client.add(
            collection_name=self.collection_name,
            documents=documents,
            metadata=metadatas,
            ids=ids,
        )
        self._document_count += len(documents)
        return len(documents)

    def search(
        self,
        query: str,
        top_k: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search over the collection using the configured retrieval mode.

        Args:
            query: Natural language query or technique ID.
            top_k: Number of results to return.
            where: Optional metadata filter (e.g., {"source": "mitre_attack"}).

        Returns:
            List of {content, source, relevance_score, metadata} dicts.
        """
        if self._client is None:
            raise RuntimeError("VectorStore not initialized — call initialize() first")

        query_filter = None
        if where:
            from qdrant_client import models

            conditions: list[Any] = [
                models.FieldCondition(
                    key=key,
                    match=models.MatchValue(value=value),
                )
                for key, value in where.items()
            ]
            query_filter = models.Filter(must=conditions)

        results = self._client.query(
            collection_name=self.collection_name,
            query_text=query,
            query_filter=query_filter,
            limit=top_k,
        )

        output: list[dict[str, Any]] = []
        for item in results:
            metadata = dict(item.metadata)
            output.append(
                {
                    "content": item.document,
                    "source": metadata.get("source", ""),
                    "relevance_score": item.score,
                    "metadata": metadata,
                }
            )
        return output

    @property
    def document_count(self) -> int:
        """Current number of documents in the collection."""
        return self._document_count
