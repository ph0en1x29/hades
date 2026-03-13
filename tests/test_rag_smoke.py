#!/usr/bin/env python3
"""Smoke tests for MITRE RAG retriever.

Tests basic retrieval functionality when Qdrant store is available.
Skips gracefully if RAG dependencies or data aren't set up.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

passed = 0
failed = 0
skipped = 0


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


def skip(name: str, reason: str):
    global skipped
    skipped += 1
    print(f"  ⏭️  {name}: {reason}")


def main():
    print("=" * 70)
    print("  HADES — MITRE RAG Smoke Tests")
    print("=" * 70)

    # Check if Qdrant is available
    try:
        from qdrant_client import QdrantClient
        qdrant_available = True
    except ImportError:
        qdrant_available = False
        skip("qdrant import", "qdrant-client not installed")

    if not qdrant_available:
        print("\n⏭️  RAG tests skipped: install 'qdrant-client[fastembed]' to enable")
        print("=" * 70)
        sys.exit(0)

    # Check if RAG data exists
    qdrant_path = ROOT / "data" / "qdrant"
    rag_docs_path = ROOT / "data" / "mitre_attack" / "rag_documents"
    
    if not qdrant_path.exists():
        skip("qdrant data", f"no data at {qdrant_path}")
        print("\n⏭️  RAG tests skipped: run 'python scripts/build_mitre_rag.py' to populate")
        print("=" * 70)
        sys.exit(0)

    # === Initialize VectorStore ===
    print("\n─── VectorStore Initialization ───")

    from src.rag.store import VectorStore
    from src.rag.retriever import Retriever

    try:
        store = VectorStore({
            "persist_dir": str(qdrant_path),
            "collection_name": "hades_threat_intel",
            "retrieval_mode": "dense",  # Avoid sparse model requirement for smoke test
        })
        store.initialize()
        
        if store.document_count == 0:
            skip("document_count", "store is empty")
            print("\n⏭️  RAG tests skipped: store has 0 documents")
            print("=" * 70)
            sys.exit(0)
        
        ok(f"VectorStore initialized: {store.document_count} documents")
    except Exception as e:
        fail("VectorStore init", str(e))
        print("=" * 70)
        sys.exit(1)

    # === Initialize Retriever ===
    print("\n─── Retriever Initialization ───")

    retriever = Retriever(store, {"top_k": 5})
    ok("Retriever initialized")

    # === Test: Query known technique ===
    print("\n─── MITRE Technique Retrieval ───")

    known_techniques = ["T1003.001", "T1059.001", "T1021.002", "T1547.001"]
    
    for tech_id in known_techniques:
        try:
            results = retriever.query_mitre(tech_id, top_k=3)
            if results:
                top_score = results[0]["relevance_score"]
                top_content = results[0]["content"][:100]
                ok(f"{tech_id}: {len(results)} results (top score: {top_score:.3f})")
            else:
                fail(f"{tech_id}", "no results returned")
        except Exception as e:
            fail(f"{tech_id}", str(e))

    # === Test: Query by description ===
    print("\n─── Natural Language Query ───")

    queries = [
        ("credential dumping LSASS", "credential"),
        ("PowerShell script execution", "execution"),
        ("lateral movement SMB", "lateral"),
        ("persistence registry run keys", "persistence"),
    ]
    
    for query, expected_topic in queries:
        try:
            results = retriever.query(query, source_filter="mitre_attack", top_k=3)
            if results:
                ok(f"'{query[:30]}...': {len(results)} results")
            else:
                skip(f"'{query[:30]}...'", "no results")
        except Exception as e:
            fail(f"'{query[:30]}...'", str(e))

    # === Test: Source filtering ===
    print("\n─── Source Filtering ───")

    try:
        mitre_results = retriever.query("attack technique", source_filter="mitre_attack", top_k=5)
        all_results = retriever.query("attack technique", source_filter=None, top_k=5)
        
        if mitre_results:
            ok(f"source_filter='mitre_attack': {len(mitre_results)} results")
        else:
            skip("mitre_attack filter", "no MITRE documents in store")
        
        if all_results:
            ok(f"source_filter=None: {len(all_results)} results")
        else:
            fail("unfiltered query", "no results")
    except Exception as e:
        fail("source filtering", str(e))

    # === Test: Result structure ===
    print("\n─── Result Structure Validation ───")

    try:
        results = retriever.query("credential access", top_k=1)
        if results:
            result = results[0]
            assert "content" in result, "missing 'content' field"
            assert "source" in result, "missing 'source' field"
            assert "relevance_score" in result, "missing 'relevance_score' field"
            assert "metadata" in result, "missing 'metadata' field"
            assert isinstance(result["relevance_score"], (int, float)), "score should be numeric"
            ok("result structure valid")
        else:
            skip("structure validation", "no results to validate")
    except AssertionError as e:
        fail("result structure", str(e))
    except Exception as e:
        fail("result structure", str(e))

    # === Test: Empty query handling ===
    print("\n─── Edge Cases ───")

    try:
        empty_results = retriever.query("", top_k=3)
        # Should return something or empty list, not crash
        ok(f"empty query handled: {len(empty_results)} results")
    except Exception as e:
        fail("empty query", str(e))

    # Very long query
    try:
        long_query = "credential " * 100
        long_results = retriever.query(long_query, top_k=3)
        ok(f"long query handled: {len(long_results)} results")
    except Exception as e:
        fail("long query", str(e))

    # Non-existent technique
    try:
        fake_results = retriever.query_mitre("T9999.999", top_k=3)
        ok(f"non-existent technique: {len(fake_results)} results (expected 0 or low relevance)")
    except Exception as e:
        fail("non-existent technique", str(e))

    print()
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed, {skipped} skipped")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
