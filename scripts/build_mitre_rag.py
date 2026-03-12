#!/usr/bin/env python3
"""Build MITRE ATT&CK RAG documents from STIX data.

Extracts technique descriptions, detection guidance, and relationships
into structured documents suitable for vector store ingestion.

Usage:
    python3 scripts/build_mitre_rag.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

STIX_PATH = Path(__file__).parent.parent / "data" / "mitre_attack" / "enterprise-attack.json"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "mitre_attack" / "rag_documents"


def extract_techniques(stix_data: dict) -> list[dict]:
    """Extract active techniques with descriptions and metadata."""
    objects = stix_data["objects"]

    # Build lookup maps
    tactics_map: dict[str, str] = {}
    for obj in objects:
        if obj["type"] == "x-mitre-tactic":
            short_name = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            tactics_map[short_name] = name

    # Build relationship map (technique → data sources, mitigations)
    relationships: dict[str, list[dict]] = {}
    for obj in objects:
        if obj["type"] == "relationship" and not obj.get("revoked", False):
            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "")
            if source_ref and target_ref:
                relationships.setdefault(source_ref, []).append({
                    "type": rel_type,
                    "target": target_ref,
                    "description": obj.get("description", ""),
                })

    # Extract analytics (detection queries)
    analytics: dict[str, list[str]] = {}
    for obj in objects:
        if obj["type"] == "x-mitre-analytic":
            for ref in obj.get("x_mitre_attack_pattern_refs", []):
                analytics.setdefault(ref, []).append(
                    obj.get("description", obj.get("name", ""))
                )

    # Build object ID → name map
    id_to_name: dict[str, str] = {}
    for obj in objects:
        if "name" in obj and "id" in obj:
            id_to_name[obj["id"]] = obj["name"]

    techniques = []
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not technique_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        platforms = obj.get("x_mitre_platforms", [])
        detection = obj.get("x_mitre_detection", "")

        # Extract tactics
        kill_chain = obj.get("kill_chain_phases", [])
        tactic_names = [
            tactics_map.get(kc.get("phase_name", ""), kc.get("phase_name", ""))
            for kc in kill_chain
            if kc.get("kill_chain_name") == "mitre-attack"
        ]

        # Get related data sources and mitigations
        rels = relationships.get(obj["id"], [])
        mitigations = [
            id_to_name.get(r["target"], r["target"])
            for r in rels if r["type"] == "mitigates"
        ]
        data_sources = obj.get("x_mitre_data_sources", [])

        # Get analytics
        technique_analytics = analytics.get(obj["id"], [])

        techniques.append({
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "detection": detection,
            "tactics": tactic_names,
            "platforms": platforms,
            "data_sources": data_sources,
            "mitigations": mitigations[:5],
            "analytics": technique_analytics[:3],
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        })

    return techniques


def build_rag_document(technique: dict) -> str:
    """Build a RAG-friendly document from a technique."""
    parts = [
        f"# {technique['technique_id']}: {technique['name']}",
        "",
        f"**Tactics:** {', '.join(technique['tactics'])}",
        f"**Platforms:** {', '.join(technique['platforms'])}",
        "",
        "## Description",
        technique["description"][:2000],
    ]

    if technique["detection"]:
        parts.extend([
            "",
            "## Detection Guidance",
            technique["detection"][:1500],
        ])

    if technique["data_sources"]:
        parts.extend([
            "",
            "## Data Sources",
            ", ".join(technique["data_sources"][:10]),
        ])

    if technique["mitigations"]:
        parts.extend([
            "",
            "## Mitigations",
            ", ".join(technique["mitigations"]),
        ])

    if technique["analytics"]:
        parts.extend([
            "",
            "## Detection Analytics",
        ])
        for a in technique["analytics"]:
            parts.append(f"- {a[:200]}")

    return "\n".join(parts)


def main() -> None:
    if not STIX_PATH.exists():
        print(f"❌ STIX data not found: {STIX_PATH}")
        print("   Download from: https://github.com/mitre-attack/attack-stix-data")
        sys.exit(1)

    print("Loading MITRE ATT&CK STIX data...")
    with STIX_PATH.open() as f:
        stix_data = json.load(f)

    techniques = extract_techniques(stix_data)
    print(f"Extracted {len(techniques)} active techniques")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Write individual technique documents
    for tech in techniques:
        doc = build_rag_document(tech)
        filepath = OUTPUT_DIR / f"{tech['technique_id']}.md"
        filepath.write_text(doc)

    # Write index
    index = {
        "total_techniques": len(techniques),
        "techniques": [
            {
                "id": t["technique_id"],
                "name": t["name"],
                "tactics": t["tactics"],
                "platforms": t["platforms"],
            }
            for t in techniques
        ],
    }
    (OUTPUT_DIR / "index.json").write_text(json.dumps(index, indent=2))

    # Write JSONL for vector store ingestion
    jsonl_path = OUTPUT_DIR / "techniques.jsonl"
    with jsonl_path.open("w") as f:
        for tech in techniques:
            doc = build_rag_document(tech)
            record = {
                "id": tech["technique_id"],
                "text": doc,
                "metadata": {
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactics": tech["tactics"],
                    "url": tech["url"],
                },
            }
            f.write(json.dumps(record) + "\n")

    # Stats
    tactic_counts = {}
    for tech in techniques:
        for tactic in tech["tactics"]:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    print(f"\nWritten to {OUTPUT_DIR}/")
    print(f"  {len(techniques)} technique documents (.md)")
    print(f"  1 index (index.json)")
    print(f"  1 JSONL for vector store (techniques.jsonl)")
    print(f"\nTactic distribution:")
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        print(f"  {tactic:30} {count:>4}")


if __name__ == "__main__":
    main()
