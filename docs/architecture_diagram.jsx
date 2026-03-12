import { useState } from "react";

const COLORS = {
  bg: "#f5f1e8",
  panel: "#fffaf1",
  border: "#a88b5f",
  accent: "#7c4f2a",
  accentSoft: "#d9b37a",
  ink: "#20150d",
  inkSoft: "#6a5643",
  ok: "#2d6a4f",
  warn: "#8a5a00",
  muted: "#d8ccb9",
};

const components = [
  {
    id: "input",
    title: "File Replay Input",
    badge: "v1",
    summary: "Local JSON or JSONL benchmark fixtures only.",
    details: [
      "No live SIEM connectors in v1.",
      "Every record must preserve raw provenance.",
      "Replay fixtures are the benchmark contract.",
    ],
  },
  {
    id: "normalize",
    title: "Alert Normalization",
    badge: "Schema",
    summary: "Transforms raw records into UnifiedAlert with explicit missing fields.",
    details: [
      "Adds dataset and parser provenance.",
      "Leaves absent network fields empty rather than inventing values.",
      "Produces the single input contract for the pipeline.",
    ],
  },
  {
    id: "triage",
    title: "Deterministic Triage Path",
    badge: "Core",
    summary: "Prompt build, optional retrieval, single reasoning path, thresholding.",
    details: [
      "No required agent swarm in v1.",
      "OpenClaw is optional, not on the critical path.",
      "Human review is triggered by explicit thresholds.",
    ],
  },
  {
    id: "rag",
    title: "Local Retrieval",
    badge: "Qdrant",
    summary: "Hybrid dense and sparse retrieval for ATT&CK and curated CVE content.",
    details: [
      "Qdrant is used for local and hybrid retrieval.",
      "Retrieval augments evidence; it does not select actions autonomously.",
      "Benchmark labels and rationales are excluded from the RAG corpus.",
    ],
  },
  {
    id: "output",
    title: "Decision Output",
    badge: "Audit",
    summary: "Emits TriageDecision with evidence trace and analyst-safe rationale.",
    details: [
      "No raw chain-of-thought retention.",
      "Includes evidence trace, tool log, and override record.",
      "Writes append-only audit data plus JSONL output.",
    ],
  },
  {
    id: "review",
    title: "Analyst Review",
    badge: "Local UI",
    summary: "CLI and/or local dashboard for review and override.",
    details: [
      "No Telegram or internet-dependent interface in v1.",
      "Designed for offline operation.",
      "Override events are explicit and structured.",
    ],
  },
];

const flow = [
  ["input", "normalize"],
  ["normalize", "triage"],
  ["rag", "triage"],
  ["triage", "output"],
  ["output", "review"],
];

export default function ArchitectureDiagram() {
  const [selected, setSelected] = useState("triage");
  const active = components.find((item) => item.id === selected);

  return (
    <div
      style={{
        minHeight: "100vh",
        background:
          "radial-gradient(circle at top, #fff7eb 0%, #f5f1e8 48%, #efe4d0 100%)",
        color: COLORS.ink,
        fontFamily: "'IBM Plex Sans', 'Avenir Next', sans-serif",
      }}
    >
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 24px 56px" }}>
        <div style={{ marginBottom: 28 }}>
          <div
            style={{
              display: "inline-block",
              padding: "6px 10px",
              border: `1px solid ${COLORS.border}`,
              borderRadius: 999,
              fontSize: 12,
              letterSpacing: 1.4,
              textTransform: "uppercase",
              color: COLORS.inkSoft,
              background: COLORS.panel,
            }}
          >
            Hades v1 Architecture
          </div>
          <h1 style={{ margin: "14px 0 8px", fontSize: 34, lineHeight: 1.1 }}>
            Scoped offline triage prototype
          </h1>
          <p style={{ margin: 0, maxWidth: 760, color: COLORS.inkSoft, fontSize: 16 }}>
            This diagram intentionally shows the narrowed v1 path: file replay,
            normalization, deterministic triage, local retrieval, structured audit
            output, and local analyst review.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 0.8fr", gap: 20 }}>
          <div
            style={{
              background: COLORS.panel,
              border: `1px solid ${COLORS.border}`,
              borderRadius: 24,
              padding: 24,
              boxShadow: "0 18px 48px rgba(60, 39, 14, 0.08)",
            }}
          >
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: 16,
              }}
            >
              {components.map((item) => {
                const isActive = item.id === selected;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelected(item.id)}
                    style={{
                      textAlign: "left",
                      background: isActive ? "#fff0d8" : COLORS.panel,
                      border: `1px solid ${isActive ? COLORS.accent : COLORS.muted}`,
                      borderRadius: 18,
                      padding: 18,
                      cursor: "pointer",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 10,
                      }}
                    >
                      <strong style={{ fontSize: 16 }}>{item.title}</strong>
                      <span
                        style={{
                          fontSize: 11,
                          textTransform: "uppercase",
                          letterSpacing: 1,
                          color: COLORS.accent,
                        }}
                      >
                        {item.badge}
                      </span>
                    </div>
                    <div style={{ color: COLORS.inkSoft, fontSize: 14, lineHeight: 1.45 }}>
                      {item.summary}
                    </div>
                  </button>
                );
              })}
            </div>

            <div
              style={{
                marginTop: 22,
                paddingTop: 18,
                borderTop: `1px dashed ${COLORS.muted}`,
                color: COLORS.inkSoft,
                fontSize: 14,
              }}
            >
              Flow:
              {" "}
              {flow.map(([from, to]) => `${from} -> ${to}`).join(" | ")}
            </div>
          </div>

          <aside
            style={{
              background: COLORS.panel,
              border: `1px solid ${COLORS.border}`,
              borderRadius: 24,
              padding: 24,
              boxShadow: "0 18px 48px rgba(60, 39, 14, 0.08)",
            }}
          >
            <div
              style={{
                display: "inline-block",
                padding: "5px 9px",
                borderRadius: 999,
                background: COLORS.accentSoft,
                color: COLORS.ink,
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: 1,
                marginBottom: 12,
              }}
            >
              Selected component
            </div>
            <h2 style={{ margin: "0 0 8px", fontSize: 24 }}>{active.title}</h2>
            <p style={{ margin: "0 0 18px", color: COLORS.inkSoft, lineHeight: 1.55 }}>
              {active.summary}
            </p>
            <ul style={{ margin: 0, paddingLeft: 18, color: COLORS.inkSoft, lineHeight: 1.7 }}>
              {active.details.map((detail) => (
                <li key={detail}>{detail}</li>
              ))}
            </ul>

            <div
              style={{
                marginTop: 22,
                padding: 16,
                borderRadius: 16,
                background: "#f2eadf",
                border: `1px solid ${COLORS.muted}`,
              }}
            >
              <div style={{ color: COLORS.warn, fontWeight: 700, marginBottom: 6 }}>
                Deferred from v1
              </div>
              <div style={{ color: COLORS.inkSoft, fontSize: 14, lineHeight: 1.6 }}>
                Live SIEM connectors, native swarm orchestration, Telegram workflows,
                automated SOAR actions, and broad cloud comparisons remain future work.
              </div>
            </div>

            <div
              style={{
                marginTop: 16,
                padding: 16,
                borderRadius: 16,
                background: "#eef7f0",
                border: `1px solid ${COLORS.muted}`,
              }}
            >
              <div style={{ color: COLORS.ok, fontWeight: 700, marginBottom: 6 }}>
                Audit contract
              </div>
              <div style={{ color: COLORS.inkSoft, fontSize: 14, lineHeight: 1.6 }}>
                The stable output is an evidence trace plus rationale summary. Raw
                chain-of-thought is not part of the stored interface.
              </div>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
