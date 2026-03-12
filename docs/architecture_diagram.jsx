import { useState } from "react";

const COLORS = {
  bg: "#0a0f1a",
  card: "#111827",
  cardHover: "#1a2234",
  border: "#1e293b",
  borderActive: "#3b82f6",
  blue: "#3b82f6",
  blueLight: "#60a5fa",
  blueDim: "#1e3a5f",
  cyan: "#06b6d4",
  cyanDim: "#0e4a5a",
  green: "#10b981",
  greenDim: "#064e3b",
  orange: "#f59e0b",
  orangeDim: "#78350f",
  red: "#ef4444",
  redDim: "#7f1d1d",
  purple: "#8b5cf6",
  purpleDim: "#4c1d95",
  text: "#e2e8f0",
  textDim: "#94a3b8",
  textMuted: "#64748b",
};

const components = {
  ingestion: {
    id: "ingestion",
    label: "Data Ingestion Layer",
    color: COLORS.orange,
    colorDim: COLORS.orangeDim,
    icon: "⚡",
    x: 50, y: 40, w: 200, h: 80,
    details: {
      purpose: "Normalize and route raw security alerts from multiple SIEM platforms into the agent pipeline.",
      tech: ["Syslog/CEF/LEEF parsers", "Kafka message queue (local)", "Splunk HEC / ELK Logstash / QRadar LEEF connectors", "Custom Python ingestion daemon"],
      inputs: "Raw SIEM alerts (JSON, CEF, syslog)",
      outputs: "Normalized alert objects (JSON schema v1)",
      notes: "Supports batch and streaming modes. Batch for historical replay during evaluation, streaming for real-time triage. Alert normalization maps vendor-specific fields to a unified schema."
    }
  },
  openclaw: {
    id: "openclaw",
    label: "OpenClaw Integration Layer",
    color: COLORS.blue,
    colorDim: COLORS.blueDim,
    icon: "🔧",
    x: 310, y: 40, w: 200, h: 80,
    details: {
      purpose: "Manages tool definitions, API routing, context windows, and serves as the bridge between external security tools and the Kimi K2.5 reasoning engine.",
      tech: ["OpenClaw (Node.js)", "Tool definition registry (YAML)", "Context window manager", "Session state store (SQLite)", "Telegram/CLI interface"],
      inputs: "Normalized alerts, tool call requests from K2.5",
      outputs: "Formatted prompts, tool execution results, session logs",
      notes: "Handles context overflow gracefully via sliding window + summarization. Manages tool versioning and fallback chains. Provides the human-in-the-loop interface for analyst override."
    }
  },
  kimi: {
    id: "kimi",
    label: "Kimi K2.5 Engine",
    color: COLORS.cyan,
    colorDim: COLORS.cyanDim,
    icon: "🧠",
    x: 180, y: 170, w: 200, h: 90,
    details: {
      purpose: "Core reasoning and orchestration. Analyzes alerts, coordinates sub-agents via native swarm, generates triage decisions and playbooks.",
      tech: ["Kimi K2.5 (1T MoE, 32B active)", "vLLM or SGLang serving", "Native INT4 quantization", "256K context window", "Agent swarm protocol"],
      inputs: "Formatted prompts from OpenClaw, RAG context, sub-agent results",
      outputs: "Triage classifications, playbook recommendations, sub-agent task decomposition",
      notes: "Runs in thinking mode (temp=1.0) for complex multi-step triage. Instant mode (temp=0.6) for simple alert classification. Swarm mode decomposes complex incidents into parallel sub-tasks across up to 100 sub-agents."
    }
  },
  classifier: {
    id: "classifier",
    label: "Alert Classifier Agent",
    color: COLORS.green,
    colorDim: COLORS.greenDim,
    icon: "🏷️",
    x: 30, y: 310, w: 160, h: 70,
    details: {
      purpose: "First-pass classification of incoming alerts into triage categories.",
      tech: ["Specialized prompt chain", "Few-shot examples per alert type", "Confidence scoring (0-1)"],
      inputs: "Single normalized alert + historical context",
      outputs: "Classification: {True Positive | False Positive | Needs Investigation | Escalate}, confidence score, reasoning chain",
      notes: "Low-confidence classifications (< 0.7) automatically trigger the Log Correlator for additional context before final decision. Maintains per-alert-type accuracy tracking for continuous prompt improvement."
    }
  },
  correlator: {
    id: "correlator",
    label: "Log Correlator Agent",
    color: COLORS.green,
    colorDim: COLORS.greenDim,
    icon: "🔗",
    x: 210, y: 310, w: 160, h: 70,
    details: {
      purpose: "Pulls related log entries and events to build context around ambiguous alerts.",
      tech: ["Time-window correlation (±15min default)", "Source IP/dest IP grouping", "Session reconstruction", "Elasticsearch/OpenSearch queries"],
      inputs: "Alert metadata (IPs, timestamps, signatures)",
      outputs: "Correlated event timeline, related alerts, network flow summary",
      notes: "Uses K2.5's 256K context to process entire incident timelines. Can correlate across multiple log sources (firewall, IDS, endpoint, auth logs). Outputs structured timeline JSON for downstream agents."
    }
  },
  playbook: {
    id: "playbook",
    label: "Playbook Generator Agent",
    color: COLORS.green,
    colorDim: COLORS.greenDim,
    icon: "📋",
    x: 390, y: 310, w: 160, h: 70,
    details: {
      purpose: "Generates specific incident response playbooks based on the classified threat and correlated evidence.",
      tech: ["RAG-augmented generation", "NIST SP 800-61 response framework", "Template library (customizable)", "Severity-based escalation rules"],
      inputs: "Classification result, correlated timeline, RAG threat intelligence",
      outputs: "Step-by-step response playbook, containment recommendations, escalation path, IOC extraction",
      notes: "Playbooks follow NIST incident response lifecycle: Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned. Severity levels map to response urgency and escalation paths."
    }
  },
  rag: {
    id: "rag",
    label: "Local RAG Pipeline",
    color: COLORS.purple,
    colorDim: COLORS.purpleDim,
    icon: "📚",
    x: 80, y: 430, w: 180, h: 70,
    details: {
      purpose: "Provides up-to-date threat intelligence and security knowledge without internet access.",
      tech: ["ChromaDB or Milvus (vector store)", "BGE-M3 or Nomic embedding model (local)", "MITRE ATT&CK v15 (full matrix)", "NVD/CVE feed (periodic offline sync)", "Custom threat intel documents"],
      inputs: "Semantic queries from agents, alert signatures, CVE IDs",
      outputs: "Relevant ATT&CK techniques, CVE details, historical threat reports, remediation guidance",
      notes: "Vector store updated via offline sync (USB, air-gapped transfer). Embedding model runs locally. Chunking strategy: 512 tokens with 128 overlap. Supports hybrid search (semantic + keyword) for precision."
    }
  },
  output: {
    id: "output",
    label: "Output & Decision Layer",
    color: COLORS.red,
    colorDim: COLORS.redDim,
    icon: "📊",
    x: 320, y: 430, w: 180, h: 70,
    details: {
      purpose: "Aggregates all agent outputs into a final triage decision with full audit trail.",
      tech: ["Decision aggregator", "Confidence threshold engine", "Audit log (append-only SQLite)", "SOAR integration hooks", "Dashboard API (FastAPI)"],
      inputs: "Classification, correlation data, playbook, confidence scores",
      outputs: "Final triage decision, response playbook, audit trail, SOAR ticket (optional)",
      notes: "Every decision is logged with full reasoning chain for compliance and review. Analyst can override any decision via the interface. Configurable confidence thresholds per alert severity. Dashboard shows real-time triage metrics, false positive rates, and processing latency."
    }
  },
  eval: {
    id: "eval",
    label: "Evaluation Framework",
    color: COLORS.textMuted,
    colorDim: "#1e293b",
    icon: "📈",
    x: 180, y: 540, w: 200, h: 70,
    details: {
      purpose: "Systematic benchmarking harness for comparing configurations, models, and modes.",
      tech: ["Python evaluation harness", "Automated prompt replay", "Confusion matrix generator", "Latency profiler", "Statistical significance testing (McNemar's, bootstrap CI)"],
      inputs: "Labeled benchmark dataset (1,000+ alerts), system configuration",
      outputs: "Precision/recall/F1 per category, latency distributions, cost analysis, comparison reports",
      notes: "Supports A/B testing between: local vs. cloud, swarm vs. single-agent, RAG vs. zero-shot, different quantization levels. All results stored in structured format for paper-ready visualization."
    }
  }
};

const connections = [
  { from: "ingestion", to: "openclaw", label: "Normalized alerts" },
  { from: "openclaw", to: "kimi", label: "Prompts + context" },
  { from: "kimi", to: "classifier", label: "Classify task" },
  { from: "kimi", to: "correlator", label: "Correlate task" },
  { from: "kimi", to: "playbook", label: "Generate task" },
  { from: "classifier", to: "output", label: "Classification" },
  { from: "correlator", to: "kimi", label: "Context" },
  { from: "playbook", to: "output", label: "Playbook" },
  { from: "rag", to: "classifier", label: "Threat intel" },
  { from: "rag", to: "correlator", label: "ATT&CK data" },
  { from: "rag", to: "playbook", label: "CVE + guidance" },
  { from: "output", to: "eval", label: "Decisions + logs" },
];

function getCenter(comp) {
  return { x: comp.x + comp.w / 2, y: comp.y + comp.h / 2 };
}

export default function ArchitectureDiagram() {
  const [selected, setSelected] = useState("kimi");
  const [hoveredConn, setHoveredConn] = useState(null);
  const sel = components[selected];

  return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", fontFamily: "'JetBrains Mono', 'SF Mono', 'Fira Code', monospace", color: COLORS.text }}>
      {/* Header */}
      <div style={{ padding: "24px 32px 0", borderBottom: `1px solid ${COLORS.border}` }}>
        <div style={{ fontSize: 11, letterSpacing: 3, color: COLORS.textMuted, textTransform: "uppercase", marginBottom: 4 }}>System Architecture</div>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: "0 0 4px", color: COLORS.text }}>Offline Agentic SOC Assistant</h1>
        <p style={{ fontSize: 12, color: COLORS.textDim, margin: "0 0 16px" }}>Kimi K2.5 + OpenClaw + Local RAG — Click any component for details</p>
      </div>

      <div style={{ display: "flex", gap: 0 }}>
        {/* Diagram */}
        <div style={{ flex: "1 1 55%", padding: "20px", minWidth: 0 }}>
          <svg viewBox="-10 10 590 620" style={{ width: "100%", height: "auto" }}>
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6" fill={COLORS.textMuted} />
              </marker>
              <marker id="arrowActive" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6" fill={COLORS.blueLight} />
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            {/* Connections */}
            {connections.map((conn, i) => {
              const from = getCenter(components[conn.from]);
              const to = getCenter(components[conn.to]);
              const isActive = selected === conn.from || selected === conn.to;
              const isHovered = hoveredConn === i;
              const midX = (from.x + to.x) / 2;
              const midY = (from.y + to.y) / 2;
              return (
                <g key={i} onMouseEnter={() => setHoveredConn(i)} onMouseLeave={() => setHoveredConn(null)} style={{ cursor: "default" }}>
                  <line
                    x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                    stroke={isActive ? COLORS.blueLight : COLORS.textMuted}
                    strokeWidth={isActive ? 2 : 1}
                    strokeOpacity={isActive ? 0.7 : 0.2}
                    markerEnd={isActive ? "url(#arrowActive)" : "url(#arrow)"}
                    strokeDasharray={isActive ? "none" : "4,4"}
                  />
                  {(isHovered || isActive) && (
                    <text x={midX} y={midY - 6} textAnchor="middle" fontSize={9} fill={COLORS.textDim}
                      style={{ pointerEvents: "none" }}>
                      {conn.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Layer labels */}
            {[
              { y: 28, label: "INGESTION + ROUTING" },
              { y: 158, label: "REASONING ENGINE" },
              { y: 298, label: "AGENT SWARM" },
              { y: 418, label: "KNOWLEDGE + OUTPUT" },
              { y: 530, label: "EVALUATION" },
            ].map((l, i) => (
              <text key={i} x={565} y={l.y} textAnchor="end" fontSize={8} fill={COLORS.textMuted}
                letterSpacing="1.5" fontWeight="600">{l.label}</text>
            ))}

            {/* Component boxes */}
            {Object.values(components).map(comp => {
              const isSelected = selected === comp.id;
              return (
                <g key={comp.id} onClick={() => setSelected(comp.id)} style={{ cursor: "pointer" }}>
                  <rect
                    x={comp.x} y={comp.y} width={comp.w} height={comp.h} rx={8}
                    fill={isSelected ? comp.colorDim : COLORS.card}
                    stroke={isSelected ? comp.color : COLORS.border}
                    strokeWidth={isSelected ? 2 : 1}
                    filter={isSelected ? "url(#glow)" : "none"}
                  />
                  <text x={comp.x + 12} y={comp.y + 24} fontSize={14}>{comp.icon}</text>
                  <text x={comp.x + 32} y={comp.y + 26} fontSize={11} fontWeight="600"
                    fill={isSelected ? comp.color : COLORS.text}>
                    {comp.label.length > 22 ? comp.label.slice(0, 20) + "..." : comp.label}
                  </text>
                  {comp.h > 75 && (
                    <text x={comp.x + 12} y={comp.y + 46} fontSize={9} fill={COLORS.textMuted}>
                      {comp.id === "kimi" ? "1T MoE · 32B active · 256K ctx" : ""}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Detail panel */}
        <div style={{
          flex: "1 1 45%", borderLeft: `1px solid ${COLORS.border}`,
          padding: "20px 24px", overflowY: "auto", maxHeight: "calc(100vh - 100px)"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <span style={{ fontSize: 24 }}>{sel.icon}</span>
            <div>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: sel.color }}>{sel.label}</h2>
              <span style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1 }}>{sel.id}</span>
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Purpose</div>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: COLORS.text, margin: 0 }}>{sel.details.purpose}</p>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Technology Stack</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {sel.details.tech.map((t, i) => (
                <span key={i} style={{
                  fontSize: 11, padding: "3px 8px", borderRadius: 4,
                  background: sel.colorDim, color: sel.color, border: `1px solid ${sel.color}33`
                }}>{t}</span>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Inputs</div>
              <p style={{ fontSize: 12, lineHeight: 1.5, color: COLORS.textDim, margin: 0 }}>{sel.details.inputs}</p>
            </div>
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Outputs</div>
              <p style={{ fontSize: 12, lineHeight: 1.5, color: COLORS.textDim, margin: 0 }}>{sel.details.outputs}</p>
            </div>
          </div>

          <div style={{
            background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8,
            padding: "12px 16px"
          }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Implementation Notes</div>
            <p style={{ fontSize: 12, lineHeight: 1.7, color: COLORS.textDim, margin: 0 }}>{sel.details.notes}</p>
          </div>

          {/* Quick nav */}
          <div style={{ marginTop: 24, borderTop: `1px solid ${COLORS.border}`, paddingTop: 16 }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>All Components</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {Object.values(components).map(c => (
                <button key={c.id} onClick={() => setSelected(c.id)} style={{
                  fontSize: 11, padding: "4px 10px", borderRadius: 4, cursor: "pointer",
                  background: selected === c.id ? c.colorDim : "transparent",
                  color: selected === c.id ? c.color : COLORS.textMuted,
                  border: `1px solid ${selected === c.id ? c.color + "66" : COLORS.border}`,
                  transition: "all 0.15s"
                }}>
                  {c.icon} {c.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
