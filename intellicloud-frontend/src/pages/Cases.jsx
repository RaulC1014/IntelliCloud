// src/pages/Cases.jsx
import React, { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api/http";

// ─── Status and priority config ──────────────────────────────────────────────
const STATUS_CONFIG = {
  open:         { label: "Open",         badge: "glass-panel",  dot: "#ef4444" },
  investigating:{ label: "Investigating",badge: "glass-panel",   dot: "#f59e0b" },
  closed:       { label: "Closed",       badge: "glass-panel",   dot: "#22c55e" },
};

const PRIORITY_CONFIG = {
  critical: { label: "Critical", badge: "glass-panel" },
  high:     { label: "High",     badge: "glass-panel" },
  medium:   { label: "Medium",   badge: "glass-panel"  },
  low:      { label: "Low",      badge: "glass-panel"  },
};

// ─── Mock data — replace with real API calls when DB is ready ─────────────────
const MOCK_CASES = [
  {
    id: 1,
    title: "Suspected RDP Brute Force — 45.33.32.156",
    status: "investigating",
    priority: "high",
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
    assigned_to: "analyst@intellicloud.io",
    alert_count: 14,
    description: "Multiple inbound RDP connection attempts from known scanner IP. Possible credential stuffing attack.",
    events: [
      { id: 1, type: "note",       content: "Opened case after 14 High alerts from same source IP within 10 minutes.", created_at: new Date(Date.now() - 86400000 * 2).toISOString() },
      { id: 2, type: "action",     content: "Ran IP lookup — AbuseIPDB score 97/100. Known Shodan scanner.", created_at: new Date(Date.now() - 86400000 * 1.5).toISOString() },
      { id: 3, type: "note",       content: "Checked RDP logs — no successful authentications. All attempts failed.", created_at: new Date(Date.now() - 3600000 * 5).toISOString() },
      { id: 4, type: "escalation", content: "Escalated to firewall team to add IP to blocklist.", created_at: new Date(Date.now() - 3600000).toISOString() },
    ],
  },
  {
    id: 2,
    title: "DNS Anomaly — High-entropy domain queries from 192.168.1.45",
    status: "open",
    priority: "medium",
    created_at: new Date(Date.now() - 3600000 * 6).toISOString(),
    updated_at: new Date(Date.now() - 3600000 * 6).toISOString(),
    assigned_to: "",
    alert_count: 3,
    description: "Internal workstation making DNS queries for unusually long, high-entropy domain names. Possible DNS tunneling or DGA malware.",
    events: [
      { id: 1, type: "note", content: "Three DNS anomaly alerts in 20 minutes from same internal host.", created_at: new Date(Date.now() - 3600000 * 6).toISOString() },
    ],
  },
  {
    id: 3,
    title: "ARP Spoofing Detected on LAN",
    status: "open",
    priority: "critical",
    created_at: new Date(Date.now() - 1800000).toISOString(),
    updated_at: new Date(Date.now() - 1800000).toISOString(),
    assigned_to: "",
    alert_count: 1,
    description: "ARP cache conflict detected — IP address changed to a different MAC. Possible MITM attack on the local network.",
    events: [
      { id: 1, type: "note", content: "ARP spoofing alert triggered. Conflicting MAC for 192.168.1.1 gateway address.", created_at: new Date(Date.now() - 1800000).toISOString() },
    ],
  },
];

// ─── API helpers (stubbed for offline, real when DB is up) ────────────────────
async function fetchCases() {
  try {
    return await apiFetch("cases");
  } catch {
    // Return mock data when backend isn't ready
    return MOCK_CASES;
  }
}

async function createCase(payload) {
  try {
    return await apiFetch("cases", { method: "POST", body: JSON.stringify(payload) });
  } catch {
    return { ...payload, id: Date.now(), created_at: new Date().toISOString(), updated_at: new Date().toISOString(), events: [] };
  }
}

async function addCaseEvent(caseId, content, type = "note") {
  try {
    return await apiFetch(`cases/${caseId}/events`, { method: "POST", body: JSON.stringify({ content, type }) });
  } catch {
    return { id: Date.now(), type, content, created_at: new Date().toISOString() };
  }
}

async function updateCaseStatus(caseId, status) {
  try {
    return await apiFetch(`cases/${caseId}`, { method: "PATCH", body: JSON.stringify({ status }) });
  } catch {
    return null;
  }
}

// ─── Timeline event component ─────────────────────────────────────────────────
function TimelineEvent({ event }) {
  const iconMap = {
    note:       { icon: "📝", color: "rgba(255, 255, 255, 0.6)" },
    action:     { icon: "⚡", color: "#fff" }, // Removed solid blue
    escalation: { icon: "🔺", color: "#ef4444" },
    resolved:   { icon: "✅", color: "#22c55e" },
    alert:      { icon: "🚨", color: "#f59e0b" },
  };
  const cfg = iconMap[event.type] || iconMap.note;

  return (
    <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
      <div className="glass-panel" style={{
        width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 14,
      }}>
        {cfg.icon}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: "var(--text-1)", lineHeight: 1.5 }}>{event.content}</div>
        <div style={{ fontSize: 11, color: "rgba(255, 255, 255, 0.4)", marginTop: 4 }}>
          {new Date(event.created_at).toLocaleString()}
          <span style={{ marginLeft: 8, textTransform: "capitalize", color: cfg.color }}>
            {event.type}
          </span>
        </div>
      </div>
    </div>
  );
}

// ─── Case detail panel ────────────────────────────────────────────────────────
function CaseDetail({ caseData, onUpdate, onClose }) {
  const [note, setNote] = useState("");
  const [noteType, setNoteType] = useState("note");
  const [submitting, setSubmitting] = useState(false);
  const [localCase, setLocalCase] = useState(caseData);

  useEffect(() => setLocalCase(caseData), [caseData]);

  const handleAddNote = async () => {
    if (!note.trim()) return;
    setSubmitting(true);
    const newEvent = await addCaseEvent(localCase.id, note.trim(), noteType);
    const updated = { ...localCase, events: [...(localCase.events || []), newEvent] };
    setLocalCase(updated);
    onUpdate(updated);
    setNote("");
    setSubmitting(false);
  };

  const handleStatusChange = async (newStatus) => {
    await updateCaseStatus(localCase.id, newStatus);
    const updated = { ...localCase, status: newStatus };
    setLocalCase(updated);
    onUpdate(updated);
  };

  const statusCfg = STATUS_CONFIG[localCase.status] || STATUS_CONFIG.open;
  const priCfg = PRIORITY_CONFIG[localCase.priority] || PRIORITY_CONFIG.medium;

  return (
    <div className="glass-panel" style={{
      position: "fixed", top: 0, right: 0, width: 560, height: "100vh",
      background: "rgba(11, 15, 23, 0.85)", borderLeft: "1px solid rgba(255, 255, 255, 0.05)",
      zIndex: 200, display: "flex", flexDirection: "column",
      boxShadow: "-4px 0 24px rgba(0,0,0,0.3)",
    }}>
      {/* Header */}
      <div style={{
        padding: "20px 24px", borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
        background: "transparent", display: "flex", justifyContent: "space-between", alignItems: "flex-start",
      }}>
        <div style={{ flex: 1, marginRight: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
            <span className={`badge ${statusCfg.badge}`}>{statusCfg.label}</span>
            <span className={`badge ${priCfg.badge}`}>{priCfg.label}</span>
            <span style={{ fontSize: 11, color: "rgba(255, 255, 255, 0.5)", padding: "2px 0" }}>
              #{localCase.id} · {localCase.alert_count} alerts
            </span>
          </div>
          <h3 className="gradient-text" style={{ margin: 0, fontSize: 16, fontWeight: 700, lineHeight: 1.4 }}>{localCase.title}</h3>
          {localCase.assigned_to && (
            <div style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.5)", marginTop: 6 }}>
              Assigned to: {localCase.assigned_to}
            </div>
          )}
        </div>
        <button className="btn-glass" onClick={onClose} style={{ padding: "6px 10px", flexShrink: 0, borderRadius: "50%" }}>✕</button>
      </div>

      {/* Status controls */}
      <div style={{ padding: "12px 24px", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", display: "flex", gap: 8 }}>
        {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
          <button
            key={key}
            className="btn-glass"
            onClick={() => handleStatusChange(key)}
            disabled={localCase.status === key}
            style={{
              fontSize: 12, padding: "5px 12px",
              background: localCase.status === key ? "rgba(255, 255, 255, 0.1)" : "transparent",
              borderColor: localCase.status === key ? cfg.dot : "rgba(255, 255, 255, 0.1)",
              color: localCase.status === key ? "#fff" : "rgba(255, 255, 255, 0.5)",
            }}
          >
            {cfg.label}
          </button>
        ))}
      </div>

      {/* Description */}
      {localCase.description && (
        <div style={{ padding: "12px 24px", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", fontSize: 13, color: "rgba(255, 255, 255, 0.7)" }}>
          {localCase.description}
        </div>
      )}

      {/* Timeline */}
      <div style={{ flex: 1, overflow: "auto", padding: "20px 24px" }}>
        <div style={{ fontWeight: 700, fontSize: 12, color: "rgba(255, 255, 255, 0.8)", marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
          Investigation Timeline
        </div>
        {(localCase.events || []).length === 0 ? (
          <div style={{ color: "rgba(255, 255, 255, 0.5)", fontSize: 13 }}>No timeline entries yet. Add a note below.</div>
        ) : (
          (localCase.events || []).map(ev => <TimelineEvent key={ev.id} event={ev} />)
        )}
      </div>

      {/* Add note */}
      <div style={{ padding: "16px 24px", borderTop: "1px solid rgba(255, 255, 255, 0.05)", background: "transparent" }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          {["note", "action", "escalation"].map(t => (
            <button
              key={t}
              onClick={() => setNoteType(t)}
              style={{
                fontSize: 11, padding: "4px 10px", borderRadius: 4, border: "1px solid rgba(255, 255, 255, 0.1)",
                cursor: "pointer", textTransform: "capitalize", fontWeight: 600,
                background: noteType === t ? "rgba(255, 255, 255, 0.1)" : "transparent",
                color: noteType === t ? "#fff" : "rgba(255, 255, 255, 0.5)",
                transition: "all 0.2s ease"
              }}
            >
              {t}
            </button>
          ))}
        </div>
        <textarea
          className="input glass-panel"
          rows={3}
          placeholder="Add a note, action taken, or escalation..."
          value={note}
          onChange={e => setNote(e.target.value)}
          style={{ fontSize: 13, resize: "none", marginBottom: 8 }}
          onKeyDown={e => { if (e.key === "Enter" && e.ctrlKey) handleAddNote(); }}
        />
        <button
          className="btn-glass"
          onClick={handleAddNote}
          disabled={submitting || !note.trim()}
          style={{ width: "100%", justifyContent: "center" }}
        >
          {submitting ? "Adding..." : "Add to Timeline (Ctrl+Enter)"}
        </button>
      </div>
    </div>
  );
}

// ─── New case modal ───────────────────────────────────────────────────────────
function NewCaseModal({ onClose, onCreate }) {
  const [form, setForm] = useState({ title: "", priority: "medium", description: "", assigned_to: "" });
  const [saving, setSaving] = useState(false);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSubmit = async () => {
    if (!form.title.trim()) return;
    setSaving(true);
    const created = await createCase({ ...form, status: "open", alert_count: 0, events: [] });
    onCreate(created);
    setSaving(false);
    onClose();
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
      zIndex: 300, display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div className="glass-panel" style={{
        background: "rgba(11, 15, 23, 0.85)", border: "1px solid rgba(255, 255, 255, 0.1)",
        borderRadius: 12, padding: 32, width: 520, boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
      }}>
        <h3 className="gradient-text" style={{ margin: "0 0 24px", fontSize: 18 }}>Open New Case</h3>

        <div style={{ marginBottom: 16 }}>
          <label className="label" style={{ color: "rgba(255, 255, 255, 0.6)" }}>Case Title *</label>
          <input className="input glass-panel" placeholder="e.g. Suspected RDP brute force from 45.33.32.156"
            value={form.title} onChange={e => set("title", e.target.value)} />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
          <div>
            <label className="label" style={{ color: "rgba(255, 255, 255, 0.6)" }}>Priority</label>
            <select className="select glass-panel" value={form.priority} onChange={e => set("priority", e.target.value)}>
              {Object.entries(PRIORITY_CONFIG).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" style={{ color: "rgba(255, 255, 255, 0.6)" }}>Assign To (optional)</label>
            <input className="input glass-panel" placeholder="analyst@example.com"
              value={form.assigned_to} onChange={e => set("assigned_to", e.target.value)} />
          </div>
        </div>

        <div style={{ marginBottom: 24 }}>
          <label className="label" style={{ color: "rgba(255, 255, 255, 0.6)" }}>Description (optional)</label>
          <textarea className="input glass-panel" rows={3} placeholder="Brief summary of what triggered this case..."
            value={form.description} onChange={e => set("description", e.target.value)}
            style={{ resize: "none" }} />
        </div>

        <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
          <button className="btn-glass" onClick={onClose} style={{ background: "transparent" }}>Cancel</button>
          <button className="btn-glass" onClick={handleSubmit} disabled={saving || !form.title.trim()}>
            {saving ? "Creating..." : "Open Case"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Cases Page ──────────────────────────────────────────────────────────
export default function Cases() {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState(null);
  const [showNewModal, setShowNewModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const [priorityFilter, setPriorityFilter] = useState("all");
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const data = await fetchCases();
    setCases(Array.isArray(data) ? data : []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = cases.filter(c => {
    if (statusFilter !== "all" && c.status !== statusFilter) return false;
    if (priorityFilter !== "all" && c.priority !== priorityFilter) return false;
    if (search && !c.title.toLowerCase().includes(search.toLowerCase()) &&
        !c.description?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleUpdate = (updated) => {
    setCases(prev => prev.map(c => c.id === updated.id ? updated : c));
    if (selectedCase?.id === updated.id) setSelectedCase(updated);
  };

  const handleCreate = (created) => {
    setCases(prev => [created, ...prev]);
  };

  // Stats
  const openCount     = cases.filter(c => c.status === "open").length;
  const invCount      = cases.filter(c => c.status === "investigating").length;
  const closedCount   = cases.filter(c => c.status === "closed").length;
  const criticalCount = cases.filter(c => c.priority === "critical" && c.status !== "closed").length;

  return (
    <div className="shell animate-fade" style={{ maxWidth: 1400 }}>

      {/* Page header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 className="gradient-text" style={{ margin: 0, fontSize: 24, fontWeight: 800 }}>Case Management</h1>
          <p style={{ margin: "4px 0 0", color: "rgba(255, 255, 255, 0.6)", fontSize: 14 }}>
            Track and investigate security incidents from alert to resolution.
          </p>
        </div>
        <button className="btn-glass" onClick={() => setShowNewModal(true)}>
          + Open New Case
        </button>
      </div>

      {/* Stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        {[
          { label: "Open",          value: openCount,     color: "#ef4444" },
          { label: "Investigating", value: invCount,       color: "#f59e0b" },
          { label: "Closed",        value: closedCount,    color: "#22c55e" },
          { label: "Critical Open", value: criticalCount,  color: "#dc2626" },
        ].map(s => (
          <div key={s.label} className="card glass-panel hover-card" style={{ padding: "16px 20px" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: s.color, fontFamily: "monospace" }}>{s.value}</div>
            <div style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.6)", fontWeight: 600, marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="card glass-panel hover-card" style={{ padding: 12, marginBottom: 16, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="input glass-panel" placeholder="Search cases..."
          value={search} onChange={e => setSearch(e.target.value)}
          style={{ width: 260 }}
        />
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>STATUS:</span>
          <select className="select glass-panel" style={{ width: 150 }} value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            <option value="all">All</option>
            {Object.entries(STATUS_CONFIG).map(([k,v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>PRIORITY:</span>
          <select className="select glass-panel" style={{ width: 150 }} value={priorityFilter} onChange={e => setPriorityFilter(e.target.value)}>
            <option value="all">All</option>
            {Object.entries(PRIORITY_CONFIG).map(([k,v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
        <span style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.4)", marginLeft: "auto" }}>
          {filtered.length} of {cases.length} cases
        </span>
      </div>

      {/* Cases table */}
      <div className="card glass-panel" style={{ padding: 0, overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: 48, textAlign: "center", color: "rgba(255, 255, 255, 0.6)" }}>Loading cases...</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 48, textAlign: "center", color: "rgba(255, 255, 255, 0.6)" }}>
            {cases.length === 0 ? "No cases yet. Click \"Open New Case\" to create one." : "No cases match your filters."}
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", background: "transparent" }}>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Case</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Status</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Priority</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Alerts</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Assigned</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Updated</th>
                <th style={{ padding: "10px 16px", textAlign: "left", fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)" }}>Timeline</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(c => {
                const sCfg = STATUS_CONFIG[c.status] || STATUS_CONFIG.open;
                const pCfg = PRIORITY_CONFIG[c.priority] || PRIORITY_CONFIG.medium;
                return (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedCase(c)}
                    style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)", cursor: "pointer", transition: "background 0.2s ease" }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <td style={{ padding: "12px 16px", maxWidth: 380 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{c.title}</div>
                      {c.description && (
                        <div style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.5)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 360 }}>
                          {c.description}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <span className={`badge ${sCfg.badge}`}>{sCfg.label}</span>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <span className={`badge ${pCfg.badge}`}>{pCfg.label}</span>
                    </td>
                    <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 13 }}>
                      {c.alert_count || 0}
                    </td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "rgba(255, 255, 255, 0.5)" }}>
                      {c.assigned_to || <span style={{ opacity: 0.4 }}>Unassigned</span>}
                    </td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "rgba(255, 255, 255, 0.5)", fontFamily: "monospace" }}>
                      {new Date(c.updated_at || c.created_at).toLocaleDateString()}
                    </td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "rgba(255, 255, 255, 0.5)" }}>
                      {(c.events || []).length} entries
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail panel */}
      {selectedCase && (
        <CaseDetail
          caseData={selectedCase}
          onUpdate={handleUpdate}
          onClose={() => setSelectedCase(null)}
        />
      )}

      {/* New case modal */}
      {showNewModal && (
        <NewCaseModal
          onClose={() => setShowNewModal(false)}
          onCreate={handleCreate}
        />
      )}
    </div>
  );
}