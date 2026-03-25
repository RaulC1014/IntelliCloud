import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { USE_MOCK, API_BASE_URL } from "../config";
import { mapThreat } from "../adapters";
import { agentStart, agentStop } from "../api/agent";
import useTrafficStream from "../hooks/useTrafficStream";

const FilterIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
    </svg>
  );
const DownloadIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);
const TrashIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="3 6 5 6 21 6" />
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </svg>
);
const RefreshIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M23 4v6h-6" />
    <path d="M1 20v-6h6" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
);
const SparklesIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 2L9.91 8.26 3.65 10.35 9.91 12.44 12 18.7 14.09 12.44 20.35 10.35 14.09 8.26 12 2z" />
  </svg>
);

const levels = ["All", "Critical", "High", "Medium", "Low", "Info"];
const protocols = ["All", "System", "TCP", "UDP", "HTTP", "HTTPS", "SSH"];

const levelBadge = (lvl) => {
  const key = (lvl || "").toLowerCase();
  if (key === "critical") return "badge crit";
  if (key === "high") return "badge high";
  if (key === "medium") return "badge med";
  if (key === "low") return "badge low";
  return "badge ok";
};

const api = (p) => `${API_BASE_URL.replace(/\/+$/, "")}${p.startsWith("/") ? "" : "/"}${p}`;

function AIAgentPanel({ selectedData, onClose }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  useEffect(() => {
    if (selectedData) {
      setMessages([]);
      handleSend("Analyze this threat signature.", selectedData, []);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedData]);

  const handleSend = async (text, contextOverride = null, historyOverride = null) => {
    if (!text.trim()) return;
    const currentHistory = historyOverride || messages;
    const newHistory = [...currentHistory, { role: "user", content: text }];
    setMessages(newHistory);
    setInput("");
    setLoading(true);
    try {
      const res = await fetch(api("/chat"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ context: contextOverride || selectedData, messages: newHistory }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.detail || "API Error");
      setMessages((prev) => [...prev, { role: "model", content: data.response }]);
    } catch {
      setMessages((prev) => [...prev, { role: "model", content: "⚠️ Connection lost. Unable to reach neural core." }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`ai-panel ${selectedData ? "open" : ""}`}>
      <div
        style={{
          padding: 24,
          borderBottom: "1px solid var(--border)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "var(--panel-2)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>IntelliCloud Agent</h3>
            <div
              style={{
                fontSize: 11,
                color: "var(--brand)",
                textTransform: "uppercase",
                letterSpacing: 1,
                fontWeight: 700,
              }}
            >
              {selectedData ? `Target: ${selectedData.src}` : "Standby"}
            </div>
          </div>
        </div>
        <button className="btn icon-only" onClick={onClose} style={{ background: "transparent", border: "none" }}>
          ✕
        </button>
      </div>

      <div className="ai-content" ref={scrollRef} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {messages.map((msg, i) => (
          <div
            key={i}
            className="ai-message animate-fade"
            style={{
              borderLeft: msg.role === "model" ? "3px solid var(--brand)" : "3px solid var(--text-2)",
              background: msg.role === "user" ? "transparent" : "var(--panel-2)",
              marginLeft: msg.role === "user" ? 20 : 0,
              marginRight: msg.role === "user" ? 0 : 20,
            }}
          >
            <div className="ai-badge" style={{ background: msg.role === "user" ? "var(--text-2)" : undefined }}>
              {msg.role === "user" ? "You" : "Analyst"}
            </div>
            <div style={{ whiteSpace: "pre-line", fontSize: 14, lineHeight: 1.6 }}>{msg.content}</div>
          </div>
        ))}

        {loading && (
          <div className="ai-message" style={{ borderLeft: "3px solid var(--brand)" }}>
            <span className="typing-dot"></span>
            <span className="typing-dot" style={{ animationDelay: "0.2s" }}></span>
            <span className="typing-dot" style={{ animationDelay: "0.4s" }}></span>
          </div>
        )}
      </div>

      <div style={{ padding: 16, borderTop: "1px solid var(--border)", background: "var(--panel-2)" }}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend(input);
          }}
        >
          <input
            className="input"
            placeholder="Ask a follow-up question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading || !selectedData}
          />
        </form>
      </div>
    </div>
  );
}

function useThreats() {
  const [raw, setRaw] = useState([]);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const url = USE_MOCK ? '/mock/threats.json' : `${API_BASE_URL}/api/threats`;
        const res = await fetch(url);
        const data = await res.json();
        if (active) setRaw((Array.isArray(data) ? data : data?.items ?? []).map(mapThreat));
      } catch {
        if (active) setRaw([]);
      }
    })();
    return () => {
      active = false;
    };
  }, []);
  return { raw };
}

function useAuditSSE({ path }) {
  const [audits, setAudits] = useState([]);
  const clear = useCallback(() => setAudits([]), []);
  const esRef = useRef(null);

  useEffect(() => {
    if (import.meta.env.DEV && esRef.current) return;

    let closed = false;
    const es = new EventSource(path);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        if (closed) return;
        const ev = JSON.parse(e.data);
        setAudits((prev) => [ev, ...prev].slice(0, 200));
      } catch {}
    };

    es.onerror = () => {};

    return () => {
      closed = true;
      try {
        es.close();
      } catch {}
      esRef.current = null;
    };
  }, [path]);

  return { audits, clear };
}

function ccToFlag(cc) {
  if (!cc || cc.length !== 2) return "";
  const base = 127397;
  return String.fromCodePoint(...cc.toUpperCase().split("").map((c) => c.charCodeAt(0) + base));
}

function GeoTag({ cc, city, org }) {
  if (!cc && !city && !org) return null;
  return (
    <span className="geo" style={{ display: "flex", alignItems: "center", gap: 6, opacity: 0.8, fontSize: 12 }}>
      {cc && (
        <span className="flag" title={cc} style={{ fontSize: 14 }}>
          {ccToFlag(cc)}
        </span>
      )}
      {city && <span className="city">{city}</span>}
      {org && <span className="asn" style={{ opacity: 0.6 }}>• {org}</span>}
    </span>
  );
}

export default function Dashboard() {
  const trafficPath = api("/api/traffic/stream");
  const auditPath = api("/api/stream/audit");

  const { raw: threats } = useThreats();
  const { audits, clear: clearAudits } = useAuditSSE({ path: auditPath });

  const clientKey = import.meta.env.VITE_CLIENT_KEY || "";

  const [trafficRunning, setTrafficRunning] = useState(() => {
    const v = localStorage.getItem("ic-traffic-running");
    return v !== "false";
  });

  useEffect(() => {
    localStorage.setItem("ic-traffic-running", String(trafficRunning));
  }, [trafficRunning]);

  const trafficEnabled = trafficRunning && !!clientKey;

  const trafficHook = useTrafficStream({
    maxRows: 2000,
    flushMs: 250,
    path: trafficPath,
    enabled: trafficEnabled,
    storageKey: "ic_lastTrafficId",
    clientKey,
  });

  const sseEvents = trafficHook?.rows ?? [];
  const clearTraffic = trafficHook?.clear ?? (() => {});
  const trafficConnected = Boolean(trafficHook?.connected);
  const trafficLastId = trafficHook?.lastId ?? null;
  const resetTrafficCursor =
    trafficHook?.resetCursor ||
    (() => {
      localStorage.setItem("ic_lastTrafficId", "0");
    });

  const trafficSeenRef = useRef(new Set());
  const [totalEvents, setTotalEvents] = useState(0);

  useEffect(() => {
    if (!Array.isArray(sseEvents)) return;
    let added = 0;
    for (const ev of sseEvents) {
      const id = ev?.eid || ev?.id || `${ev?.ts ?? ""}-${ev?.src ?? ""}-${ev?.dst ?? ""}-${ev?.sport ?? ""}-${ev?.dport ?? ""}`;
      if (!id) continue;
      if (!trafficSeenRef.current.has(id)) {
        trafficSeenRef.current.add(id);
        added += 1;
      }
    }
    if (added) setTotalEvents((n) => n + added);

    if (trafficSeenRef.current.size > 100000) {
      const arr = Array.from(trafficSeenRef.current);
      trafficSeenRef.current = new Set(arr.slice(-50000));
    }
  }, [sseEvents]);

  const [selectedForAI, setSelectedForAI] = useState(null);

  const [ipFilter, setIpFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState("All");
  const [sinceTs, setSinceTs] = useState(0);
  const [limit, setLimit] = useState(200);

  const [auditLevel, setAuditLevel] = useState("All");
  const [auditProto, setAuditProto] = useState("All");

  useEffect(() => {
    const s = JSON.parse(localStorage.getItem("ic-filters") || "{}");
    if (typeof s.ipFilter === "string") setIpFilter(s.ipFilter);
    if (typeof s.levelFilter === "string") setLevelFilter(s.levelFilter);
    if (typeof s.limit === "number") setLimit(s.limit);

    const savedSince = Number(localStorage.getItem("ic-traffic-sinceTs") || 0);
    if (Number.isFinite(savedSince) && savedSince > 0) setSinceTs(savedSince);
  }, []);

  useEffect(() => {
    localStorage.setItem("ic-filters", JSON.stringify({ ipFilter, levelFilter, limit }));
  }, [ipFilter, levelFilter, limit]);

  useEffect(() => {
    if (sinceTs && sinceTs > 0) localStorage.setItem("ic-traffic-sinceTs", String(sinceTs));
    else localStorage.removeItem("ic-traffic-sinceTs");
  }, [sinceTs]);

  const handleClearTraffic = () => {
    const now = Date.now();
    setSinceTs(now);
    trafficSeenRef.current = new Set();
    setTotalEvents(0);
    clearTraffic();
  };

  const handleReloadTraffic = () => {
    setSinceTs(0);
  };

  const handleResetCursor = () => {
    resetTrafficCursor();
    trafficSeenRef.current = new Set();
    setTotalEvents(0);
    clearTraffic();
  };

  const startCapture = async () => {
    try {
      await agentStart();
      setTrafficRunning(true);
    } catch (e) {
      console.error("Start capture failed:", e);
      alert(`Start capture failed: ${e?.message || e}`);
    }
  };

  const stopCapture = async () => {
    try {
      await agentStop();
      setTrafficRunning(false);
    } catch (e) {
      console.error("Stop capture failed:", e);
      alert(`Stop capture failed: ${e?.message || e}`);
    }
  };

  const combined = useMemo(() => {
    const ipq = ipFilter.trim();
    const lvlq = levelFilter || "All";

    const rowsFromThreats = threats.map((t) => ({
      type: "threat",
      id: t.id,
      timeMs: new Date(t.detectedAt).getTime(),
      src: t.ip || "",
      dst: t.dst || "",
      proto: t.proto || "",
      sport: t.sport,
      dport: t.dport,
      level: t.level,
      flow: t.source || "Rule",
      dns: t.dns || "",
      src_cc: t.cc,
      src_city: t.city,
      src_asnorg: t.asn,
    }));

    const rowsFromSSE = (Array.isArray(sseEvents) ? sseEvents : []).map((ev) => {
      const t = ev.event_ts ? Date.parse(ev.event_ts) : ev.created_at ? Date.parse(ev.created_at) : ev.ts ? Math.floor(ev.ts * 1000) : Date.now();
      return {
        type: "traffic",
        id: ev.id ?? ev.eid ?? `${ev.ts}-${ev.src}`,
        timeMs: Number.isFinite(t) ? t : Date.now(),
        src: ev.src || ev.src_ip,
        dst: ev.dst || ev.dst_ip,
        proto: ev.proto || ev.protocol,
        sport: ev.sport ?? ev.src_port,
        dport: ev.dport ?? ev.dst_port,
        level: ev.level || "Low",
        flow: ev.dir || ev.direction || "Live",
        dns: ev.dns || ev.dns_qname || "",
        src_cc: ev.src_cc,
        src_city: ev.src_city,
        src_asnorg: ev.src_asnorg,
        dst_cc: ev.dst_cc,
        dst_city: ev.dst_city,
        dst_asnorg: ev.dst_asnorg,
      };
    });

    let rows = [...rowsFromThreats, ...rowsFromSSE]
      .filter((r) => (ipq ? r.src?.includes(ipq) || r.dst?.includes(ipq) : true))
      .filter((r) => (lvlq === "All" ? true : r.level === lvlq))
      .filter((r) => (sinceTs ? r.timeMs >= sinceTs : true))
      .sort((a, b) => b.timeMs - a.timeMs);

    if (limit && limit > 0) rows = rows.slice(0, limit);
    return rows;
  }, [threats, sseEvents, ipFilter, levelFilter, sinceTs, limit]);

  const filteredAudits = useMemo(() => {
    return audits.filter((a) => {
      if (auditLevel !== "All" && (a.level || "Info") !== auditLevel) return false;
      if (auditProto !== "All" && (a.proto || "System") !== auditProto) return false;
      return true;
    });
  }, [audits, auditLevel, auditProto]);

  const downloadCSV = () => {
    const headers = ["time", "type", "src", "dst", "proto", "sport", "dport", "level", "flow", "status"];
    const lines = [headers.join(",")].concat(
      combined.map((r) =>
        [
          new Date(r.timeMs).toISOString(),
          r.type,
          r.src,
          r.dst,
          r.proto,
          r.sport ?? "",
          r.dport ?? "",
          r.level,
          r.flow,
          "Observed",
        ]
          .map((x) => String(x).replaceAll('"', '""'))
          .map((x) => `"${x}"`)
          .join(",")
      )
    );
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `intellicloud-export-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div className="shell dashboard animate-fade" style={{ maxWidth: 1600 }}>
      <AIAgentPanel selectedData={selectedForAI} onClose={() => setSelectedForAI(null)} />

      <div
        className="card animate-slide"
        style={{
          marginBottom: 20,
          padding: 12,
          display: "flex",
          flexWrap: "wrap",
          gap: 16,
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ position: "relative" }}>
            <div style={{ position: "absolute", left: 10, top: 10, color: "var(--muted)" }}>
              <FilterIcon />
            </div>
            <input
              className="input"
              placeholder="Filter IP Address..."
              style={{ paddingLeft: 34, width: 220 }}
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "var(--muted)", letterSpacing: 0.5 }}>SEVERITY:</span>
            <select className="select" style={{ width: 140 }} value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)}>
              {levels.filter((l) => l !== "Info").map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "var(--muted)", letterSpacing: 0.5 }}>ROWS:</span>
            <select className="select" style={{ width: 140 }} value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value="50">50 Rows</option>
              <option value="100">100 Rows</option>
              <option value="200">200 Rows</option>
              <option value="0">All Rows</option>
            </select>
          </div>

          {(ipFilter || levelFilter !== "All") && (
            <button className="btn ghost" onClick={() => { setIpFilter(""); setLevelFilter("All"); }} style={{ fontSize: 13 }}>
              Reset Filters
            </button>
          )}
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" onClick={handleClearTraffic} title="Clear current view">
            <TrashIcon /> Clear
          </button>
          <button className="btn" onClick={handleReloadTraffic} title="Show all history">
            <RefreshIcon /> Reload
          </button>
          <button className="btn primary" onClick={downloadCSV}>
            <DownloadIcon /> Export CSV
          </button>
        </div>
      </div>

      <div className="grid-halves animate-slide animate-delay-1" style={{ alignItems: "start" }}>
        <div className="card" style={{ padding: 0, overflow: "hidden", height: "75vh", display: "flex", flexDirection: "column" }}>
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "var(--panel-2)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div
                style={{
                  width: 8,
                  height: 8,
                  background: trafficEnabled ? "var(--success)" : "var(--muted)",
                  borderRadius: "50%",
                  boxShadow: trafficEnabled ? "0 0 8px var(--success)" : "none",
                }}
              />
              <h3 style={{ margin: 0, fontSize: 16 }}>Live Traffic Feed</h3>

              <span className="badge ghost" style={{ marginLeft: 10 }}>
                {trafficEnabled ? (trafficConnected ? "Live" : "Reconnecting…") : "Paused"}
                {trafficLastId != null ? ` · lastId=${trafficLastId}` : ""}
              </span>
            </div>

            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {trafficRunning ? (
                <button className="btn" onClick={stopCapture}>
                  ⏸ Pause
                </button>
              ) : (
                <button className="btn primary" onClick={startCapture}>
                  ▶ Start / Resume
                </button>
              )}
              <button className="btn ghost" onClick={handleResetCursor} title="Reset resume cursor and clear view">
                ⟲ Reset Cursor
              </button>

              <span className="badge med">{totalEvents} Events</span>
            </div>
          </div>

          <div style={{ overflow: "auto", flex: 1 }}>
            <table className="table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th>Type</th>
                  <th className="col-src">Source</th>
                  <th className="col-dst">Destination</th>
                  <th className="col-proto">Proto</th>
                  <th className="col-ports">Port</th>
                  <th className="col-level">Severity</th>
                  <th style={{ textAlign: "right" }}>Analysis</th>
                </tr>
              </thead>
              <tbody>
                {combined.map((r) => (
                  <tr key={`${r.type}-${r.id}`} style={{ cursor: "default" }}>
                    <td className="mono" style={{ color: "var(--muted)", fontSize: 13 }}>
                      {new Date(r.timeMs).toLocaleTimeString()}
                    </td>
                    <td>
                      <span className="chip ghost" style={{ fontSize: 11, padding: "2px 8px", height: "auto" }}>
                        {r.type}
                      </span>
                    </td>
                    <td className="mono">
                      <div style={{ fontWeight: 600 }}>{r.src}</div>
                      <GeoTag cc={r.src_cc} city={r.src_city} org={r.src_asnorg} />
                    </td>
                    <td className="mono">
                      <div style={{ fontWeight: 600 }}>{r.dst}</div>
                      <GeoTag cc={r.dst_cc} city={r.dst_city} org={r.dst_asnorg} />
                    </td>
                    <td className="mono" style={{ fontSize: 13 }}>
                      {r.proto}
                    </td>
                    <td className="mono" style={{ fontSize: 13 }}>
                      {r.dport}
                    </td>
                    <td>
                      <span className={levelBadge(r.level)}>{r.level}</span>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost"
                        style={{ padding: "6px 12px", fontSize: 12, color: "var(--brand)", borderColor: "var(--border)" }}
                        onClick={() => setSelectedForAI(r)}
                      >
                        <SparklesIcon /> Ask AI
                      </button>
                    </td>
                  </tr>
                ))}
                {combined.length === 0 && (
                  <tr>
                    <td colSpan="8" style={{ padding: 40, textAlign: "center", color: "var(--muted)" }}>
                      No events match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card" style={{ padding: 0, overflow: "hidden", height: "75vh", display: "flex", flexDirection: "column" }}>
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "var(--panel-2)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 8, height: 8, background: "var(--brand)", borderRadius: "50%" }} />
              <h3 style={{ margin: 0, fontSize: 16 }}>System Audit Log</h3>
            </div>
            <button className="btn icon-only" onClick={clearAudits} title="Clear audit log" style={{ width: 28, height: 28 }}>
              <TrashIcon />
            </button>
          </div>

          <div style={{ padding: "8px 16px", borderBottom: "1px solid var(--border)", background: "var(--panel)", display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)" }}>SEVERITY:</span>
              <select
                className="select"
                style={{ fontSize: 12, padding: "4px 8px", height: 28, width: 100 }}
                value={auditLevel}
                onChange={(e) => setAuditLevel(e.target.value)}
              >
                {levels.map((l) => (
                  <option key={l} value={l}>
                    {l}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)" }}>PROTOCOL:</span>
              <select
                className="select"
                style={{ fontSize: 12, padding: "4px 8px", height: 28, width: 100 }}
                value={auditProto}
                onChange={(e) => setAuditProto(e.target.value)}
              >
                {protocols.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ overflow: "auto", flex: 1 }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Proto</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filteredAudits.map((a, i) => (
                  <tr key={i}>
                    <td>
                      <span className={levelBadge(a.level || "Info")}>{a.level || "Info"}</span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{a.actor}</td>
                    <td>
                      <span style={{ color: "var(--brand)", fontWeight: 600 }}>{a.action}</span>
                    </td>
                    <td className="mono" style={{ fontSize: 13 }}>
                      {a.target}
                    </td>
                    <td className="mono" style={{ fontSize: 13, color: "var(--muted)" }}>
                      {a.proto || "System"}
                    </td>
                    <td className="mono" style={{ fontSize: 13, color: "var(--muted)" }}>
                      {new Date((a.at || 0) * 1000).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
                {filteredAudits.length === 0 && (
                  <tr>
                    <td colSpan="6" style={{ padding: 40, textAlign: "center", color: "var(--muted)" }}>
                      No audit activity recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
