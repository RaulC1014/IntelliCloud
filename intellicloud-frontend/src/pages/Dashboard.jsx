import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { USE_MOCK, } from "../config";
import { agentStart, agentStop, agentStatus } from "../api/agent";
import { apiFetch, apiUrl } from "../api/http";
import { mapThreat } from "../adapters";
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
const alertStatuses = ["All", "open", "acknowledged", "closed"];

const levelBadge = (lvl) => {
  return "badge glass-panel";
};

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
      const res = await fetch(apiUrl("chat"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ context: contextOverride || selectedData, messages: newHistory }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.detail || "API Error");
      setMessages((prev) => [...prev, { role: "model", content: data.response }]);
    } catch (error) {
      console.error("AI agent request failed:", error);
      setMessages((prev) => [
        ...prev,
        { role: "model", content: "⚠️ Connection lost. Unable to reach neural core." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`ai-panel glass-panel ${selectedData ? "open" : ""}`} style={{ background: "rgba(11, 15, 23, 0.85)" }}>
      <div
        style={{
          padding: 24,
          borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "transparent",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div>
            <h3 className="gradient-text" style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>IntelliCloud Agent</h3>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: 1,
                fontWeight: 700,
                color: "rgba(255, 255, 255, 0.6)"
              }}
            >
              {selectedData ? `Target: ${selectedData.src}` : "Standby"}
            </div>
          </div>
        </div>
        <button className="btn-glass" onClick={onClose} style={{ padding: "10px", borderRadius: "50%" }}>
          ✕
        </button>
      </div>

      <div className="ai-content" ref={scrollRef} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {messages.map((msg, i) => (
          <div
            key={i}
            className="ai-message glass-panel animate-fade"
            style={{
              borderLeft: msg.role === "model" ? "3px solid rgba(255, 255, 255, 0.4)" : "3px solid rgba(255, 255, 255, 0.1)",
              background: msg.role === "user" ? "transparent" : "rgba(255, 255, 255, 0.02)",
              marginLeft: msg.role === "user" ? 20 : 0,
              marginRight: msg.role === "user" ? 0 : 20,
            }}
          >
            <div className="badge glass-panel" style={{ marginBottom: 12 }}>
              {msg.role === "user" ? "You" : "Analyst"}
            </div>
            <div style={{ whiteSpace: "pre-line", fontSize: 14, lineHeight: 1.6 }}>{msg.content}</div>
          </div>
        ))}

        {loading && (
          <div className="ai-message glass-panel" style={{ borderLeft: "3px solid rgba(255, 255, 255, 0.4)", background: "rgba(255, 255, 255, 0.02)" }}>
            <span className="typing-dot" style={{ background: "rgba(255, 255, 255, 0.6)" }}></span>
            <span className="typing-dot" style={{ background: "rgba(255, 255, 255, 0.6)", animationDelay: "0.2s" }}></span>
            <span className="typing-dot" style={{ background: "rgba(255, 255, 255, 0.6)", animationDelay: "0.4s" }}></span>
          </div>
        )}
      </div>

      <div style={{ padding: 16, borderTop: "1px solid rgba(255, 255, 255, 0.05)", background: "transparent" }}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend(input);
          }}
        >
          <input
            className="input glass-panel"
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
        const url = USE_MOCK ? "/mock/threats.json" : apiUrl("threats/public");
        const res = await fetch(url);

        if (!res.ok) {
          throw new Error(`Threat fetch failed with status ${res.status}`);
        }

        const data = await res.json();

        if (active) {
          setRaw((Array.isArray(data) ? data : data?.items ?? []).map(mapThreat));
        }
      } catch (error) {
        console.error("Threat fetch failed:", error);
        if (active) setRaw([]);
      }
    })();

    return () => {
      active = false;
    };
  }, []);

  return { raw };
}

function useRecentTraffic({ clientKey, limit = 200 }) {
  const [recentTraffic, setRecentTraffic] = useState([]);

  useEffect(() => {
    let active = true;

    (async () => {
      try {
        if (!clientKey) {
          if (active) setRecentTraffic([]);
          return;
        }

        const data = await apiFetch(`traffic/recent?client_key=${encodeURIComponent(clientKey)}&limit=${limit}`);
        const items = Array.isArray(data?.items) ? data.items : [];

        const normalized = items.map((ev, idx) => {
          const t = ev.event_ts
            ? Date.parse(ev.event_ts)
            : ev.created_at
              ? Date.parse(ev.created_at)
              : Date.now();

          return {
            type: "traffic",
            id: ev.id ?? `recent-${idx}`,
            timeMs: Number.isFinite(t) ? t : Date.now(),
            src: ev.src_ip || "",
            dst: ev.dst_ip || "",
            proto: ev.protocol || "",
            sport: ev.src_port,
            dport: ev.dst_port,
            level: ev.level || "Low",
            flow: ev.direction || "Recent",
            dns: ev.dns || "",
            reason: ev.reason || "",
            detectionType: ev.detection_type || "",
            src_zone: ev.src_zone,
            dst_zone: ev.dst_zone,
            network_scope: ev.network_scope,
            sensor_id: ev.sensor_id,
          };
        });

        if (active) setRecentTraffic(normalized);
      } catch (error) {
        console.error("Recent traffic fetch failed:", error);
        if (active) setRecentTraffic([]);
      }
    })();

    return () => {
      active = false;
    };
  }, [clientKey, limit]);

  return { recentTraffic };
}

function useAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(apiUrl("alerts"), {
        credentials: "include",
      });

      if (!res.ok) {
        throw new Error(`Alerts fetch failed with status ${res.status}`);
      }

      const data = await res.json();
      setAlerts(Array.isArray(data) ? data : data?.items ?? []);
    } catch (error) {
      console.error("Alerts fetch failed:", error);
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const updateStatus = useCallback(async (alertId, status) => {
    const res = await fetch(apiUrl(`alerts/${alertId}`), {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Alert update failed with status ${res.status}${text ? `: ${text}` : ""}`);
    }

    const data = await res.json();
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === alertId
          ? {
              ...a,
              status: data.status || status,
            }
          : a
      )
    );
    return data;
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { alerts, loading, refresh, updateStatus };
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

  const { raw: threats } = useThreats();
  const { alerts, loading: alertsLoading, refresh: refreshAlerts, updateStatus: updateAlertStatus } = useAlerts();

  const clientKey = import.meta.env.VITE_CLIENT_KEY || "";

  const { recentTraffic } = useRecentTraffic({ clientKey, limit: 200})

  const [agentRunning, setAgentRunning] = useState(false);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentChecked, setAgentChecked] = useState(false);

  const [streamPaused, setStreamPaused] = useState(false);

  useEffect(() => {
    let cancelled = false;
  
    const checkStatus = async () => {
      try {
        const data = await agentStatus();
        if (!cancelled) {
          setAgentRunning(data?.running === true);
          setAgentChecked(true);
        }
      } catch {
        if (!cancelled) setAgentChecked(true);
      }
    };
  
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const trafficEnabled = agentRunning && !streamPaused && !clientKey

  const trafficHook = useTrafficStream({
    maxRows: 2000,
    flushMs: 250,
    path: "traffic/stream",
    enabled: trafficEnabled,
    storageKey: "ic_lastTrafficId",
    clientKey,
  });

  const sseEvents = useMemo(() => {
    const rows = trafficHook?.rows ?? [];
    return rows.filter((ev) => {
      if (!ev) return false;
      if (ev.status) return false;
      return !!(
        ev.id ||
        ev.eid ||
        ev.src ||
        ev.src_ip ||
        ev.dst ||
        ev.dst_ip ||
        ev.proto ||
        ev.protocol ||
        ev.sport ||
        ev.src_port ||
        ev.dport ||
        ev.dst_port ||
        ev.ts ||
        ev.event_ts ||
        ev.created_at
      );
    });
  }, [trafficHook?.rows]);

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
      const id =
        ev?.eid ||
        ev?.id ||
        `${ev?.ts ?? ""}-${ev?.event_ts ?? ""}-${ev?.created_at ?? ""}-${ev?.src ?? ev?.src_ip ?? ""}-${ev?.dst ?? ev?.dst_ip ?? ""}-${ev?.sport ?? ev?.src_port ?? ""}-${ev?.dport ?? ev?.dst_port ?? ""}`;

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

  const [alertStatusFilter, setAlertStatusFilter] = useState("All");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("All");
  const [alertDetectionFilter, setAlertDetectionFilter] = useState("");

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

  const toggleAgent = async () => {
    setAgentLoading(true);
    try {
      if (agentRunning) {
        await agentStop();
        setAgentRunning(false);
        setStreamPaused(false);
      } else {
        await agentStart()
        setAgentRunning(true);
        setStreamPaused(false);
      }
    } catch (e) {
      console.error("Agent toggle failed:", e);
      alert(`Agent control failed: ${e?.message || e}`);
    } finally {
      setAgentLoading(false);
    }
  }

  const toggleStreamPause = () => setStreamPaused(p => !p);

  const combined = useMemo(() => {
    const ipq = ipFilter.trim();
    const lvlq = levelFilter || "All";

    const rowsFromThreats = threats.map((t, idx) => ({
      type: "threat",
      id: t.id ?? `threat-${idx}-${t.ip ?? "no-ip"}-${t.detectedAt ?? "no-time"}`,
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
      reason: t.reason || "",
      detectionType: t.detectionType || "",
    }));

    const rowsFromSSE = sseEvents.map((ev, idx) => {
      const t = ev.event_ts
        ? Date.parse(ev.event_ts)
        : ev.created_at
          ? Date.parse(ev.created_at)
          : ev.ts
            ? Math.floor(ev.ts * 1000)
            : Date.now();

      return {
        type: "traffic",
        id:
          ev.id ??
          ev.eid ??
          `${ev.ts ?? ev.event_ts ?? ev.created_at ?? "no-ts"}-${ev.src ?? ev.src_ip ?? "no-src"}-${ev.dst ?? ev.dst_ip ?? "no-dst"}-${ev.proto ?? ev.protocol ?? "no-proto"}-${ev.sport ?? ev.src_port ?? "no-sport"}-${ev.dport ?? ev.dst_port ?? "no-dport"}-${idx}`,
        timeMs: Number.isFinite(t) ? t : Date.now(),
        src: ev.src || ev.src_ip || "",
        dst: ev.dst || ev.dst_ip || "",
        proto: ev.proto || ev.protocol || "",
        sport: ev.sport ?? ev.src_port,
        dport: ev.dport ?? ev.dst_port,
        level: ev.level || "Low",
        flow: ev.dir || ev.direction || "Live",
        dns: ev.dns || ev.dns_qname || "",
        reason: ev.reason || ev.info || "",
        detectionType: ev.detection_type || "",
        src_cc: ev.src_cc,
        src_city: ev.src_city,
        src_asnorg: ev.src_asnorg,
        dst_cc: ev.dst_cc,
        dst_city: ev.dst_city,
        dst_asnorg: ev.dst_asnorg,
      };
    });

    let rows = [...rowsFromThreats, ...recentTraffic, ...rowsFromSSE]
      .filter((r) => (ipq ? r.src?.includes(ipq) || r.dst?.includes(ipq) : true))
      .filter((r) => (lvlq === "All" ? true : r.level === lvlq))
      .filter((r) => (sinceTs ? r.timeMs >= sinceTs : true))
      .sort((a, b) => b.timeMs - a.timeMs);

    if (limit && limit > 0) rows = rows.slice(0, limit);
    return rows;
  }, [threats, recentTraffic, sseEvents, ipFilter, levelFilter, sinceTs, limit]);


  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (alertStatusFilter !== "All" && (a.status || "open") !== alertStatusFilter) return false;
      if (alertSeverityFilter !== "All" && (a.severity || "Low") !== alertSeverityFilter) return false;
      if (alertDetectionFilter.trim()) {
        const q = alertDetectionFilter.trim().toLowerCase();
        if (!String(a.detection_type || "").toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [alerts, alertStatusFilter, alertSeverityFilter, alertDetectionFilter]);

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

  const handleAlertUpdate = async (alertId, status) => {
    try {
      await updateAlertStatus(alertId, status);
    } catch (error) {
      console.error("Alert update failed:", error);
      alert(`Alert update failed: ${error?.message || error}`);
    }
  };

  return (
    <div className="shell dashboard animate-fade" style={{ maxWidth: 1600 }}>
  
      {/* AI analysis side panel — slides in when a row is clicked */}
      <AIAgentPanel selectedData={selectedForAI} onClose={() => setSelectedForAI(null)} />
  
      {/* ── Top toolbar — filters and action buttons ── */}
      <div
        className="card glass-panel hover-card animate-slide"
        style={{
          marginBottom: 20,
          display: "flex",
          flexWrap: "wrap",
          gap: 16,
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        {/* Left side — IP filter, severity filter, row count */}
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ position: "relative" }}>
            <div style={{ position: "absolute", left: 10, top: 10, color: "var(--muted)" }}>
              <FilterIcon />
            </div>
            <input
              className="input glass-panel"
              placeholder="Filter IP Address..."
              style={{ paddingLeft: 34, width: 220 }}
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
            />
          </div>
  
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "var(--muted)", letterSpacing: 0.5 }}>SEVERITY:</span>
            <select className="select glass-panel" style={{ width: 140 }} value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)}>
              {levels.filter((l) => l !== "Info").map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
  
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "var(--muted)", letterSpacing: 0.5 }}>ROWS:</span>
            <select className="select glass-panel" style={{ width: 140 }} value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value="50">50 Rows</option>
              <option value="100">100 Rows</option>
              <option value="200">200 Rows</option>
              <option value="0">All Rows</option>
            </select>
          </div>
  
          {/* Only shows when a filter is active */}
          {(ipFilter || levelFilter !== "All") && (
            <button className="btn-glass" onClick={() => { setIpFilter(""); setLevelFilter("All"); }}>
              Reset Filters
            </button>
          )}
        </div>
  
        {/* Right side — view management buttons */}
        <div style={{ display: "flex", gap: 8 }}>
          {/* Soft clear — filters out events older than now using sinceTs */}
          <button className="btn-glass" onClick={handleClearTraffic} title="Clear current view">
            <TrashIcon /> Clear
          </button>
  
          {/* Reloads all stored history from the database */}
          <button className="btn-glass" onClick={handleReloadTraffic} title="Show all history">
            <RefreshIcon /> Reload
          </button>
  
          {/* Hard reset — wipes display, resets event counter and SSE cursor */}
          <button className="btn-glass" onClick={handleResetCursor} title="Hard reset — clears display, resets event counter and stream cursor">
            ↺ Reset
          </button>
  
          {/* Downloads the current filtered table as a CSV file */}
          <button className="btn-glass" onClick={downloadCSV}>
            <DownloadIcon /> Export CSV
          </button>
        </div>
      </div>
  
      <div className="grid-halves animate-slide animate-delay-1" style={{ alignItems: "start" }}>
  
        {/* ── Live Traffic Feed card ── */}
        <div className="card glass-panel" style={{ padding: 0, overflow: "hidden", height: "75vh", display: "flex", flexDirection: "column" }}>
  
          {/* Card header — SSE status on left, agent controls on right */}
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "transparent",
            }}
          >
            {/* Left — connection dot, title, live/paused badge, running event count */}
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
  
              {/* Green when SSE stream is connected, grey when paused or disconnected */}
              <div
                style={{
                  width: 8,
                  height: 8,
                  background: trafficEnabled ? "var(--success)" : "var(--muted)",
                  borderRadius: "50%",
                  boxShadow: trafficEnabled ? "0 0 8px var(--success)" : "none",
                }}
              />
              <h3 className="gradient-text" style={{ margin: 0, fontSize: 16 }}>Live Traffic Feed</h3>
  
              {/* Reflects SSE connection state — Live, Reconnecting, or Paused */}
              <span className="badge glass-panel" style={{ marginLeft: 10 }}>
                {trafficEnabled ? (trafficConnected ? "Live" : "Reconnecting…") : "Paused"}
                {trafficLastId != null ? ` · lastId=${trafficLastId}` : ""}
              </span>
  
              {/* Running total of unique events seen this session */}
              {agentRunning && totalEvents > 0 && (
                <span style={{
                  fontSize: 12,
                  color: "var(--text-2)",
                  fontFamily: "monospace",
                  fontWeight: 600,
                  marginLeft: 6,
                }}>
                  {totalEvents.toLocaleString()} events
                </span>
              )}
            </div>
  
            {/* Right — start/stop the capture agent, pause/resume the display */}
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
  
              {/* Controls the actual ic_agent.py process running on the backend.
                  Shows Checking on load, then Start Agent / Stop Agent */}
              <button
                className="btn-glass"
                onClick={toggleAgent}
                disabled={agentLoading || !agentChecked}
              >
                {!agentChecked
                  ? "Checking..."
                  : agentLoading
                  ? "..."
                  : agentRunning
                  ? "⏹ Stop Agent"
                  : "▶ Start Agent"}
              </button>
  
              {/* Only visible while agent is running.
                  Pauses the frontend display — agent keeps capturing in the background */}
              {agentRunning && (
                <button
                  className="btn-glass"
                  onClick={toggleStreamPause}
                  title={streamPaused ? "Resume live display" : "Pause live display (agent keeps capturing)"}
                >
                  {streamPaused ? "▶ Resume Display" : "⏸ Pause Display"}
                </button>
              )}
  
            </div>
          </div>
  
          {/* Pause banner — sits between header and table when display is paused */}
          {streamPaused && agentRunning && (
            <div style={{
              padding: "6px 20px",
              background: "rgba(234,179,8,0.05)",
              borderBottom: "1px solid rgba(234,179,8,0.2)",
              color: "rgba(255, 255, 255, 0.7)",
              fontSize: 12,
              fontWeight: 600,
            }}>
              ⏸ Display paused — agent is still capturing in the background
            </div>
          )}
  
          {/* Scrollable packet table */}
          <div style={{ overflow: "auto", flex: 1 }}>
            <table className="table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th className="col-time" style={{ background: "transparent" }}>Time</th>
                  <th style={{ background: "transparent" }}>Type</th>
                  <th className="col-src" style={{ background: "transparent" }}>Source</th>
                  <th className="col-dst" style={{ background: "transparent" }}>Destination</th>
                  <th className="col-proto" style={{ background: "transparent" }}>Proto</th>
                  <th className="col-ports" style={{ background: "transparent" }}>Port</th>
                  <th className="col-level" style={{ background: "transparent" }}>Severity</th>
                  <th style={{ background: "transparent" }}>Reason</th>
                  <th style={{ textAlign: "right", background: "transparent" }}>Analysis</th>
                </tr>
              </thead>
              <tbody>
                {combined.map((r, idx) => (
                  <tr
                    key={`${r.type}-${r.id ?? `${r.timeMs ?? "no-time"}-${r.src ?? "no-src"}-${r.dst ?? "no-dst"}-${r.proto ?? "no-proto"}-${r.sport ?? "no-sport"}-${r.dport ?? "no-dport"}-${idx}`}`}
                    style={{ cursor: "default" }}
                  >
                    <td className="mono" style={{ color: "var(--muted)", fontSize: 13 }}>
                      {new Date(r.timeMs).toLocaleTimeString()}
                    </td>
                    <td>
                      <span className="badge glass-panel" style={{ fontSize: 11, padding: "2px 8px", height: "auto" }}>
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
                    <td className="mono" style={{ fontSize: 13 }}>{r.proto}</td>
                    <td className="mono" style={{ fontSize: 13 }}>{r.dport}</td>
                    <td>
                      <span className={levelBadge(r.level)}>{r.level}</span>
                    </td>
                    <td style={{ fontSize: 13, color: "var(--muted)", maxWidth: 260 }}>
                      {r.reason || "—"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {/* Opens the AI analysis side panel for this specific event */}
                      <button
                        className="btn-glass"
                        onClick={() => setSelectedForAI(r)}
                      >
                        <SparklesIcon /> Ask AI
                      </button>
                    </td>
                  </tr>
                ))}
                {combined.length === 0 && (
                  <tr>
                    <td colSpan="9" style={{ padding: 40, textAlign: "center", color: "var(--muted)" }}>
                      No events match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
  
        {/* ── Alerts card ── */}
        <div className="card glass-panel hover-card animate-slide animate-delay-1" style={{ padding: 0, overflow: "hidden", marginTop: 20 }}>
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "transparent",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 8, height: 8, background: "rgba(255, 255, 255, 0.6)", borderRadius: "50%" }} />
              <h3 className="gradient-text" style={{ margin: 0, fontSize: 16 }}>Alerts</h3>
              <span className="badge glass-panel">{alertsLoading ? "Loading…" : `${filteredAlerts.length} visible`}</span>
            </div>
  
            {/* Manually re-fetches alerts from the backend */}
            <button className="btn-glass" onClick={refreshAlerts}>
              <RefreshIcon /> Refresh Alerts
            </button>
          </div>
  
          {/* Alert filter bar — status, severity, and detection type */}
          <div
            style={{
              padding: "8px 16px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
              background: "rgba(255, 255, 255, 0.02)",
              display: "flex",
              gap: 12,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)" }}>STATUS:</span>
              <select
                className="select glass-panel"
                style={{ fontSize: 12, padding: "4px 8px", height: 28, width: 130 }}
                value={alertStatusFilter}
                onChange={(e) => setAlertStatusFilter(e.target.value)}
              >
                {alertStatuses.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
  
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)" }}>SEVERITY:</span>
              <select
                className="select glass-panel"
                style={{ fontSize: 12, padding: "4px 8px", height: 28, width: 130 }}
                value={alertSeverityFilter}
                onChange={(e) => setAlertSeverityFilter(e.target.value)}
              >
                {levels.filter((l) => l !== "Info").map((l) => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
            </div>
  
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)" }}>TYPE:</span>
              <input
                className="input glass-panel"
                style={{ height: 28, fontSize: 12, width: 220 }}
                placeholder="Filter detection type..."
                value={alertDetectionFilter}
                onChange={(e) => setAlertDetectionFilter(e.target.value)}
              />
            </div>
          </div>
  
          {/* Scrollable alerts table */}
          <div style={{ overflow: "auto", maxHeight: "45vh" }}>
            <table className="table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th style={{ background: "transparent" }}>Created</th>
                  <th style={{ background: "transparent" }}>Status</th>
                  <th style={{ background: "transparent" }}>Severity</th>
                  <th style={{ background: "transparent" }}>Detection</th>
                  <th style={{ background: "transparent" }}>Reason</th>
                  <th style={{ background: "transparent" }}>Source</th>
                  <th style={{ background: "transparent" }}>Destination</th>
                  <th style={{ background: "transparent" }}>Proto</th>
                  <th style={{ background: "transparent" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((a, idx) => (
                  <tr key={`${a.id ?? "no-id"}-${idx}`}>
                    <td className="mono" style={{ fontSize: 13, color: "var(--muted)" }}>
                      {a.created_at ? new Date(a.created_at).toLocaleString() : "—"}
                    </td>
                    <td>
                      <span className="badge glass-panel" style={{ fontSize: 11, padding: "2px 8px", height: "auto" }}>
                        {a.status || "open"}
                      </span>
                    </td>
                    <td>
                      <span className={levelBadge(a.severity || "Low")}>{a.severity || "Low"}</span>
                    </td>
                    <td className="mono" style={{ fontSize: 13 }}>{a.detection_type || "—"}</td>
                    <td style={{ fontSize: 13, color: "var(--muted)", maxWidth: 320 }}>{a.reason || "—"}</td>
                    <td className="mono" style={{ fontSize: 13 }}>{a.src_ip || "—"}</td>
                    <td className="mono" style={{ fontSize: 13 }}>
                      {a.dst_ip || "—"}
                      {(a.dst_port ?? a.src_port) != null && (
                        <div style={{ color: "var(--muted)" }}>:{a.dst_port ?? a.src_port}</div>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 13 }}>{a.protocol || "—"}</td>
                    <td>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {/* Marks alert as acknowledged — disables once already acknowledged */}
                        <button
                          className="btn-glass"
                          disabled={(a.status || "open") === "acknowledged"}
                          onClick={() => handleAlertUpdate(a.id, "acknowledged")}
                        >
                          Acknowledge
                        </button>
                        {/* Closes the alert — disables once already closed */}
                        <button
                          className="btn-glass"
                          disabled={(a.status || "open") === "closed"}
                          onClick={() => handleAlertUpdate(a.id, "closed")}
                        >
                          Close
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredAlerts.length === 0 && (
                  <tr>
                    <td colSpan="9" style={{ padding: 40, textAlign: "center", color: "var(--muted)" }}>
                      No alerts match your filters.
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