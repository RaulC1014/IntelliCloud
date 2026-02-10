import React from "react";
import useTrafficStream from "../hooks/useTrafficStream";
import { API_BASE_URL } from "../config";



function eventTimeMs(ev) {
  return ev?.ts ? ev.ts * 1000 : (ev?.timeMs ?? Date.now());
}

function fmtAgo(ms) {
  if (!ms) return "—";
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

function isRFC1918(ip) {
  if (!ip) return false;
  const n = ip.split(".").map(Number);
  if (n.length !== 4 || n.some(x => Number.isNaN(x) || x < 0 || x > 255)) return false;
  if (n[0] === 10) return true;
  if (n[0] === 172 && n[1] >= 16 && n[1] <= 31) return true;
  if (n[0] === 192 && n[1] === 168) return true;
  return false;
}

function topNFromMap(map, n = 5) {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => ({ k, v }));
}

/** ---------- local aliases ---------- **/

function useAliases(storageKey = "ic-device-aliases") {
  const [aliases, setAliases] = React.useState(() => {
    try {
      return new Map(Object.entries(JSON.parse(localStorage.getItem(storageKey) || "{}")));
    } catch {
      return new Map();
    }
  });

  const save = React.useCallback((ip, name) => {
    const next = new Map(aliases);
    if (!name || !name.trim()) next.delete(ip);
    else next.set(ip, name.trim());
    setAliases(next);
    localStorage.setItem(storageKey, JSON.stringify(Object.fromEntries(next)));
  }, [aliases, storageKey]);

  return { aliases, save };
}



function useThroughput(rows, windowSec = 60) {
  const [series, setSeries] = React.useState([]);

  React.useEffect(() => {
    const now = Date.now();
    const cutoff = now - windowSec * 1000;

    const windowRows = (rows || []).filter(ev => eventTimeMs(ev) >= cutoff);

    const buckets = new Map();
    for (const ev of windowRows) {
      const t = Math.floor(eventTimeMs(ev) / 1000) * 1000;
      buckets.set(t, (buckets.get(t) || 0) + 1);
    }

    const sorted = Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([t, count]) => ({ t, pps: count }));

    setSeries(sorted);
  }, [rows, windowSec]);

  const pps = series.length ? series[series.length - 1].pps : 0;
  const peak = series.reduce((m, x) => Math.max(m, x.pps), 0);
  const avg = series.length ? Math.round(series.reduce((s, x) => s + x.pps, 0) / series.length) : 0;

  return { series, pps, peak, avg };
}

function Sparkline({ data, height = 48 }) {
  if (!data?.length) return <div style={{ height }} className="helper">No traffic yet</div>;
  const minT = data[0].t;
  const maxT = data[data.length - 1].t || (minT + 1);
  const maxY = Math.max(1, ...data.map(d => d.pps));
  const pts = data.map(d => {
    const x = ((d.t - minT) / (maxT - minT || 1)) * 100;
    const y = (1 - d.pps / maxY) * 100;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height }}>
      <polyline fill="none" stroke="currentColor" strokeWidth="1.5" points={pts} />
    </svg>
  );
}



export default function Diagnostics() {

  const clientKey = import.meta.env.VITE_CLIENT_KEY || "";
  
  const [running, setRunning] = React.useState(true);

  const traffic = useTrafficStream({
    maxRows: 4000,
    flushMs: 200,
    path: "/api/traffic/stream",
    clientKey,
    enabled: running && !!clientKey,
    storageKey: "ic_diag_lastId",
  });
  const rows = Array.isArray(traffic?.rows) ? traffic.rows : [];
  const connected = Boolean(traffic?.connected);

  // last event time (for "stale feed" detection)
  const lastEventMs = React.useMemo(() => {
    if (!rows.length) return 0;
    return eventTimeMs(rows[0]);
  }, [rows]);

  const stale = running && (!connected || (lastEventMs && (Date.now() - lastEventMs > 30_000)));

  const { series, pps, peak, avg } = useThroughput(rows, 60);

  // Build host stats + insight widgets from last N seconds for "live feel"
  const windowSec = 120;
  const windowRows = React.useMemo(() => {
    const cutoff = Date.now() - windowSec * 1000;
    return rows.filter(ev => eventTimeMs(ev) >= cutoff);
  }, [rows]);

  const computed = React.useMemo(() => {
    const hosts = new Map();                 // internal ip -> stats
    const topTalkers = new Map();            // internal src -> count
    const topDestinations = new Map();       // external dst -> count
    const topPorts = new Map();              // dport -> count

    for (const ev of windowRows) {
      const src = ev?.src;
      const dst = ev?.dst;
      const dport = ev?.dport;

      // talkers/dests/ports
      if (isRFC1918(src)) topTalkers.set(src, (topTalkers.get(src) || 0) + 1);
      if (dst && !isRFC1918(dst)) topDestinations.set(dst, (topDestinations.get(dst) || 0) + 1);
      if (dport != null) topPorts.set(String(dport), (topPorts.get(String(dport)) || 0) + 1);

      // host aggregation (for internal endpoints observed anywhere)
      for (const ip of [src, dst]) {
        if (!isRFC1918(ip)) continue;
        const cur = hosts.get(ip) || {
          ip,
          seen: 0,
          last: 0,
          topPeers: new Map(),
          topPorts: new Map()
        };
        cur.seen += 1;
        cur.last = Math.max(cur.last, eventTimeMs(ev));

        // peers: if this host is src, peer is dst; if host is dst, peer is src
        const peer = (ip === src) ? dst : src;
        if (peer) cur.topPeers.set(peer, (cur.topPeers.get(peer) || 0) + 1);

        // ports: consider destination port as the "service" in use
        if (dport != null) cur.topPorts.set(String(dport), (cur.topPorts.get(String(dport)) || 0) + 1);

        hosts.set(ip, cur);
      }
    }

    const hostList = Array.from(hosts.values())
      .map(h => {
        const tp = topNFromMap(h.topPeers, 1)[0];
        const tport = topNFromMap(h.topPorts, 1)[0];
        return {
          ...h,
          topPeer: tp ? `${tp.k} (${tp.v})` : "—",
          topPort: tport ? `${tport.k} (${tport.v})` : "—"
        };
      })
      .sort((a, b) => b.seen - a.seen);

    return {
      hostList,
      topTalkers: topNFromMap(topTalkers, 6),
      topDestinations: topNFromMap(topDestinations, 6),
      topPorts: topNFromMap(topPorts, 6)
    };
  }, [windowRows]);

  const { aliases, save } = useAliases();

  // “device drawer”
  const [selectedIp, setSelectedIp] = React.useState(null);
  const selected = React.useMemo(() => {
    if (!selectedIp) return null;
    const recent = windowRows
      .filter(ev => ev?.src === selectedIp || ev?.dst === selectedIp)
      .slice(0, 60);

    const peers = new Map();
    const ports = new Map();
    for (const ev of recent) {
      const peer = (ev?.src === selectedIp) ? ev?.dst : ev?.src;
      if (peer) peers.set(peer, (peers.get(peer) || 0) + 1);
      if (ev?.dport != null) ports.set(String(ev.dport), (ports.get(String(ev.dport)) || 0) + 1);
    }

    const host = computed.hostList.find(h => h.ip === selectedIp);
    return {
      ip: selectedIp,
      host,
      recent,
      topPeers: topNFromMap(peers, 6),
      topPorts: topNFromMap(ports, 6)
    };
  }, [selectedIp, windowRows, computed.hostList]);

  // basic connectivity checks (kept simple)
  const [checks, setChecks] = React.useState([]);
  const runChecks = async () => {
    const apiBase = (API_BASE_URL || "").replace(/\/+$/, "") || "http://localhost:5000";
    const sites = [
      { name: "API", url: apiBase },
      { name: "Cloudflare", url: "https://1.1.1.1" },
      { name: "Google", url: "https://www.google.com/generate_204" },
    ];

    const results = [];
    for (const s of sites) {
      const t0 = performance.now();
      try {
        // mode:no-cors means you cannot trust status codes; treat "no throw" as reachability.
        await fetch(s.url, { method: "HEAD", mode: "no-cors" });
        results.push({ name: s.name, rtt: Math.round(performance.now() - t0), ok: true });
      } catch (e) {
        results.push({ name: s.name, rtt: null, ok: false, err: String(e?.message || e) });
      }
    }
    setChecks(results);
  };

  const exportHostsCSV = () => {
    const hdr = "ip,alias,seen,last,topPeer,topPort\n";
    const lines = computed.hostList.map(h => {
      const alias = aliases.get(h.ip) || "";
      return [
        h.ip,
        alias,
        h.seen,
        new Date(h.last).toISOString(),
        h.topPeer,
        h.topPort
      ].map(x => `"${String(x).replaceAll('"', '""')}"`).join(",");
    });

    const blob = new Blob([hdr + lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hosts-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="shell animate-fade" style={{ maxWidth: 1400 }}>

      {/* OVERVIEW / FEED HEALTH */}
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 10, height: 10, borderRadius: 999,
              background: running ? (connected ? "var(--success)" : "var(--warning)") : "var(--muted)",
              boxShadow: running ? "0 0 10px rgba(0,0,0,0.2)" : "none"
            }}
          />
          <div>
            <div style={{ fontWeight: 800, fontSize: 16 }}>Diagnostics</div>
            <div className="helper">
              {running ? (connected ? "Live stream" : "Reconnecting…") : "Paused"} · Last event: {lastEventMs ? fmtAgo(lastEventMs) : "—"}
              {stale ? " · ⚠ feed stale" : ""}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" }}>
          <span className="chip">Now: {pps} eps · Avg: {avg} · Peak: {peak}</span>
          <span className="chip">{computed.hostList.length} observed hosts</span>

          {running ? (
            <button className="btn" onClick={() => setRunning(false)}>⏸ Pause</button>
          ) : (
            <button className="btn primary" onClick={() => setRunning(true)}>▶ Play</button>
          )}

          <button className="btn" onClick={runChecks}>Run Checks</button>
          <button className="btn" onClick={exportHostsCSV}>Export CSV</button>
        </div>
      </div>

      {/* TOP INSIGHTS */}
      <div className="grid-halves" style={{ alignItems: "stretch", marginBottom: 16 }}>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Throughput (events/sec, last 60s)</h3>
            <div className="chip">Now: {pps} · Avg: {avg} · Peak: {peak}</div>
          </div>
          <div style={{ color: "var(--brand)", marginTop: 8 }}>
            <Sparkline data={series} height={56} />
          </div>
        </div>

        <div className="card">
          <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Network Health</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginTop: 10 }}>
            {checks.map((c, i) => (
              <div key={i} className="home-kpi">
                <div className="stat-num" style={{ color: c.ok ? "var(--success)" : "var(--danger)" }}>
                  {c.ok ? `${c.rtt} ms` : "Fail"}
                </div>
                <div className="stat-label">{c.name}</div>
              </div>
            ))}
            {!checks.length && (
              <div style={{ gridColumn: "1 / -1" }} className="helper">
                Click “Run Checks” to measure reachability (rough RTT) to a few endpoints.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid-halves" style={{ alignItems: "stretch", marginBottom: 16 }}>
        <div className="card">
          <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Talkers (internal src, last {windowSec}s)</h3>
          <table className="table">
            <thead><tr><th>IP</th><th style={{ width: 120 }}>Events</th></tr></thead>
            <tbody>
              {computed.topTalkers.map((x) => (
                <tr key={x.k}><td className="mono">{x.k}</td><td className="mono">{x.v}</td></tr>
              ))}
              {!computed.topTalkers.length && <tr><td colSpan="2" className="helper">No data yet.</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Destinations (external dst, last {windowSec}s)</h3>
          <table className="table">
            <thead><tr><th>IP</th><th style={{ width: 120 }}>Events</th></tr></thead>
            <tbody>
              {computed.topDestinations.map((x) => (
                <tr key={x.k}><td className="mono">{x.k}</td><td className="mono">{x.v}</td></tr>
              ))}
              {!computed.topDestinations.length && <tr><td colSpan="2" className="helper">No data yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {/* HOSTS TABLE */}
      <div className="card" style={{ overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 10 }}>
          <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Observed Hosts (internal, telemetry-derived)</h3>
          <span className="helper">Click a row for details</span>
        </div>

        <div style={{ overflow: "auto", maxHeight: 520 }}>
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 260 }}>Host</th>
                <th style={{ width: 120 }}>Events</th>
                <th style={{ width: 170 }}>Last Seen</th>
                <th style={{ width: 220 }}>Top Peer</th>
                <th style={{ width: 160 }}>Top Port</th>
              </tr>
            </thead>
            <tbody>
              {computed.hostList.map(h => (
                <tr key={h.ip} style={{ cursor: "pointer" }} onClick={() => setSelectedIp(h.ip)}>
                  <td>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span className="mono" style={{ fontWeight: 700 }}>{h.ip}</span>
                        {aliases.get(h.ip) ? <span className="chip">{aliases.get(h.ip)}</span> : null}
                      </div>
                      <div className="helper">{aliases.get(h.ip) ? "Renamed locally" : "—"}</div>
                    </div>
                  </td>
                  <td className="mono">{h.seen}</td>
                  <td className="mono">{new Date(h.last).toLocaleString()}</td>
                  <td className="mono" style={{ fontSize: 13 }}>{h.topPeer}</td>
                  <td className="mono" style={{ fontSize: 13 }}>{h.topPort}</td>
                </tr>
              ))}
              {!computed.hostList.length && (
                <tr>
                  <td colSpan="5" className="helper">
                    No internal hosts observed yet. Generate traffic (browse, ping, curl) and keep this tab open.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* DEVICE DRAWER */}
      {selected && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)",
          display: "flex", justifyContent: "flex-end", zIndex: 1000
        }}>
          <div className="card" style={{
            width: 520, height: "100%", borderRadius: 0,
            overflow: "auto", padding: 18
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 16, fontWeight: 900 }}>Host: <span className="mono">{selected.ip}</span></div>
                <div className="helper">
                  Last seen: {selected.host?.last ? fmtAgo(selected.host.last) : "—"} · Events: {selected.host?.seen ?? 0}
                </div>
              </div>
              <button className="btn" onClick={() => setSelectedIp(null)}>✕</button>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Nickname</div>
              <input
                className="input"
                value={aliases.get(selected.ip) || ""}
                placeholder="e.g. Office PC, NAS, Laptop"
                onChange={(e) => save(selected.ip, e.target.value)}
              />
            </div>

            <div className="grid-halves" style={{ marginTop: 14 }}>
              <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Top Peers</div>
                <table className="table">
                  <tbody>
                    {selected.topPeers.map(x => (
                      <tr key={x.k}>
                        <td className="mono">{x.k}</td>
                        <td className="mono" style={{ width: 80, textAlign: "right" }}>{x.v}</td>
                      </tr>
                    ))}
                    {!selected.topPeers.length && <tr><td className="helper">—</td></tr>}
                  </tbody>
                </table>
              </div>

              <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Top Ports</div>
                <table className="table">
                  <tbody>
                    {selected.topPorts.map(x => (
                      <tr key={x.k}>
                        <td className="mono">{x.k}</td>
                        <td className="mono" style={{ width: 80, textAlign: "right" }}>{x.v}</td>
                      </tr>
                    ))}
                    {!selected.topPorts.length && <tr><td className="helper">—</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Recent Events (last {windowSec}s)</div>
              <div style={{ overflow: "auto", maxHeight: 420 }}>
                <table className="table">
                  <thead>
                    <tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th></tr>
                  </thead>
                  <tbody>
                    {selected.recent.map((ev, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontSize: 12, color: "var(--muted)" }}>
                          {new Date(eventTimeMs(ev)).toLocaleTimeString()}
                        </td>
                        <td className="mono" style={{ fontSize: 12 }}>{ev?.src}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{ev?.dst}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{ev?.proto || "—"}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{ev?.dport ?? "—"}</td>
                      </tr>
                    ))}
                    {!selected.recent.length && <tr><td colSpan="5" className="helper">No recent events for this host.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}