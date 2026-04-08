import React from "react";
import useTrafficStream from "../hooks/useTrafficStream";
import { fetchAssets, createAsset, updateAsset } from "../api/assets";

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
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function isRFC1918(ip) {
  if (!ip) return false;
  const n = ip.split(".").map(Number);
  if (n.length !== 4 || n.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return false;
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

function normalizeTrustStatus(value) {
  const v = String(value || "unknown").toLowerCase();
  if (["trusted", "untrusted", "monitor", "unknown"].includes(v)) return v;
  return "unknown";
}

export default function Devices() {
  const clientKey = import.meta.env.VITE_CLIENT_KEY || "";

  const [running, setRunning] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [trustFilter, setTrustFilter] = React.useState("all");

  const traffic = useTrafficStream({
    maxRows: 4000,
    flushMs: 200,
    path: "traffic/stream",
    clientKey,
    enabled: running && !!clientKey,
    storageKey: "ic_diag_lastId",
  });

  const rows = React.useMemo(() => {
    return Array.isArray(traffic?.rows) ? traffic.rows : [];
  }, [traffic?.rows]);

  const connected = Boolean(traffic?.connected);

  const [assets, setAssets] = React.useState([]);
  const [assetMap, setAssetMap] = React.useState(new Map());
  const [assetsLoading, setAssetsLoading] = React.useState(true);
  const [assetsError, setAssetsError] = React.useState("");

  const loadAssets = React.useCallback(async () => {
    try {
      setAssetsLoading(true);
      setAssetsError("");
      const data = await fetchAssets();
      const items = Array.isArray(data?.items) ? data.items : [];
      setAssets(items);
      setAssetMap(new Map(items.map((item) => [item.ip_address, item])));
    } catch (err) {
      setAssetsError(String(err?.message || err));
    } finally {
      setAssetsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const lastEventMs = React.useMemo(() => {
    if (!rows.length) return 0;
    return eventTimeMs(rows[0]);
  }, [rows]);

  const stale = running && (!connected || (lastEventMs && Date.now() - lastEventMs > 30_000));

  const windowSec = 120;
  const windowRows = React.useMemo(() => {
    const cutoff = Date.now() - windowSec * 1000;
    return rows.filter((ev) => eventTimeMs(ev) >= cutoff);
  }, [rows]);

  const computed = React.useMemo(() => {
    const hosts = new Map();

    for (const ev of windowRows) {
      const src = ev?.src;
      const dst = ev?.dst;
      const dport = ev?.dport;

      for (const ip of [src, dst]) {
        if (!isRFC1918(ip)) continue;

        const cur = hosts.get(ip) || {
          ip,
          seen: 0,
          last: 0,
          topPeers: new Map(),
          topPorts: new Map(),
        };

        cur.seen += 1;
        cur.last = Math.max(cur.last, eventTimeMs(ev));

        const peer = ip === src ? dst : src;
        if (peer) cur.topPeers.set(peer, (cur.topPeers.get(peer) || 0) + 1);

        if (dport != null) {
          cur.topPorts.set(String(dport), (cur.topPorts.get(String(dport)) || 0) + 1);
        }

        hosts.set(ip, cur);
      }
    }

    const telemetryHosts = Array.from(hosts.values()).map((h) => {
      const tp = topNFromMap(h.topPeers, 1)[0];
      const tport = topNFromMap(h.topPorts, 1)[0];
      const asset = assetMap.get(h.ip);

      return {
        ...h,
        assetId: asset?.id ?? null,
        displayName: asset?.display_name || "",
        notes: asset?.notes || "",
        trustStatus: normalizeTrustStatus(asset?.trust_status),
        topPeer: tp ? `${tp.k} (${tp.v})` : "—",
        topPort: tport ? `${tport.k} (${tport.v})` : "—",
      };
    });

    const merged = new Map();

    for (const h of telemetryHosts) {
      merged.set(h.ip, h);
    }

    for (const asset of assets) {
      if (merged.has(asset.ip_address)) continue;

      merged.set(asset.ip_address, {
        ip: asset.ip_address,
        seen: 0,
        last: asset.last_seen ? new Date(asset.last_seen).getTime() : 0,
        topPeers: new Map(),
        topPorts: new Map(),
        assetId: asset.id,
        displayName: asset.display_name || "",
        notes: asset.notes || "",
        trustStatus: normalizeTrustStatus(asset.trust_status),
        topPeer: "—",
        topPort: "—",
      });
    }

    const hostList = Array.from(merged.values()).sort((a, b) => {
      const aScore = Math.max(a.seen || 0, a.last || 0);
      const bScore = Math.max(b.seen || 0, b.last || 0);
      return bScore - aScore;
    });

    return { hostList };
  }, [windowRows, assetMap, assets]);

  const filteredHosts = React.useMemo(() => {
    const q = search.trim().toLowerCase();

    return computed.hostList.filter((h) => {
      const matchesSearch =
        !q ||
        h.ip.toLowerCase().includes(q) ||
        (h.displayName || "").toLowerCase().includes(q) ||
        (h.notes || "").toLowerCase().includes(q);

      const matchesTrust =
        trustFilter === "all" ? true : normalizeTrustStatus(h.trustStatus) === trustFilter;

      return matchesSearch && matchesTrust;
    });
  }, [computed.hostList, search, trustFilter]);

  const summary = React.useMemo(() => {
    const total = computed.hostList.length;
    const activeRecently = computed.hostList.filter((h) => h.last && Date.now() - h.last <= 2 * 60 * 1000).length;
    const trusted = computed.hostList.filter((h) => normalizeTrustStatus(h.trustStatus) === "trusted").length;
    const needsReview = computed.hostList.filter((h) =>
      ["unknown", "monitor", "untrusted"].includes(normalizeTrustStatus(h.trustStatus))
    ).length;

    return { total, activeRecently, trusted, needsReview };
  }, [computed.hostList]);

  const [selectedIp, setSelectedIp] = React.useState(null);

  const selected = React.useMemo(() => {
    if (!selectedIp) return null;

    const recent = windowRows
      .filter((ev) => ev?.src === selectedIp || ev?.dst === selectedIp)
      .slice(0, 60);

    const peers = new Map();
    const ports = new Map();

    for (const ev of recent) {
      const peer = ev?.src === selectedIp ? ev?.dst : ev?.src;
      if (peer) peers.set(peer, (peers.get(peer) || 0) + 1);
      if (ev?.dport != null) ports.set(String(ev.dport), (ports.get(String(ev.dport)) || 0) + 1);
    }

    const host = computed.hostList.find((h) => h.ip === selectedIp);

    return {
      ip: selectedIp,
      host,
      recent,
      topPeers: topNFromMap(peers, 6),
      topPorts: topNFromMap(ports, 6),
    };
  }, [selectedIp, windowRows, computed.hostList]);

  const [editName, setEditName] = React.useState("");
  const [editNotes, setEditNotes] = React.useState("");
  const [editTrustStatus, setEditTrustStatus] = React.useState("unknown");
  const [savingAsset, setSavingAsset] = React.useState(false);

  React.useEffect(() => {
    if (!selected) return;
    setEditName(selected.host?.displayName || "");
    setEditNotes(selected.host?.notes || "");
    setEditTrustStatus(normalizeTrustStatus(selected.host?.trustStatus));
  }, [selected]);

  const saveSelectedAsset = async () => {
    if (!selected) return;

    try {
      setSavingAsset(true);
      const existing = assetMap.get(selected.ip);

      if (existing?.id) {
        await updateAsset(existing.id, {
          display_name: editName,
          notes: editNotes,
          trust_status: editTrustStatus,
        });
      } else {
        await createAsset({
          ip_address: selected.ip,
          display_name: editName,
          notes: editNotes,
          trust_status: editTrustStatus,
        });
      }

      await loadAssets();
    } catch (err) {
      alert(String(err?.message || err));
    } finally {
      setSavingAsset(false);
    }
  };

  const exportHostsCSV = () => {
    const hdr = "ip,display_name,trust_status,seen,last,notes,topPeer,topPort\n";
    const lines = filteredHosts.map((h) => {
      return [
        h.ip,
        h.displayName || "",
        h.trustStatus || "unknown",
        h.seen,
        h.last ? new Date(h.last).toISOString() : "",
        h.notes || "",
        h.topPeer,
        h.topPort,
      ]
        .map((x) => `"${String(x).replaceAll('"', '""')}"`)
        .join(",");
    });

    const blob = new Blob([hdr + lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `devices-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const trustBadgeStyle = (value) => {
    const v = normalizeTrustStatus(value);
    if (v === "trusted") return { background: "rgba(34,197,94,0.15)", color: "#86efac" };
    if (v === "untrusted") return { background: "rgba(239,68,68,0.15)", color: "#fca5a5" };
    if (v === "monitor") return { background: "rgba(245,158,11,0.15)", color: "#fcd34d" };
    return { background: "rgba(148,163,184,0.15)", color: "#cbd5e1" };
  };

  return (
    <div className="shell animate-fade" style={{ maxWidth: 1400 }}>
      <div
        className="card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: 999,
              background: running ? (connected ? "var(--success)" : "var(--warning)") : "var(--muted)",
              boxShadow: running ? "0 0 10px rgba(0,0,0,0.2)" : "none",
            }}
          />
          <div>
            <div style={{ fontWeight: 800, fontSize: 18 }}>Devices</div>
            <div className="helper">
              Manage known devices and view recent activity
              {running ? (connected ? " · Live stream" : " · Reconnecting…") : " · Paused"}
              {stale ? " · feed stale" : ""}
              {assetsLoading ? " · loading devices…" : ""}
              {assetsError ? ` · ${assetsError}` : ""}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" }}>
          <span className="chip">{summary.total} devices</span>
          {running ? (
            <button className="btn" onClick={() => setRunning(false)}>⏸ Pause</button>
          ) : (
            <button className="btn primary" onClick={() => setRunning(true)}>▶ Play</button>
          )}
          <button className="btn" onClick={loadAssets}>Refresh Devices</button>
          <button className="btn" onClick={exportHostsCSV}>Export CSV</button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 12,
          marginBottom: 16,
        }}
      >
        {[
          { label: "Total Devices", value: summary.total },
          { label: "Active Recently", value: summary.activeRecently },
          { label: "Trusted", value: summary.trusted },
          { label: "Needs Review", value: summary.needsReview },
        ].map((card) => (
          <div key={card.label} className="card" style={{ padding: 16 }}>
            <div className="helper" style={{ marginBottom: 8 }}>{card.label}</div>
            <div style={{ fontSize: 28, fontWeight: 800 }}>{card.value}</div>
          </div>
        ))}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(280px, 1.4fr) minmax(180px, 220px)",
            gap: 12,
          }}
        >
          <input
            className="input"
            value={search}
            placeholder="Search by IP, name, or notes"
            onChange={(e) => setSearch(e.target.value)}
          />

          <select
            className="input"
            value={trustFilter}
            onChange={(e) => setTrustFilter(e.target.value)}
          >
            <option value="all">All Trust States</option>
            <option value="trusted">Trusted</option>
            <option value="monitor">Monitor</option>
            <option value="unknown">Unknown</option>
            <option value="untrusted">Untrusted</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 10 }}>
          <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Device Inventory</h3>
          <span className="helper">Click a row for details</span>
        </div>

        <div style={{ overflow: "auto", maxHeight: 560 }}>
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 170 }}>IP</th>
                <th style={{ width: 220 }}>Name</th>
                <th style={{ width: 140 }}>Trust</th>
                <th style={{ width: 160 }}>Last Seen</th>
                <th style={{ width: 100 }}>Events</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {filteredHosts.map((h) => (
                <tr key={h.ip} style={{ cursor: "pointer" }} onClick={() => setSelectedIp(h.ip)}>
                  <td className="mono" style={{ fontWeight: 700 }}>{h.ip}</td>
                  <td>{h.displayName || <span className="helper">Unnamed device</span>}</td>
                  <td>
                    <span className="chip" style={trustBadgeStyle(h.trustStatus)}>
                      {normalizeTrustStatus(h.trustStatus)}
                    </span>
                  </td>
                  <td className="mono">
                    {h.last ? fmtAgo(h.last) : "—"}
                  </td>
                  <td className="mono">{h.seen}</td>
                  <td style={{ maxWidth: 360 }}>
                    <div
                      className="helper"
                      style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {h.notes || "—"}
                    </div>
                  </td>
                </tr>
              ))}

              {!filteredHosts.length && (
                <tr>
                  <td colSpan="6" className="helper">
                    No matching devices. Generate traffic or save a device record from the backend.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.45)",
            display: "flex",
            justifyContent: "flex-end",
            zIndex: 1000,
          }}
        >
          <div
            className="card"
            style={{
              width: 560,
              height: "100%",
              borderRadius: 0,
              overflow: "auto",
              padding: 18,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 18, fontWeight: 900 }}>
                  Device: <span className="mono">{selected.ip}</span>
                </div>
                <div className="helper">
                  Last seen: {selected.host?.last ? fmtAgo(selected.host.last) : "—"} · Events: {selected.host?.seen ?? 0}
                </div>
              </div>
              <button className="btn" onClick={() => setSelectedIp(null)}>✕</button>
            </div>

            <div style={{ marginTop: 16 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Device Name</div>
              <input
                className="input"
                value={editName}
                placeholder="e.g. Office PC, NAS, Laptop"
                onChange={(e) => setEditName(e.target.value)}
              />
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Trust Status</div>
              <select
                className="input"
                value={editTrustStatus}
                onChange={(e) => setEditTrustStatus(e.target.value)}
              >
                <option value="unknown">unknown</option>
                <option value="trusted">trusted</option>
                <option value="untrusted">untrusted</option>
                <option value="monitor">monitor</option>
              </select>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Notes</div>
              <textarea
                className="input"
                rows={4}
                value={editNotes}
                placeholder="Add context about this device"
                onChange={(e) => setEditNotes(e.target.value)}
              />
            </div>

            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button className="btn primary" onClick={saveSelectedAsset} disabled={savingAsset}>
                {savingAsset ? "Saving..." : "Save Device"}
              </button>
            </div>

            <div className="grid-halves" style={{ marginTop: 16 }}>
              <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Top Peers</div>
                <table className="table">
                  <tbody>
                    {selected.topPeers.map((x) => (
                      <tr key={x.k}>
                        <td className="mono">{x.k}</td>
                        <td className="mono" style={{ width: 80, textAlign: "right" }}>{x.v}</td>
                      </tr>
                    ))}
                    {!selected.topPeers.length && (
                      <tr>
                        <td className="helper">—</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Top Ports</div>
                <table className="table">
                  <tbody>
                    {selected.topPorts.map((x) => (
                      <tr key={x.k}>
                        <td className="mono">{x.k}</td>
                        <td className="mono" style={{ width: 80, textAlign: "right" }}>{x.v}</td>
                      </tr>
                    ))}
                    {!selected.topPorts.length && (
                      <tr>
                        <td className="helper">—</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div style={{ marginTop: 16 }}>
              <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>
                Recent Events (last {windowSec}s)
              </div>
              <div style={{ overflow: "auto", maxHeight: 420 }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Src</th>
                      <th>Dst</th>
                      <th>Proto</th>
                      <th>Port</th>
                    </tr>
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
                    {!selected.recent.length && (
                      <tr>
                        <td colSpan="5" className="helper">No recent events for this device.</td>
                      </tr>
                    )}
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