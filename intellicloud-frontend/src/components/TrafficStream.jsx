import { useMemo, useState } from "react";
import { useTrafficStream } from "../hooks/useTrafficStream";

function fmtTs(ts) {
  const n = Number(ts);
  if (!Number.isFinite(n)) return "";
  const d = new Date(n * 1000);
  return Number.isFinite(d.getTime()) ? d.toLocaleTimeString() : "";
}

export default function TrafficStream() {
  const [paused, setPaused] = useState(false);
  const [rate, setRate] = useState(50); // packets/sec displayed
  const [dir, setDir] = useState("all");
  const [q, setQ] = useState("");

  const { rows, total, status, clear, start, stop } = useTrafficStream({
    maxRows: 500,
    path: "/api/stream/traffic",
    paused,
    ratePerSec: rate,
    enabled: true,
  });

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((e) => {
      const d = (e.dir || "unknown").toLowerCase();
      if (dir !== "all" && d !== dir) return false;
      if (!needle) return true;

      const blob = [
        e.src, e.dst, e.proto, e.dns, e.level,
        String(e.sport ?? ""), String(e.dport ?? "")
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return blob.includes(needle);
    });
  }, [rows, dir, q]);

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Live Traffic</h2>

        <span style={{ fontSize: 12, opacity: 0.75 }}>
          {status === "open" ? "Connected" : status === "connecting" ? "Connecting…" : status === "reconnecting" ? "Reconnecting…" : "Stopped"}
        </span>

        <button onClick={() => setPaused((p) => !p)}>
          {paused ? "Play" : "Pause"}
        </button>

        <button onClick={clear}>Clear</button>

        <button onClick={start}>Start</button>
        <button onClick={stop}>Stop</button>

        <label style={{ marginLeft: 12 }}>
          Speed:&nbsp;
          <input
            type="range"
            min="1"
            max="500"
            value={rate}
            onChange={(e) => setRate(Number(e.target.value))}
          />
          <span style={{ marginLeft: 8, fontSize: 12, opacity: 0.8 }}>{rate}/sec</span>
        </label>

        <label style={{ marginLeft: 12 }}>
          Direction:&nbsp;
          <select value={dir} onChange={(e) => setDir(e.target.value)}>
            <option value="all">All</option>
            <option value="inbound">Inbound</option>
            <option value="outbound">Outbound</option>
            <option value="internal">Internal</option>
            <option value="external">External</option>
            <option value="unknown">Unknown</option>
          </select>
        </label>

        <input
          style={{ marginLeft: "auto", minWidth: 260 }}
          placeholder="Search (IP, port, dns, proto...)"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <div style={{ marginBottom: 8, opacity: 0.8 }}>
        Total received since clear: {total} — Showing {filtered.length} (max 500)
      </div>

      <div style={{ overflow: "auto", border: "1px solid #333", borderRadius: 8 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: 8 }}>Time</th>
              <th style={{ textAlign: "left", padding: 8 }}>Dir</th>
              <th style={{ textAlign: "left", padding: 8 }}>Proto</th>
              <th style={{ textAlign: "left", padding: 8 }}>Source</th>
              <th style={{ textAlign: "left", padding: 8 }}>Destination</th>
              <th style={{ textAlign: "left", padding: 8 }}>DNS</th>
              <th style={{ textAlign: "left", padding: 8 }}>Level</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.eid || `${e.ts}-${e.src}-${e.dst}-${e.dport}`} style={{ borderTop: "1px solid #222" }}>
                <td style={{ padding: 8, whiteSpace: "nowrap" }}>{fmtTs(e.ts)}</td>
                <td style={{ padding: 8 }}>{e.dir || "unknown"}</td>
                <td style={{ padding: 8 }}>{String(e.proto || "").toUpperCase()}</td>
                <td style={{ padding: 8 }}>{e.src}{e.sport != null ? `:${e.sport}` : ""}</td>
                <td style={{ padding: 8 }}>{e.dst}{e.dport != null ? `:${e.dport}` : ""}</td>
                <td style={{ padding: 8 }}>{e.dns || ""}</td>
                <td style={{ padding: 8 }}>{e.level || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
