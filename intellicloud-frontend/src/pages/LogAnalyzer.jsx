import React from "react";

function guessSeverity(line) {
  const s = String(line || "").toLowerCase();
  
  const severityRules = [
    {
      severity: "critical",
      keywords: ["fatal", "panic", "critical", "crit", "emergency"],
    },
    {
      severity: "error",
      keywords: ["error", "failed", "denied", "exception", "unauthorized", "forbidden"],
    },
    {
      severity: "warning",
      keywords: ["warn", "warning", "suspicious", "retry"],
    },
    {
      severity: "info",
      keywords: ["info", "started", "connected", "accepted", "success"],
    },
  ];
  
  const match = severityRules.find(({ keywords }) =>
    keywords.some((keyword) => s.includes(keyword))
  );
  
  return match ? match.severity : "other";
}

function extractIp(line) {
  const match = String(line || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : "";
}

function extractTimestamp(line) {
  const s = String(line || "");

  const patterns = [
    /\b\d{4}-\d{2}-\d{2}[T ][\d:.+-Z]+\b/,
    /\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b/,
    /\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/,
    /\b\d{2}\/\d{2}\/\d{4}[ T]\d{2}:\d{2}:\d{2}\b/,
  ];

  for (const p of patterns) {
    const m = s.match(p);
    if (m) return m[0];
  }

  return "";
}

function firstRegexGroup(text, patterns) {
  const input = String(text || "");

  for (const pattern of patterns) {
    const match = input.match(pattern);
    if (match?.[1]) return match[1];
  }

  return "";
}

function extractUsername(line) {
  return firstRegexGroup(line, [
    /\buser(?:name)?[=: ]+["']?([A-Za-z0-9._@-]+)["']?/i,
    /\baccount[=: ]+["']?([A-Za-z0-9._@-]+)["']?/i,
    /\blogin[=: ]+["']?([A-Za-z0-9._@-]+)["']?/i,
    /\bfor user ["']?([A-Za-z0-9._@-]+)["']?/i,
    /\buser ["']?([A-Za-z0-9._@-]+)["']?/i,
  ]);
}

function extractHostname(line) {
  return firstRegexGroup(line, [
    /\bhost(?:name)?[=: ]+["']?([A-Za-z0-9._-]+)["']?/i,
    /\bdevice[=: ]+["']?([A-Za-z0-9._-]+)["']?/i,
    /\bcomputer[=: ]+["']?([A-Za-z0-9._-]+)["']?/i,
    /\bfrom host ["']?([A-Za-z0-9._-]+)["']?/i,
  ]);
}

function extractEventId(line) {
  return firstRegexGroup(line, [
    /\bevent[_ ]?id[=: ]+([A-Za-z0-9-]+)/i,
    /\bid[=: ]+([A-Za-z0-9-]+)/i,
    /\bcode[=: ]+([A-Za-z0-9-]+)/i,
  ]);
}

function extractPort(line) {
  return firstRegexGroup(line, [
    /\bport[=: ]+(\d{1,5})\b/i,
    /:(\d{1,5})\b/,
  ]);
}

function extractMessage(line) {
  return String(line || "").trim();
}

function parseTimestampForBucket(ts) {
  if (!ts) return null;
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function minuteBucketLabel(date) {
  const y = date.getFullYear();
  const mo = String(date.getMonth() + 1).padStart(2, "0");
  const da = String(date.getDate()).padStart(2, "0");
  const h = String(date.getHours()).padStart(2, "0");
  const mi = String(date.getMinutes()).padStart(2, "0");
  return `${y}-${mo}-${da} ${h}:${mi}`;
}

function parseLogLine(line, index) {
  const timestamp = extractTimestamp(line);

  return {
    id: index + 1,
    raw: line,
    timestamp,
    severity: guessSeverity(line),
    ip: extractIp(line),
    user: extractUsername(line),
    hostname: extractHostname(line),
    eventId: extractEventId(line),
    port: extractPort(line),
    message: extractMessage(line),
  };
}

function topCounts(items, keyFn, limit = 8) {
  const map = new Map();

  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    map.set(key, (map.get(key) || 0) + 1);
  }

  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

function topComboCounts(items, keyFnA, keyFnB, limit = 8) {
  const map = new Map();

  for (const item of items) {
    const a = keyFnA(item);
    const b = keyFnB(item);
    if (!a || !b) continue;
    const combo = `${a}|||${b}`;
    map.set(combo, (map.get(combo) || 0) + 1);
  }

  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([combo, count]) => {
      const [left, right] = combo.split("|||");
      return { left, right, count };
    });
}

function downloadCsv(rows, filename) {
  const header = [
    "line",
    "timestamp",
    "severity",
    "ip",
    "user",
    "hostname",
    "event_id",
    "port",
    "message",
  ];

  const csv = [
    header.join(","),
    ...rows.map((r) =>
      [
        r.id,
        r.timestamp,
        r.severity,
        r.ip,
        r.user,
        r.hostname,
        r.eventId,
        r.port,
        r.message,
      ]
        .map((v) => `"${String(v ?? "").replaceAll('"', '""')}"`)
        .join(",")
    ),
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function severityBadgeStyle(value) {
  const v = String(value || "other").toLowerCase();
  if (v === "critical") return { borderColor: "rgba(239, 68, 68, 0.4)", color: "#f87171", background: "transparent" };
  if (v === "error") return { borderColor: "rgba(248, 113, 113, 0.4)", color: "#fca5a5", background: "transparent" };
  if (v === "warning") return { borderColor: "rgba(245, 158, 11, 0.4)", color: "#fbbf24", background: "transparent" };
  if (v === "info") return { borderColor: "rgba(59, 130, 246, 0.4)", color: "#60a5fa", background: "transparent" };
  return { borderColor: "rgba(255, 255, 255, 0.1)", color: "rgba(255, 255, 255, 0.5)", background: "transparent" };
}

export default function LogAnalyzer() {
  const [fileName, setFileName] = React.useState("");
  const [rows, setRows] = React.useState([]);
  const [search, setSearch] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState("all");
  const [ipFilter, setIpFilter] = React.useState("");
  const [userFilter, setUserFilter] = React.useState("");
  const [hostnameFilter, setHostnameFilter] = React.useState("");
  const [selectedRow, setSelectedRow] = React.useState(null);
  const [loadError, setLoadError] = React.useState("");

  const handleFile = async (file) => {
    if (!file) return;

    try {
      setLoadError("");
      setFileName(file.name);

      const text = await file.text();

      const parsed = text
        .split(/\r?\n/)
        .filter((line) => line.trim().length > 0)
        .map((line, index) => parseLogLine(line, index));

      setRows(parsed);
      setSelectedRow(null);
    } catch (error) {
      setLoadError(String(error?.message || error));
      setRows([]);
      setSelectedRow(null);
    }
  };

  const onFileChange = (e) => {
    const file = e.target.files?.[0];
    handleFile(file);
  };

  const filteredRows = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    const ipQ = ipFilter.trim().toLowerCase();
    const userQ = userFilter.trim().toLowerCase();
    const hostQ = hostnameFilter.trim().toLowerCase();

    return rows.filter((row) => {
      const matchesSearch =
        !q ||
        row.raw.toLowerCase().includes(q) ||
        row.message.toLowerCase().includes(q) ||
        row.timestamp.toLowerCase().includes(q) ||
        row.ip.toLowerCase().includes(q) ||
        row.user.toLowerCase().includes(q) ||
        row.hostname.toLowerCase().includes(q) ||
        row.eventId.toLowerCase().includes(q);

      const matchesSeverity =
        severityFilter === "all" ? true : row.severity === severityFilter;

      const matchesIp = !ipQ || row.ip.toLowerCase().includes(ipQ);
      const matchesUser = !userQ || row.user.toLowerCase().includes(userQ);
      const matchesHostname = !hostQ || row.hostname.toLowerCase().includes(hostQ);

      return matchesSearch && matchesSeverity && matchesIp && matchesUser && matchesHostname;
    });
  }, [rows, search, severityFilter, ipFilter, userFilter, hostnameFilter]);

  const summary = React.useMemo(() => {
    const total = rows.length;
    const critical = rows.filter((r) => r.severity === "critical").length;
    const errors = rows.filter((r) => r.severity === "error").length;
    const warnings = rows.filter((r) => r.severity === "warning").length;
    const infos = rows.filter((r) => r.severity === "info").length;
    const uniqueIps = new Set(rows.map((r) => r.ip).filter(Boolean)).size;
    const uniqueUsers = new Set(rows.map((r) => r.user).filter(Boolean)).size;
    const uniqueHosts = new Set(rows.map((r) => r.hostname).filter(Boolean)).size;

    return {
      total,
      critical,
      errors,
      warnings,
      infos,
      uniqueIps,
      uniqueUsers,
      uniqueHosts,
    };
  }, [rows]);

  const topIps = React.useMemo(() => topCounts(rows, (r) => r.ip, 8), [rows]);
  const topUsers = React.useMemo(() => topCounts(rows, (r) => r.user, 8), [rows]);
  const topHosts = React.useMemo(() => topCounts(rows, (r) => r.hostname, 8), [rows]);
  const topMessages = React.useMemo(() => topCounts(rows, (r) => r.message, 8), [rows]);
  const topEventIds = React.useMemo(() => topCounts(rows, (r) => r.eventId, 8), [rows]);
  const topPorts = React.useMemo(() => topCounts(rows, (r) => r.port, 8), [rows]);
  const topIpMessages = React.useMemo(
    () => topComboCounts(rows, (r) => r.ip, (r) => r.message, 8),
    [rows]
  );

  const suspiciousFindings = React.useMemo(() => {
    const keywords = [
      "failed",
      "denied",
      "invalid",
      "unauthorized",
      "error",
      "exception",
      "suspicious",
      "malware",
      "attack",
      "blocked",
      "brute",
      "forbidden",
    ];

    return rows.filter((r) =>
      keywords.some((k) => r.raw.toLowerCase().includes(k))
    );
  }, [rows]);

  const timelineBuckets = React.useMemo(() => {
    const map = new Map();

    for (const row of rows) {
      const d = parseTimestampForBucket(row.timestamp);
      if (!d) continue;
      const key = minuteBucketLabel(d);
      map.set(key, (map.get(key) || 0) + 1);
    }

    return Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(-12)
      .map(([key, count]) => ({ key, count }));
  }, [rows]);

  const findingsSummary = React.useMemo(() => {
    return [
      summary.total > 0
        ? `The file contains ${summary.total} parsed log entries.`
        : null,
      
      summary.critical > 0
        ? `${summary.critical} entries were classified as critical.`
        : null,
      
      summary.errors > 0
        ? `${summary.errors} entries were classified as errors.`
        : null,
      
      summary.uniqueIps > 0
        ? `${summary.uniqueIps} unique IP addresses were identified.`
        : null,
      
      summary.uniqueUsers > 0
        ? `${summary.uniqueUsers} unique usernames or accounts were identified.`
        : null,
      
      topIps[0]
        ? `IP ${topIps[0].key} appears most often with ${topIps[0].count} occurrences.`
        : null,
      
      topUsers[0]
        ? `User ${topUsers[0].key} appears ${topUsers[0].count} times.`
        : null,
      
      topHosts[0]
        ? `Hostname ${topHosts[0].key} appears ${topHosts[0].count} times.`
        : null,
      
      topMessages[0]
        ? `The most repeated message appears ${topMessages[0].count} times.`
        : null,
      
      topIpMessages[0]
        ? `The most repeated IP/message combination is ${topIpMessages[0].left} with ${topIpMessages[0].count} matching lines.`
        : null,
      
      suspiciousFindings.length > 0
        ? `${suspiciousFindings.length} lines matched suspicious keywords.`
        : null,
    ]
      .filter(Boolean)
      .slice(0, 8);
  }, [summary, topIps, topUsers, topHosts, topMessages, topIpMessages, suspiciousFindings]);

  const applyIpFilter = (value) => setIpFilter(value || "");
  const applyUserFilter = (value) => setUserFilter(value || "");
  const applyHostnameFilter = (value) => setHostnameFilter(value || "");
  const applySearchFilter = (value) => setSearch(value || "");

  return (
    <div className="shell animate-fade" style={{ maxWidth: 1440 }}>
      <div
        className="card glass-panel hover-card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div>
          <div className="gradient-text" style={{ fontWeight: 800, fontSize: 18 }}>Log Analyzer</div>
          <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.5)", marginTop: 2 }}>
            Upload logs and review repeated IPs, users, hostnames, event patterns, and suspicious activity
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <label className="btn-glass" style={{ cursor: "pointer" }}>
            Upload Log
            <input
              type="file"
              accept=".log,.txt,.csv,.json,.jsonl"
              onChange={onFileChange}
              style={{ display: "none" }}
            />
          </label>

          <button
            className="btn-glass"
            onClick={() => downloadCsv(filteredRows, `log-analysis-${Date.now()}.csv`)}
            disabled={!filteredRows.length}
          >
            Export CSV
          </button>
        </div>
      </div>

      <div
        className="card glass-panel hover-card"
        style={{
          marginBottom: 16,
          border: "1px dashed rgba(255, 255, 255, 0.2)",
          background: "rgba(255, 255, 255, 0.02)",
          textAlign: "center",
          padding: 24,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 6, color: "rgba(255, 255, 255, 0.8)" }}>
          {fileName ? `Loaded: ${fileName}` : "Drop in a log file or use Upload Log"}
        </div>
        <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.5)" }}>
          Supported now: .log, .txt, .csv, .json, .jsonl
        </div>
        {loadError ? (
          <div style={{ marginTop: 10, color: "#f87171" }}>{loadError}</div>
        ) : null}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(8, minmax(0, 1fr))",
          gap: 12,
          marginBottom: 16,
        }}
      >
        {[
          { label: "Total Lines", value: summary.total },
          { label: "Critical", value: summary.critical },
          { label: "Errors", value: summary.errors },
          { label: "Warnings", value: summary.warnings },
          { label: "Info", value: summary.infos },
          { label: "Unique IPs", value: summary.uniqueIps },
          { label: "Unique Users", value: summary.uniqueUsers },
          { label: "Unique Hosts", value: summary.uniqueHosts },
        ].map((card) => (
          <div key={card.label} className="card glass-panel hover-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: "rgba(255, 255, 255, 0.6)", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>{card.label}</div>
            <div style={{ fontSize: 24, fontWeight: 800 }}>{card.value}</div>
          </div>
        ))}
      </div>

      <div className="card glass-panel hover-card" style={{ marginBottom: 16 }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(260px, 1.5fr) repeat(4, minmax(160px, 220px))",
            gap: 12,
          }}
        >
          <input
            className="input glass-panel"
            value={search}
            placeholder="Search all parsed fields"
            onChange={(e) => setSearch(e.target.value)}
          />

          <select
            className="select glass-panel"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
            <option value="other">Other</option>
          </select>

          <input
            className="input glass-panel"
            value={ipFilter}
            placeholder="Filter by IP"
            onChange={(e) => setIpFilter(e.target.value)}
          />

          <input
            className="input glass-panel"
            value={userFilter}
            placeholder="Filter by user"
            onChange={(e) => setUserFilter(e.target.value)}
          />

          <input
            className="input glass-panel"
            value={hostnameFilter}
            placeholder="Filter by hostname"
            onChange={(e) => setHostnameFilter(e.target.value)}
          />
        </div>
      </div>

      <div className="grid-halves" style={{ marginBottom: 16, gap: 16 }}>
        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Findings Summary</h3>
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, color: "rgba(255, 255, 255, 0.7)", fontSize: 14 }}>
            {findingsSummary.map((f, idx) => (
              <li key={idx} style={{ marginBottom: 4 }}>{f}</li>
            ))}
            {!findingsSummary.length && <li style={{ color: "rgba(255, 255, 255, 0.4)", listStyle: "none", marginLeft: -18 }}>Upload a log file to generate findings.</li>}
          </ul>
        </div>

        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Timeline Activity</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Time Bucket</th>
                <th style={{ width: 100, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {timelineBuckets.map((x) => (
                <tr key={x.key} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.7)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.7)" }}>{x.count}</td>
                </tr>
              ))}
              {!timelineBuckets.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No parseable timestamps found yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 16,
          marginBottom: 16,
        }}
      >
        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Top IPs</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>IP</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topIps.map((x) => (
                <tr 
                  key={x.key} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => applyIpFilter(x.key)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
                </tr>
              ))}
              {!topIps.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No IPs extracted yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Top Users</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>User</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topUsers.map((x) => (
                <tr 
                  key={x.key} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => applyUserFilter(x.key)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td style={{ color: "rgba(255, 255, 255, 0.8)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
                </tr>
              ))}
              {!topUsers.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No usernames identified yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Top Hostnames</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Hostname</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topHosts.map((x) => (
                <tr 
                  key={x.key} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => applyHostnameFilter(x.key)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td style={{ color: "rgba(255, 255, 255, 0.8)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
                </tr>
              ))}
              {!topHosts.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No hostnames identified yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 16,
          marginBottom: 16,
        }}
      >
        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Top Event IDs</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Event ID</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topEventIds.map((x) => (
                <tr 
                  key={x.key} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => applySearchFilter(x.key)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
                </tr>
              ))}
              {!topEventIds.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No event IDs identified yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Top Ports</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Port</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topPorts.map((x) => (
                <tr 
                  key={x.key} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => applySearchFilter(x.key)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{x.key}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
                </tr>
              ))}
              {!topPorts.length && (
                <tr>
                  <td colSpan="2" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No ports identified yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card glass-panel hover-card">
          <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Suspicious Findings Preview</h3>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ width: 70, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Line</th>
                <th style={{ width: 110, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Severity</th>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Message</th>
              </tr>
            </thead>
            <tbody>
              {suspiciousFindings.slice(0, 8).map((row) => (
                <tr 
                  key={row.id} 
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }} 
                  onClick={() => setSelectedRow(row)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{row.id}</td>
                  <td><span className="badge glass-panel" style={severityBadgeStyle(row.severity)}>{row.severity}</span></td>
                  <td>
                    <div
                      style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 360,
                        color: "rgba(255, 255, 255, 0.8)",
                        fontSize: 13
                      }}
                    >
                      {row.message}
                    </div>
                  </td>
                </tr>
              ))}
              {!suspiciousFindings.length && (
                <tr>
                  <td colSpan="3" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No suspicious keywords found yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card glass-panel hover-card" style={{ marginBottom: 16 }}>
        <h3 className="gradient-text" style={{ marginTop: 0, fontSize: 16 }}>Repeated IP + Message Combinations</h3>
        <table className="table" style={{ width: "100%" }}>
          <thead>
            <tr style={{ background: "transparent" }}>
              <th style={{ width: 180, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>IP</th>
              <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Message</th>
              <th style={{ width: 100, color: "rgba(255, 255, 255, 0.6)", background: "transparent", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>Count</th>
            </tr>
          </thead>
          <tbody>
            {topIpMessages.map((x, idx) => (
              <tr 
                key={`${idx}-${x.left}-${x.right}`} 
                style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <td className="mono" style={{ cursor: "pointer", color: "rgba(255, 255, 255, 0.8)" }} onClick={() => applyIpFilter(x.left)}>
                  {x.left}
                </td>
                <td style={{ cursor: "pointer" }} onClick={() => applySearchFilter(x.right)}>
                  <div
                    style={{
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      maxWidth: 800,
                      color: "rgba(255, 255, 255, 0.7)",
                      fontSize: 13
                    }}
                    title={x.right}
                  >
                    {x.right}
                  </div>
                </td>
                <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{x.count}</td>
              </tr>
            ))}
            {!topIpMessages.length && (
              <tr>
                <td colSpan="3" style={{ padding: "12px", color: "rgba(255, 255, 255, 0.4)", textAlign: "center" }}>No repeated IP/message combinations identified yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card glass-panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", background: "transparent" }}>
          <h3 className="gradient-text" style={{ margin: 0, fontSize: 16 }}>Parsed Log Entries</h3>
          <span style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.5)" }}>{filteredRows.length} matching rows</span>
        </div>

        <div style={{ overflow: "auto", maxHeight: 560 }}>
          <table className="table" style={{ width: "100%" }}>
            <thead>
              <tr style={{ background: "transparent" }}>
                <th style={{ width: 70, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Line</th>
                <th style={{ width: 180, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Timestamp</th>
                <th style={{ width: 110, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Severity</th>
                <th style={{ width: 140, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>IP</th>
                <th style={{ width: 140, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>User</th>
                <th style={{ width: 160, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Hostname</th>
                <th style={{ width: 110, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Event ID</th>
                <th style={{ width: 90, color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Port</th>
                <th style={{ color: "rgba(255, 255, 255, 0.6)", background: "transparent" }}>Message</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr
                  key={row.id}
                  style={{ cursor: "pointer", borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }}
                  onClick={() => setSelectedRow(row)}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.5)" }}>{row.id}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{row.timestamp || "—"}</td>
                  <td>
                    <span className="badge glass-panel" style={severityBadgeStyle(row.severity)}>
                      {row.severity}
                    </span>
                  </td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{row.ip || "—"}</td>
                  <td style={{ color: "rgba(255, 255, 255, 0.8)", fontSize: 13 }}>{row.user || "—"}</td>
                  <td style={{ color: "rgba(255, 255, 255, 0.8)", fontSize: 13 }}>{row.hostname || "—"}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{row.eventId || "—"}</td>
                  <td className="mono" style={{ color: "rgba(255, 255, 255, 0.8)" }}>{row.port || "—"}</td>
                  <td>
                    <div
                      style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 600,
                        color: "rgba(255, 255, 255, 0.6)",
                        fontSize: 13
                      }}
                      title={row.message}
                    >
                      {row.message}
                    </div>
                  </td>
                </tr>
              ))}

              {!filteredRows.length && (
                <tr>
                  <td colSpan="9" style={{ padding: 40, textAlign: "center", color: "rgba(255, 255, 255, 0.5)" }}>
                    No log lines to display yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedRow && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            backdropFilter: "blur(4px)",
            display: "flex",
            justifyContent: "flex-end",
            zIndex: 1000,
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: 680,
              height: "100vh",
              borderRadius: 0,
              borderLeft: "1px solid rgba(255, 255, 255, 0.05)",
              background: "rgba(11, 15, 23, 0.85)",
              overflow: "auto",
              padding: "24px",
              boxShadow: "-4px 0 24px rgba(0,0,0,0.3)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ fontSize: 18, fontWeight: 900, marginBottom: 4 }}>
                  Log Entry <span className="mono gradient-text">#{selectedRow.id}</span>
                </div>
                <div style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.5)" }}>
                  {selectedRow.timestamp || "No timestamp"} · <span style={{ textTransform: "capitalize" }}>{selectedRow.severity}</span>
                </div>
              </div>
              <button className="btn-glass" onClick={() => setSelectedRow(null)} style={{ padding: "8px 12px", borderRadius: "50%" }}>✕</button>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: 16,
                marginTop: 24,
              }}
            >
              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>IP</div>
                <div className="mono" style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.9)" }}>{selectedRow.ip || "—"}</div>
              </div>

              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>User</div>
                <div style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.9)" }}>{selectedRow.user || "—"}</div>
              </div>

              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Hostname</div>
                <div style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.9)" }}>{selectedRow.hostname || "—"}</div>
              </div>

              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Event ID</div>
                <div className="mono" style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.9)" }}>{selectedRow.eventId || "—"}</div>
              </div>

              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Port</div>
                <div className="mono" style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.9)" }}>{selectedRow.port || "—"}</div>
              </div>

              <div className="card glass-panel" style={{ padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255, 255, 255, 0.5)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Severity</div>
                <div>
                  <span className="badge glass-panel" style={severityBadgeStyle(selectedRow.severity)}>
                    {selectedRow.severity}
                  </span>
                </div>
              </div>
            </div>

            <div style={{ marginTop: 24 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Message</div>
              <div style={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "rgba(255, 255, 255, 0.9)", fontSize: 14, background: "rgba(255, 255, 255, 0.02)", padding: 16, borderRadius: 8, border: "1px solid rgba(255, 255, 255, 0.05)" }}>
                {selectedRow.message}
              </div>
            </div>

            <div style={{ marginTop: 24 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "rgba(255, 255, 255, 0.6)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>Raw Line</div>
              <pre
                style={{
                  margin: 0,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  background: "rgba(255, 255, 255, 0.02)",
                  border: "1px solid rgba(255, 255, 255, 0.05)",
                  padding: 16,
                  borderRadius: 8,
                  color: "rgba(255, 255, 255, 0.6)",
                  fontSize: 13,
                  lineHeight: 1.5,
                  fontFamily: "monospace"
                }}
              >
                {selectedRow.raw}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}