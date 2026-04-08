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
    if (v === "critical") return { background: "rgba(239,68,68,0.18)", color: "#fca5a5" };
    if (v === "error") return { background: "rgba(248,113,113,0.16)", color: "#fda4af" };
    if (v === "warning") return { background: "rgba(245,158,11,0.16)", color: "#fcd34d" };
    if (v === "info") return { background: "rgba(59,130,246,0.16)", color: "#93c5fd" };
    return { background: "rgba(148,163,184,0.16)", color: "#cbd5e1" };
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
        className="card"
        style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 12,
            marginBottom: 16,
        }}
        >
        <div>
            <div style={{ fontWeight: 800, fontSize: 18 }}>Log Analyzer</div>
            <div className="helper">
            Upload logs and review repeated IPs, users, hostnames, event patterns, and suspicious activity
            </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <label className="btn primary" style={{ cursor: "pointer" }}>
            Upload Log
            <input
                type="file"
                accept=".log,.txt,.csv,.json,.jsonl"
                onChange={onFileChange}
                style={{ display: "none" }}
            />
            </label>

            <button
            className="btn"
            onClick={() => downloadCsv(filteredRows, `log-analysis-${Date.now()}.csv`)}
            disabled={!filteredRows.length}
            >
            Export CSV
            </button>
        </div>
        </div>

        <div
        className="card"
        style={{
            marginBottom: 16,
            borderStyle: "dashed",
            textAlign: "center",
            padding: 24,
        }}
        >
        <div style={{ fontWeight: 700, marginBottom: 6 }}>
            {fileName ? `Loaded: ${fileName}` : "Drop in a log file or use Upload Log"}
        </div>
        <div className="helper">
            Supported now: .log, .txt, .csv, .json, .jsonl
        </div>
        {loadError ? (
            <div style={{ marginTop: 10, color: "var(--danger)" }}>{loadError}</div>
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
            <div key={card.label} className="card" style={{ padding: 16 }}>
            <div className="helper" style={{ marginBottom: 8 }}>{card.label}</div>
            <div style={{ fontSize: 24, fontWeight: 800 }}>{card.value}</div>
            </div>
        ))}
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
        <div
            style={{
            display: "grid",
            gridTemplateColumns: "minmax(260px, 1.5fr) repeat(4, minmax(160px, 220px))",
            gap: 12,
            }}
        >
            <input
            className="input"
            value={search}
            placeholder="Search all parsed fields"
            onChange={(e) => setSearch(e.target.value)}
            />

            <select
            className="input"
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
            className="input"
            value={ipFilter}
            placeholder="Filter by IP"
            onChange={(e) => setIpFilter(e.target.value)}
            />

            <input
            className="input"
            value={userFilter}
            placeholder="Filter by user"
            onChange={(e) => setUserFilter(e.target.value)}
            />

            <input
            className="input"
            value={hostnameFilter}
            placeholder="Filter by hostname"
            onChange={(e) => setHostnameFilter(e.target.value)}
            />
        </div>
        </div>

        <div className="grid-halves" style={{ marginBottom: 16 }}>
        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Findings Summary</h3>
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
            {findingsSummary.map((f, idx) => (
                <li key={idx}>{f}</li>
            ))}
            {!findingsSummary.length && <li className="helper">Upload a log file to generate findings.</li>}
            </ul>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Timeline Activity</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Time Bucket</th>
                <th style={{ width: 100 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {timelineBuckets.map((x) => (
                <tr key={x.key}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!timelineBuckets.length && (
                <tr>
                    <td colSpan="2" className="helper">No parseable timestamps found yet.</td>
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
            gap: 12,
            marginBottom: 16,
        }}
        >
        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top IPs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>IP</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topIps.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyIpFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topIps.length && (
                <tr>
                    <td colSpan="2" className="helper">No IPs extracted yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Users</h3>
            <table className="table">
            <thead>
                <tr>
                <th>User</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topUsers.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyUserFilter(x.key)}>
                    <td>{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topUsers.length && (
                <tr>
                    <td colSpan="2" className="helper">No usernames identified yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Hostnames</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Hostname</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topHosts.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyHostnameFilter(x.key)}>
                    <td>{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topHosts.length && (
                <tr>
                    <td colSpan="2" className="helper">No hostnames identified yet.</td>
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
            gap: 12,
            marginBottom: 16,
        }}
        >
        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Event IDs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Event ID</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topEventIds.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applySearchFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topEventIds.length && (
                <tr>
                    <td colSpan="2" className="helper">No event IDs identified yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Ports</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Port</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topPorts.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applySearchFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topPorts.length && (
                <tr>
                    <td colSpan="2" className="helper">No ports identified yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Suspicious Findings Preview</h3>
            <table className="table">
            <thead>
                <tr>
                <th style={{ width: 70 }}>Line</th>
                <th style={{ width: 110 }}>Severity</th>
                <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {suspiciousFindings.slice(0, 8).map((row) => (
                <tr key={row.id} style={{ cursor: "pointer" }} onClick={() => setSelectedRow(row)}>
                    <td className="mono">{row.id}</td>
                    <td><span className="chip" style={severityBadgeStyle(row.severity)}>{row.severity}</span></td>
                    <td>
                    <div
                        style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 360,
                        }}
                    >
                        {row.message}
                    </div>
                    </td>
                </tr>
                ))}
                {!suspiciousFindings.length && (
                <tr>
                    <td colSpan="3" className="helper">No suspicious keywords found yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
        <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Repeated IP + Message Combinations</h3>
        <table className="table">
            <thead>
            <tr>
                <th style={{ width: 180 }}>IP</th>
                <th>Message</th>
                <th style={{ width: 100 }}>Count</th>
            </tr>
            </thead>
            <tbody>
            {topIpMessages.map((x, idx) => (
                <tr key={`${idx}-${x.left}-${x.right}`}>
                <td className="mono" style={{ cursor: "pointer" }} onClick={() => applyIpFilter(x.left)}>
                    {x.left}
                </td>
                <td style={{ cursor: "pointer" }} onClick={() => applySearchFilter(x.right)}>
                    <div
                    style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 800,
                    }}
                    title={x.right}
                    >
                    {x.right}
                    </div>
                </td>
                <td className="mono">{x.count}</td>
                </tr>
            ))}
            {!topIpMessages.length && (
                <tr>
                <td colSpan="3" className="helper">No repeated IP/message combinations identified yet.</td>
                </tr>
            )}
            </tbody>
        </table>
        </div>

        <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 10 }}>
            <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Parsed Log Entries</h3>
            <span className="helper">{filteredRows.length} matching rows</span>
        </div>

        <div style={{ overflow: "auto", maxHeight: 560 }}>
            <table className="table">
            <thead>
                <tr>
                <th style={{ width: 70 }}>Line</th>
                <th style={{ width: 180 }}>Timestamp</th>
                <th style={{ width: 110 }}>Severity</th>
                <th style={{ width: 140 }}>IP</th>
                <th style={{ width: 140 }}>User</th>
                <th style={{ width: 160 }}>Hostname</th>
                <th style={{ width: 110 }}>Event ID</th>
                <th style={{ width: 90 }}>Port</th>
                <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {filteredRows.map((row) => (
                <tr
                    key={row.id}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedRow(row)}
                >
                    <td className="mono">{row.id}</td>
                    <td className="mono">{row.timestamp || "—"}</td>
                    <td>
                    <span className="chip" style={severityBadgeStyle(row.severity)}>
                        {row.severity}
                    </span>
                    </td>
                    <td className="mono">{row.ip || "—"}</td>
                    <td>{row.user || "—"}</td>
                    <td>{row.hostname || "—"}</td>
                    <td className="mono">{row.eventId || "—"}</td>
                    <td className="mono">{row.port || "—"}</td>
                    <td>
                    <div
                        style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 600,
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
                    <td colSpan="9" className="helper">
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
            background: "rgba(0,0,0,0.45)",
            display: "flex",
            justifyContent: "flex-end",
            zIndex: 1000,
            }}
        >
            <div
            className="card"
            style={{
                width: 680,
                height: "100%",
                borderRadius: 0,
                overflow: "auto",
                padding: 18,
            }}
            >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                <div style={{ fontSize: 18, fontWeight: 900 }}>
                    Log Entry <span className="mono">#{selectedRow.id}</span>
                </div>
                <div className="helper">
                    {selectedRow.timestamp || "No timestamp"} · {selectedRow.severity}
                </div>
                </div>
                <button className="btn" onClick={() => setSelectedRow(null)}>✕</button>
            </div>

            <div
                style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: 12,
                marginTop: 16,
                }}
            >
                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>IP</div>
                <div className="mono">{selectedRow.ip || "—"}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>User</div>
                <div>{selectedRow.user || "—"}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Hostname</div>
                <div>{selectedRow.hostname || "—"}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Event ID</div>
                <div className="mono">{selectedRow.eventId || "—"}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Port</div>
                <div className="mono">{selectedRow.port || "—"}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Severity</div>
                <div>
                    <span className="chip" style={severityBadgeStyle(selectedRow.severity)}>
                    {selectedRow.severity}
                    </span>
                </div>
                </div>
            </div>

            <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Message</div>
                <div style={{ whiteSpace: "pre-wrap", lineHeight: 1.5 }}>{selectedRow.message}</div>
            </div>

            <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Raw Line</div>
                <pre
                style={{
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    background: "rgba(255,255,255,0.03)",
                    padding: 12,
                    borderRadius: 10,
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