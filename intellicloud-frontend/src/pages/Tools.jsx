import React, { useState } from "react";
import { apiFetch } from "../api/http";

// ─── Shared UI helpers ────────────────────────────────────────────────────────

function ToolCard({ title, icon, description, children }) {
  return (
    <div className="card glass-panel hover-card animate-slide" style={{ marginBottom: 24, padding: 0 }}>
      <div style={{
        padding: "18px 24px",
        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
        display: "flex", alignItems: "center", gap: 12,
        background: "transparent",
      }}>
        <span style={{ fontSize: 22 }}>{icon}</span>
        <div>
          <div className="gradient-text" style={{ fontWeight: 700, fontSize: 16 }}>{title}</div>
          <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.5)", marginTop: 2 }}>{description}</div>
        </div>
      </div>
      <div style={{ padding: 24 }}>{children}</div>
    </div>
  );
}

function SearchInput({ value, onChange, onSubmit, placeholder, loading, buttonLabel = "Look Up" }) {
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }}
      style={{ display: "flex", gap: 12 }}>
      <input
        className="input glass-panel"
        style={{ flex: 1 }}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={loading}
      />
      <button className="btn-glass" type="submit" disabled={loading || !value.trim()}>
        {loading ? "Searching…" : buttonLabel}
      </button>
    </form>
  );
}

function ErrorBox({ message }) {
  return (
    <div style={{
      marginTop: 16, padding: "12px 16px", borderRadius: 8,
      background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)",
      color: "#f87171", fontSize: 13,
    }}>
      ⚠ {message}
    </div>
  );
}

const badgeStyleMap = (b) => {
  if (b === "high" || b === "crit") return { borderColor: "rgba(239, 68, 68, 0.4)", color: "#f87171" };
  if (b === "med") return { borderColor: "rgba(245, 158, 11, 0.4)", color: "#fbbf24" };
  if (b === "low") return { borderColor: "rgba(46, 204, 113, 0.4)", color: "#2ecc71" };
  return { borderColor: "rgba(255, 255, 255, 0.1)", color: "rgba(255, 255, 255, 0.6)" };
};

function ResultTable({ rows }) {
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 16, fontSize: 13 }}>
      <tbody>
        {rows.filter(r => r.value !== null && r.value !== undefined && r.value !== "").map((row, i) => (
          <tr key={i} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
            <td style={{ padding: "10px 12px", color: "rgba(255, 255, 255, 0.6)", width: "35%", fontWeight: 600 }}>
              {row.label}
            </td>
            <td style={{ padding: "10px 12px", color: "rgba(255, 255, 255, 0.9)" }}>
              {row.badge ? (
                <span className="badge glass-panel" style={{ ...badgeStyleMap(row.badge), background: "transparent" }}>
                  {String(row.value)}
                </span>
              ) : (
                <span style={{ fontFamily: row.mono ? "monospace" : undefined, wordBreak: "break-all" }}>
                  {String(row.value)}
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function VerdictBadge({ verdict }) {
  const vStr = String(verdict || "").toLowerCase();
  let style = badgeStyleMap("low"); // Clean default
  let label = "CLEAN";
  
  if (vStr === "malicious" || vStr === "high") { 
    style = badgeStyleMap("high"); label = "MALICIOUS"; 
  } else if (vStr === "suspicious" || vStr === "medium" || vStr === "med") { 
    style = badgeStyleMap("med"); label = "SUSPICIOUS"; 
  } else if (vStr && vStr !== "clean") { 
    label = vStr.toUpperCase(); style = badgeStyleMap(); 
  }

  return (
    <span className="badge glass-panel" style={{ ...style, background: "transparent", fontSize: 12, padding: "4px 12px", letterSpacing: 0.5, fontWeight: 700 }}>
      {label}
    </span>
  );
}

function SourceBlock({ title, data }) {
  if (!data) return null;
  if (!data.available) {
    return (
      <div style={{ marginTop: 16, padding: "10px 14px", borderRadius: 8,
        background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)", fontSize: 12,
        color: "rgba(255, 255, 255, 0.4)" }}>
        <strong>{title}:</strong> {data.reason || "unavailable"}
      </div>
    );
  }
  return (
    <div className="glass-panel" style={{ marginTop: 16, padding: "14px 16px", borderRadius: 8,
      background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)" }}>
      <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12, color: "rgba(255, 255, 255, 0.8)", textTransform: "uppercase", letterSpacing: 0.5 }}>
        {title}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 16px", fontSize: 13 }}>
        {Object.entries(data)
          .filter(([k, v]) => k !== "available" && v !== null && v !== undefined && v !== "")
          .map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 8 }}>
              <span style={{ color: "rgba(255, 255, 255, 0.5)", minWidth: 110, textTransform: "capitalize" }}>
                {k.replace(/_/g, " ")}
              </span>
              <span style={{ fontWeight: 600, wordBreak: "break-all", color: "rgba(255, 255, 255, 0.9)" }}>{String(v)}</span>
            </div>
          ))}
      </div>
    </div>
  );
}

// ─── Tool 1: IP Intelligence ──────────────────────────────────────────────────

function IPLookupTool() {
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/ip-lookup", {
        method: "POST",
        body: JSON.stringify({ ip }),
      });
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="IP Intelligence"
      icon="🔍"
      description="Query AbuseIPDB, VirusTotal, and ipinfo.io simultaneously for any IP address."
    >
      <SearchInput
        value={ip} onChange={setIp} onSubmit={run}
        placeholder="e.g. 1.1.1.1 or 45.33.32.156" loading={loading}
      />
      {error && <ErrorBox message={error} />}
      {result && (
        <div style={{ marginTop: 24 }} className="animate-fade">
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <span style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{result.ip}</span>
            <VerdictBadge verdict={result.verdict} />
          </div>
          <SourceBlock title="AbuseIPDB"  data={result.sources?.abuseipdb} />
          <SourceBlock title="VirusTotal" data={result.sources?.virustotal} />
          <SourceBlock title="IPInfo"     data={result.sources?.ipinfo} />
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 2: DNS Lookup ───────────────────────────────────────────────────────

function DNSLookupTool() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/dns-lookup", {
        method: "POST",
        body: JSON.stringify({ domain: target }),
      });
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "DNS lookup failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="DNS Interrogation"
      icon="🌐"
      description="Full DNS record lookup — A, AAAA, MX, TXT, NS, CNAME, SOA, PTR. Works on domains and IPs."
    >
      <SearchInput
        value={target} onChange={setTarget} onSubmit={run}
        placeholder="e.g. google.com or 8.8.8.8" loading={loading}
        buttonLabel="Resolve"
      />
      {error && <ErrorBox message={error} />}
      {result && (
        <div style={{ marginTop: 24 }} className="animate-fade">
          <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.6)", marginBottom: 16 }}>
            {result.type === "reverse" ? "Reverse DNS" : "Forward DNS"} results for{" "}
            <strong style={{ color: "#fff", fontFamily: "monospace" }}>{result.target}</strong>
          </div>
          {Object.entries(result.records || {}).map(([type, values]) => (
            values && values.length > 0 ? (
              <div key={type} className="glass-panel" style={{
                marginBottom: 12, padding: "12px 16px", borderRadius: 8,
                background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)",
              }}>
                <div className="gradient-text" style={{ fontWeight: 800, fontSize: 13, marginBottom: 8, letterSpacing: 0.5 }}>{type}</div>
                {values.map((v, i) => (
                  <div key={i} style={{ fontFamily: "monospace", fontSize: 13, color: "rgba(255, 255, 255, 0.8)", wordBreak: "break-all", marginBottom: 4 }}>
                    {v}
                  </div>
                ))}
              </div>
            ) : null
          ))}
          {Object.values(result.records || {}).every(v => !v || v.length === 0) && (
            <div style={{ color: "rgba(255, 255, 255, 0.4)", fontSize: 13 }}>No records found.</div>
          )}
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 3: WHOIS ────────────────────────────────────────────────────────────

function WhoIsTool() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/whois", {
        method: "POST",
        body: JSON.stringify({ domain: target }),
      });
      if (data.error) throw new Error(data.detail || data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "WHOIS lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const r = result?.result || {};

  const rows = [
    { label: "Domain",       value: r.domain_name, mono: true },
    { label: "Registrar",    value: r.registrar },
    { label: "Registered",   value: r.creation_date },
    { label: "Expires",      value: r.expiration_date },
    { label: "Last Updated", value: r.updated_date },
    { label: "Org",          value: r.org },
    { label: "Country",      value: r.country },
    { label: "DNSSEC",       value: r.dnssec },
    { label: "Emails",       value: (r.emails || []).join(", ") },
    { label: "Name Servers", value: (r.name_servers || []).join(", "), mono: true },
    { label: "Status",       value: (r.status || []).slice(0, 3).join(" | ") },
  ];

  return (
    <ToolCard
      title="WHOIS Lookup"
      icon="📋"
      description="Domain registration information — registrar, dates, nameservers, and registrant details."
    >
      <SearchInput
        value={target} onChange={setTarget} onSubmit={run}
        placeholder="e.g. example.com" loading={loading}
        buttonLabel="Query"
      />
      {error && <ErrorBox message={error} />}
      {result && (
        <div style={{ marginTop: 16 }} className="animate-fade">
          <ResultTable rows={rows} />
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 4: Hash Lookup ──────────────────────────────────────────────────────

function HashLookupTool() {
  const [hash, setHash] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/hash-lookup", {
        method: "POST",
        body: JSON.stringify({ hash }),
      });
      if (data.error) throw new Error(data.detail || data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "Hash lookup failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="File Hash Lookup"
      icon="🔐"
      description="Check any MD5, SHA1, or SHA256 hash against the VirusTotal database."
    >
      <SearchInput
        value={hash} onChange={setHash} onSubmit={run}
        placeholder="MD5, SHA1, or SHA256 hash" loading={loading}
        buttonLabel="Scan"
      />
      {error && <ErrorBox message={error} />}

      {result && !result.found && (
        <div style={{ marginTop: 16, color: "rgba(255, 255, 255, 0.5)", fontSize: 13 }}>
          Hash not found in VirusTotal database.
        </div>
      )}

      {result?.found && (
        <div style={{ marginTop: 24 }} className="animate-fade">
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <span style={{ fontFamily: "monospace", fontSize: 14, color: "rgba(255, 255, 255, 0.8)", wordBreak: "break-all" }}>
              {result.hash}
            </span>
            <VerdictBadge verdict={result.verdict} />
          </div>

          <ResultTable rows={[
            { label: "File Name",  value: result.file_name, mono: true },
            { label: "File Type",  value: result.file_type },
            { label: "File Size",  value: result.file_size ? `${result.file_size} bytes` : null },
            { label: "First Seen", value: result.first_seen ? new Date(result.first_seen * 1000).toLocaleString() : null },
            { label: "Last Seen",  value: result.last_seen ? new Date(result.last_seen * 1000).toLocaleString() : null },
            { label: "Tags",       value: (result.tags || []).join(", ") },
            { label: "Malicious",  value: result.stats?.malicious, badge: result.stats?.malicious > 0 ? "high" : "low" },
            { label: "Suspicious", value: result.stats?.suspicious, badge: result.stats?.suspicious > 0 ? "med" : "low" },
            { label: "Harmless",   value: result.stats?.harmless },
            { label: "Undetected", value: result.stats?.undetected },
          ]} />

          {result.detections?.length > 0 && (
            <div style={{ marginTop: 24 }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12, color: "rgba(255, 255, 255, 0.7)", textTransform: "uppercase", letterSpacing: 0.5 }}>
                Vendor Detections ({result.detections.length})
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {result.detections.map((d, i) => (
                  <div key={i} className="glass-panel" style={{
                    padding: "8px 12px", borderRadius: 6, fontSize: 12,
                    background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)",
                    display: "flex", justifyContent: "space-between", gap: 8,
                  }}>
                    <span style={{ color: "rgba(255, 255, 255, 0.6)", fontWeight: 600 }}>{d.vendor}</span>
                    <span style={{ color: "#f87171", fontWeight: 700, wordBreak: "break-all", textAlign: "right" }}>
                      {d.result || d.category}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 5: URL Scanner ──────────────────────────────────────────────────────

function URLScannerTool() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/url-scan", {
        method: "POST",
        body: JSON.stringify({ url }),
      });
      if (data.error) throw new Error(data.detail || data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="URL / Link Scanner"
      icon="🔗"
      description="Safely analyze a suspicious URL — follow redirects, detect typosquatting, and check against Google Safe Browsing."
    >
      <SearchInput
        value={url} onChange={setUrl} onSubmit={run}
        placeholder="e.g. https://suspicious-link.com or bit.ly/abc123"
        loading={loading} buttonLabel="Scan"
      />
      {error && <ErrorBox message={error} />}
      {result && (
        <div style={{ marginTop: 24 }} className="animate-fade">
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <span style={{ fontSize: 14, fontFamily: "monospace", wordBreak: "break-all", color: "rgba(255, 255, 255, 0.8)" }}>
              {result.url}
            </span>
            <VerdictBadge verdict={result.verdict} />
          </div>

          {/* Redirect chain */}
          {result.redirect && !result.redirect.error && (
            <div className="glass-panel" style={{ marginBottom: 16, padding: "16px 20px", borderRadius: 8, background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <div className="gradient-text" style={{ fontWeight: 800, fontSize: 12, marginBottom: 12, letterSpacing: 0.5 }}>
                REDIRECT CHAIN ({result.redirect.redirect_count} redirects)
              </div>
              {(result.redirect.redirect_chain || []).map((u, i) => (
                <div key={i} style={{ fontSize: 13, fontFamily: "monospace", color: "rgba(255, 255, 255, 0.8)", marginBottom: 6, wordBreak: "break-all" }}>
                  <span style={{ color: "rgba(255, 255, 255, 0.4)", marginRight: 8 }}>{i + 1}.</span>{u}
                </div>
              ))}
              <div style={{ marginTop: 12, fontSize: 13, color: "rgba(255, 255, 255, 0.5)" }}>
                Final status: <strong style={{ color: "#fff" }}>{result.redirect.status_code}</strong>
              </div>
            </div>
          )}

          {/* Typosquat warnings */}
          {(result.typosquat_warnings || []).length > 0 && (
            <div style={{ marginBottom: 16, padding: "12px 16px", borderRadius: 8, background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)" }}>
              <div style={{ fontWeight: 800, fontSize: 12, color: "#fbbf24", marginBottom: 8, letterSpacing: 0.5 }}>⚠ TYPOSQUATTING WARNINGS</div>
              {result.typosquat_warnings.map((w, i) => (
                <div key={i} style={{ fontSize: 13, color: "#fbbf24", marginBottom: 4 }}>{w}</div>
              ))}
            </div>
          )}

          {/* Safe Browsing */}
          <SourceBlock title="Google Safe Browsing" data={
            result.safe_browsing?.available === false
              ? result.safe_browsing
              : {
                  available: true,
                  safe: result.safe_browsing?.safe ? "Yes" : "NO — THREATS DETECTED",
                  threats: (result.safe_browsing?.threats || []).join(", ") || "None",
                }
          } />
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 6: CVE Search ───────────────────────────────────────────────────────

const SEVERITY_BADGE = {
  CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low",
};

function CVESearchTool() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResults(null);
    try {
      const isCveId = /^CVE-\d{4}-\d+$/i.test(query.trim());
      const params  = isCveId
        ? `cve_id=${encodeURIComponent(query.trim().toUpperCase())}`
        : `q=${encodeURIComponent(query.trim())}`;
      const data = await apiFetch(`tools/cve-search?${params}`);
      if (data.error) throw new Error(data.detail || data.error);
      setResults(data);
    } catch (e) {
      setError(e.message || "Search failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="CVE / Vulnerability Search"
      icon="🛡"
      description="Search the NIST National Vulnerability Database by keyword or CVE ID. No API key required."
    >
      <SearchInput
        value={query} onChange={setQuery} onSubmit={run}
        placeholder="e.g. log4j, apache struts, CVE-2021-44228"
        loading={loading} buttonLabel="Search"
      />
      {error && <ErrorBox message={error} />}

      {results && (
        <div style={{ marginTop: 24 }} className="animate-fade">
          <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.5)", marginBottom: 16, fontWeight: 600 }}>
            {results.total} total results — showing {results.results?.length || 0}
          </div>
          {(results.results || []).length === 0 && (
            <div style={{ color: "rgba(255, 255, 255, 0.5)", fontSize: 13 }}>No CVEs found for that query.</div>
          )}
          {(results.results || []).map((cve) => (
            <div key={cve.cve_id} className="glass-panel" style={{
              marginBottom: 16, padding: "20px", borderRadius: 10,
              background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12, flexWrap: "wrap" }}>
                <span className="gradient-text" style={{ fontFamily: "monospace", fontWeight: 800, fontSize: 16 }}>
                  {cve.cve_id}
                </span>
                {cve.severity && (
                  <span className="badge glass-panel" style={{ ...badgeStyleMap(SEVERITY_BADGE[cve.severity?.toUpperCase()]), background: "transparent", fontSize: 11, padding: "2px 8px" }}>
                    {cve.severity}
                  </span>
                )}
                {cve.cvss_score && (
                  <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: "rgba(255, 255, 255, 0.9)" }}>
                    CVSS {cve.cvss_score}
                  </span>
                )}
                {cve.published && (
                  <span style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.4)", marginLeft: "auto" }}>
                    Published: {new Date(cve.published).toLocaleDateString()}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 14, color: "rgba(255, 255, 255, 0.7)", lineHeight: 1.6, marginBottom: 12 }}>
                {cve.description}
              </div>
              {(cve.references || []).length > 0 && (
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  {cve.references.map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 12, color: "rgba(255, 255, 255, 0.8)", textDecoration: "underline", textDecorationColor: "rgba(255, 255, 255, 0.2)", textUnderlineOffset: 4 }}>
                      Reference {i + 1} ↗
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </ToolCard>
  );
}

// ─── Tool 7: SSL Inspector ────────────────────────────────────────────────────

const GRADE_COLORS = { A: "#2ecc71", B: "#f1c40f", C: "#e67e22", F: "#e74c3c" };

function SSLInspectorTool() {
  const [host, setHost] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await apiFetch("tools/ssl-inspect", {
        method: "POST",
        body: JSON.stringify({ host }),
      });
      if (data.error && !data.grade) throw new Error(data.detail || data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "Inspection failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolCard
      title="SSL / TLS Certificate Inspector"
      icon="🔒"
      description="Inspect a domain's SSL certificate — validity, issuer, cipher strength, SANs, and expiry."
    >
      <SearchInput
        value={host} onChange={setHost} onSubmit={run}
        placeholder="e.g. google.com or suspicious-site.io"
        loading={loading} buttonLabel="Inspect"
      />
      {error && <ErrorBox message={error} />}

      {result && (
        <div style={{ marginTop: 24 }} className="animate-fade">

          {/* Grade + status */}
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
            <div className="glass-panel" style={{
              width: 64, height: 64, borderRadius: 12, display: "flex",
              alignItems: "center", justifyContent: "center",
              background: "transparent",
              border: `2px solid ${GRADE_COLORS[result.grade] || "rgba(255, 255, 255, 0.2)"}`,
              fontSize: 28, fontWeight: 900, color: GRADE_COLORS[result.grade] || "rgba(255, 255, 255, 0.6)",
              fontFamily: "monospace",
              boxShadow: `0 0 15px ${GRADE_COLORS[result.grade] || "transparent"}33`
            }}>
              {result.grade}
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: 18, color: "#fff", fontFamily: "monospace" }}>{result.host}</div>
              <div style={{ fontSize: 13, color: "rgba(255, 255, 255, 0.6)", marginTop: 6 }}>
                {result.expired
                  ? <span style={{ color: "#f87171", fontWeight: 700 }}>⚠ Certificate EXPIRED</span>
                  : result.days_remaining !== null
                  ? <span style={{ color: result.days_remaining < 30 ? "#fbbf24" : "#2ecc71", fontWeight: 600 }}>
                      ✓ Valid — {result.days_remaining} days remaining
                    </span>
                  : "Status unknown"}
              </div>
            </div>
          </div>

          {/* Warnings */}
          {(result.is_weak_cipher || result.is_weak_bits) && (
            <div style={{ marginBottom: 16, padding: "12px 16px", borderRadius: 8, background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", color: "#f87171", fontSize: 13 }}>
              ⚠ Weak cipher detected: <strong>{result.cipher}</strong> ({result.cipher_bits} bits)
            </div>
          )}

          {/* Details table */}
          <ResultTable rows={[
            { label: "Protocol",     value: result.protocol },
            { label: "Cipher Suite", value: result.cipher, mono: true },
            { label: "Key Strength", value: result.cipher_bits ? `${result.cipher_bits} bits` : null },
            { label: "Valid From",   value: result.valid_from },
            { label: "Valid Until",  value: result.valid_until },
            { label: "Common Name",  value: result.subject?.common_name },
            { label: "Organization", value: result.subject?.org },
            { label: "Country",      value: result.subject?.country },
            { label: "Issued By",    value: result.issuer?.common_name },
            { label: "Issuer Org",   value: result.issuer?.org },
            { label: "Serial",       value: result.serial_number, mono: true },
          ]} />

          {/* SANs */}
          {(result.sans || []).length > 0 && (
            <div className="glass-panel" style={{ marginTop: 24, padding: 16, borderRadius: 8, background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <div style={{ fontWeight: 800, fontSize: 12, color: "rgba(255, 255, 255, 0.6)", marginBottom: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>
                SUBJECT ALTERNATIVE NAMES ({result.sans.length})
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {result.sans.map((san, i) => (
                  <span key={i} className="glass-panel" style={{ fontFamily: "monospace", fontSize: 12, padding: "4px 10px", background: "transparent", border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: 6, color: "rgba(255, 255, 255, 0.8)" }}>
                    {san}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </ToolCard>
  );
}

// ─── Main Tools Page ──────────────────────────────────────────────────────────

const TOOL_LIST = [
  { id: "ip",   label: "IP Intelligence", icon: "🔍" },
  { id: "dns",  label: "DNS Lookup",      icon: "🌐" },
  { id: "whois",label: "WHOIS",           icon: "📋" },
  { id: "hash", label: "Hash Lookup",     icon: "🔐" },
  { id: "url",  label: "URL Scanner",     icon: "🔗" },
  { id: "cve",  label: "CVE Search",      icon: "🛡" },
  { id: "ssl",  label: "SSL Inspector",   icon: "🔒" },
];

export default function Tools() {
  const [active, setActive] = useState("ip");

  return (
    <div className="shell animate-fade" style={{ padding: 24, maxWidth: 1000, margin: "0 auto", marginTop: 20 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 className="gradient-text" style={{ margin: 0, fontSize: 26, fontWeight: 800 }}>Security Tools</h1>
        <p style={{ margin: "8px 0 0", color: "rgba(255, 255, 255, 0.6)", fontSize: 15 }}>
          Threat intelligence lookups — no need to leave the platform.
        </p>
      </div>

      {/* Tab bar */}
      <div style={{
        display: "flex", gap: 6, marginBottom: 32, flexWrap: "wrap",
        background: "rgba(255, 255, 255, 0.02)", padding: 6, borderRadius: 16,
        border: "1px solid rgba(255, 255, 255, 0.05)", width: "fit-content",
        backdropFilter: "blur(10px)",
      }}>
        {TOOL_LIST.map(tool => (
          <button
            key={tool.id}
            onClick={() => setActive(tool.id)}
            style={{
              padding: "10px 20px", borderRadius: 10, border: "1px solid transparent", cursor: "pointer",
              fontWeight: 600, fontSize: 13,
              background: active === tool.id ? "rgba(255, 255, 255, 0.08)" : "transparent",
              color: active === tool.id ? "#fff" : "rgba(255, 255, 255, 0.5)",
              transition: "all 0.2s cubic-bezier(0.4, 0, 0.2, 1)",
              display: "flex", alignItems: "center", gap: 8,
            }}
          >
            <span style={{ fontSize: 16 }}>{tool.icon}</span> {tool.label}
          </button>
        ))}
      </div>

      {/* Active tool */}
      <div className="animate-slide animate-delay-1">
        {active === "ip"    && <IPLookupTool />}
        {active === "dns"   && <DNSLookupTool />}
        {active === "whois" && <WhoIsTool />}
        {active === "hash"  && <HashLookupTool />}
        {active === "url"   && <URLScannerTool />}
        {active === "cve"   && <CVESearchTool />}
        {active === "ssl"   && <SSLInspectorTool />}
      </div>
    </div>
  );
}