// src/pages/Decipher.jsx
import React, { useState, useEffect, useMemo } from 'react';

// ─── Morse Code ───────────────────────────────────────────────────────────────
const MORSE_MAP = {
  'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
  'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
  'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
  '1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','0':'-----',' ':'/'
};
const REVERSE_MORSE = Object.fromEntries(Object.entries(MORSE_MAP).map(([k,v])=>[v,k]));

// ─── Cipher Definitions ───────────────────────────────────────────────────────
const ciphers = {
  base64: {
    name: 'Base64', desc: 'Encode binary data into ASCII characters.',
    encode: (s) => { try { return btoa(unescape(encodeURIComponent(s))); } catch { return 'Error: Invalid input.'; } },
    decode: (s) => { try { return decodeURIComponent(escape(atob(s))); } catch { return 'Invalid Base64 string.'; } }
  },
  hex: {
    name: 'Hexadecimal', desc: 'Convert text to hexadecimal bytes.',
    encode: (s) => Array.from(s).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(' '),
    decode: (s) => {
      try {
        const hex = s.replace(/\s+/g,'');
        if (hex.length % 2 !== 0) return 'Invalid Hex (odd length)';
        let str = '';
        for (let i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i,2),16));
        return str;
      } catch { return 'Invalid Hex'; }
    }
  },
  binary: {
    name: 'Binary', desc: 'Convert text to binary (8-bit) representation.',
    encode: (s) => Array.from(s).map(c => c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '),
    decode: (s) => {
      try {
        return s.trim().split(/\s+/).map(b => String.fromCharCode(parseInt(b,2))).join('');
      } catch { return 'Invalid binary string.'; }
    }
  },
  url: {
    name: 'URL Encode', desc: 'Encode/decode URL-safe strings.',
    encode: (s) => encodeURIComponent(s),
    decode: (s) => { try { return decodeURIComponent(s); } catch { return 'Invalid URL-encoded string.'; } }
  },
  html: {
    name: 'HTML Entities', desc: 'Encode/decode HTML special characters.',
    encode: (s) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'),
    decode: (s) => s.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'")
  },
  rot13: {
    name: 'ROT13', desc: 'Rotate characters by 13 places.',
    encode: (s) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c<='Z'?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26)),
    decode: (s) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c<='Z'?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26))
  },
  atbash: {
    name: 'Atbash', desc: 'Reverses the alphabet (A↔Z, B↔Y).',
    encode: (s) => s.replace(/[a-zA-Z]/g, c => { const b=c<='Z'?65:97; return String.fromCharCode(b+(25-(c.charCodeAt(0)-b))); }),
    decode: (s) => s.replace(/[a-zA-Z]/g, c => { const b=c<='Z'?65:97; return String.fromCharCode(b+(25-(c.charCodeAt(0)-b))); })
  },
  morse: {
    name: 'Morse Code', desc: 'Dots and dashes encoding. Use / for space between words.',
    encode: (s) => s.toUpperCase().split('').map(c=>MORSE_MAP[c]||c).join(' '),
    decode: (s) => s.split(' ').map(c=>REVERSE_MORSE[c]||c).join('')
  },
  railfence: {
    name: 'Rail Fence', desc: 'Zig-zag transposition cipher.',
    requiresKey: true, keyLabel: 'Rails (Number)', defaultKey: '3',
    encode: (s, key) => {
      const rails = parseInt(key)||3; if(rails<2) return s;
      let fence = Array(rails).fill(0).map(()=>[]), rail=0, dir=1;
      for(let c of s){fence[rail].push(c);rail+=dir;if(rail===0||rail===rails-1)dir=-dir;}
      return fence.flat().join('');
    },
    decode: (s, key) => {
      const rails=parseInt(key)||3; if(rails<2) return s;
      const len=s.length;
      let fence=Array(rails).fill(0).map(()=>Array(len).fill(null)),rail=0,dir=1;
      for(let i=0;i<len;i++){fence[rail][i]='?';rail+=dir;if(rail===0||rail===rails-1)dir=-dir;}
      let idx=0;
      for(let r=0;r<rails;r++) for(let c=0;c<len;c++) if(fence[r][c]==='?'&&idx<len) fence[r][c]=s[idx++];
      let res='';rail=0;dir=1;
      for(let i=0;i<len;i++){res+=fence[rail][i];rail+=dir;if(rail===0||rail===rails-1)dir=-dir;}
      return res;
    }
  },
  vigenere: {
    name: 'Vigenère', desc: 'Polyalphabetic substitution using a keyword.',
    requiresKey: true, keyLabel: 'Secret Key (Text)', defaultKey: 'KEY',
    encode: (s,key) => {
      if(!key) return s; const k=key.toUpperCase().replace(/[^A-Z]/g,''); if(!k) return s;
      let ki=0;
      return s.replace(/[a-zA-Z]/g, c=>{const b=c<='Z'?65:97,sh=k[ki++%k.length].charCodeAt(0)-65;return String.fromCharCode(b+(c.charCodeAt(0)-b+sh)%26);});
    },
    decode: (s,key) => {
      if(!key) return s; const k=key.toUpperCase().replace(/[^A-Z]/g,''); if(!k) return s;
      let ki=0;
      return s.replace(/[a-zA-Z]/g, c=>{const b=c<='Z'?65:97,sh=k[ki++%k.length].charCodeAt(0)-65;return String.fromCharCode(b+(c.charCodeAt(0)-b-sh+26)%26);});
    }
  }
};

// ─── JWT Decoder ──────────────────────────────────────────────────────────────
function JWTDecoder() {
  const [token, setToken] = useState('');

  const decoded = useMemo(() => {
    if (!token.trim()) return null;
    const parts = token.trim().split('.');
    if (parts.length !== 3) return { error: 'Invalid JWT — must have 3 parts separated by dots.' };
    try {
      const decode = (str) => {
        const b64 = str.replace(/-/g,'+').replace(/_/g,'/');
        const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
        return JSON.parse(decodeURIComponent(escape(atob(padded))));
      };
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      const now = Math.floor(Date.now() / 1000);
      const expired = payload.exp ? payload.exp < now : null;
      const issuedAt = payload.iat ? new Date(payload.iat * 1000).toLocaleString() : null;
      const expiresAt = payload.exp ? new Date(payload.exp * 1000).toLocaleString() : null;
      return { header, payload, signature: parts[2], expired, issuedAt, expiresAt };
    } catch (e) {
      return { error: `Failed to decode: ${e.message}` };
    }
  }, [token]);

  const JsonBlock = ({ data }) => (
    <pre style={{
      background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)',
      borderRadius: 6, padding: 16, fontSize: 13, fontFamily: 'monospace',
      overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0
    }}>
      {JSON.stringify(data, null, 2)}
    </pre>
  );

  return (
    <div>
      <div style={{ marginBottom: 8 }}>
        <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>JWT Token</label>
        <textarea
          className="input glass-panel mono"
          rows={4}
          placeholder="Paste a JWT token here (eyJ...)"
          value={token}
          onChange={e => setToken(e.target.value)}
          style={{ fontSize: 13, resize: 'vertical' }}
        />
      </div>

      {decoded?.error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 6, color: '#f87171', fontSize: 13, marginTop: 16 }}>
          {decoded.error}
        </div>
      )}

      {decoded && !decoded.error && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>

          {/* Status bar */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {decoded.expired !== null && (
              <span className="badge glass-panel" style={{ borderColor: decoded.expired ? "rgba(239,68,68,0.4)" : "rgba(46, 204, 113, 0.4)", color: decoded.expired ? "#f87171" : "#2ecc71" }}>
                {decoded.expired ? '⚠ EXPIRED' : '✓ VALID (not expired)'}
              </span>
            )}
            {decoded.issuedAt && <span style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.5)', display: 'flex', alignItems: 'center' }}>Issued: {decoded.issuedAt}</span>}
            {decoded.expiresAt && <span style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.5)', display: 'flex', alignItems: 'center' }}>Expires: {decoded.expiresAt}</span>}
          </div>

          <div>
            <div className="gradient-text" style={{ fontWeight: 700, fontSize: 12, marginBottom: 6 }}>HEADER</div>
            <JsonBlock data={decoded.header} />
          </div>
          <div>
            <div className="gradient-text" style={{ fontWeight: 700, fontSize: 12, marginBottom: 6 }}>PAYLOAD</div>
            <JsonBlock data={decoded.payload} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 12, color: 'rgba(255, 255, 255, 0.6)', marginBottom: 6 }}>SIGNATURE (not verified — client-side only)</div>
            <div style={{ fontFamily: 'monospace', fontSize: 12, color: 'rgba(255, 255, 255, 0.6)', wordBreak: 'break-all', padding: '8px 12px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 6, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              {decoded.signature}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Subnet / CIDR Calculator ─────────────────────────────────────────────────
function SubnetCalc() {
  const [input, setInput] = useState('192.168.1.0/24');

  const result = useMemo(() => {
    try {
      const [ip, prefix] = input.trim().split('/');
      const prefixLen = parseInt(prefix);
      if (!ip || isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return null;

      const ipParts = ip.split('.').map(Number);
      if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return null;

      const ipInt = ipParts.reduce((acc, octet) => (acc << 8) | octet, 0) >>> 0;
      const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
      const network = (ipInt & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const firstHost = prefixLen < 31 ? network + 1 : network;
      const lastHost  = prefixLen < 31 ? broadcast - 1 : broadcast;
      const totalHosts = prefixLen >= 31 ? Math.pow(2, 32 - prefixLen) : Math.pow(2, 32 - prefixLen) - 2;

      const toIp = (n) => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');

      const isPrivate = (
        (ipInt >>> 24) === 10 ||
        ((ipInt >>> 16) === 0xAC10 && ((ipInt >>> 16) & 0xFFF0) === 0xAC10) ||
        ((ipInt >>> 16) === 0xC0A8)
      );

      return {
        network: toIp(network),
        broadcast: toIp(broadcast),
        mask: toIp(mask),
        wildcardMask: toIp(~mask >>> 0),
        firstHost: toIp(firstHost),
        lastHost: toIp(lastHost),
        totalHosts: totalHosts.toLocaleString(),
        prefixLen,
        isPrivate,
        ipClass: (ipInt >>> 28) >= 14 ? 'E' : (ipInt >>> 28) >= 12 ? 'D (Multicast)' : (ipInt >>> 24) >= 192 ? 'C' : (ipInt >>> 24) >= 128 ? 'B' : 'A',
      };
    } catch { return null; }
  }, [input]);

  const Row = ({ label, value, mono = true, badge }) => (
    <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
      <td style={{ padding: '8px 12px', color: 'rgba(255, 255, 255, 0.6)', fontWeight: 600, width: '40%' }}>{label}</td>
      <td style={{ padding: '8px 12px', fontFamily: mono ? 'monospace' : undefined }}>
        {badge ? <span className="badge glass-panel">{value}</span> : value}
      </td>
    </tr>
  );

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>IP Address / CIDR</label>
        <input
          className="input glass-panel mono"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/8"
        />
      </div>

      {result ? (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
          <tbody>
            <Row label="Network Address"   value={`${result.network}/${result.prefixLen}`} />
            <Row label="Subnet Mask"       value={result.mask} />
            <Row label="Wildcard Mask"     value={result.wildcardMask} />
            <Row label="Broadcast"         value={result.broadcast} />
            <Row label="First Host"        value={result.firstHost} />
            <Row label="Last Host"         value={result.lastHost} />
            <Row label="Usable Hosts"      value={result.totalHosts} />
            <Row label="IP Class"          value={result.ipClass} />
            <Row label="Private Range"     value={result.isPrivate ? 'Yes (RFC 1918)' : 'No (Public)'} mono={false} badge="glass-panel" />
          </tbody>
        </table>
      ) : (
        <div style={{ color: 'rgba(255, 255, 255, 0.5)', fontSize: 13, padding: 12 }}>
          Enter a valid CIDR notation like <code>192.168.1.0/24</code>
        </div>
      )}
    </div>
  );
}

// ─── Port Reference Database ──────────────────────────────────────────────────
const PORT_DB = [
  { port: 20,    proto: 'TCP', service: 'FTP Data',         risk: 'medium', notes: 'File Transfer Protocol data channel. Often disabled if not needed.' },
  { port: 21,    proto: 'TCP', service: 'FTP Control',      risk: 'high',   notes: 'Sends credentials in plaintext. Use SFTP instead.' },
  { port: 22,    proto: 'TCP', service: 'SSH',               risk: 'medium', notes: 'Secure shell. Common brute-force target if exposed publicly.' },
  { port: 23,    proto: 'TCP', service: 'Telnet',            risk: 'critical', notes: 'Transmits all data including passwords in plaintext. Never use.' },
  { port: 25,    proto: 'TCP', service: 'SMTP',              risk: 'medium', notes: 'Mail transfer. Open relays can be abused for spam.' },
  { port: 53,    proto: 'TCP/UDP', service: 'DNS',           risk: 'medium', notes: 'Domain resolution. Abuse vectors: amplification DDoS, tunneling, cache poisoning.' },
  { port: 67,    proto: 'UDP', service: 'DHCP Server',       risk: 'low',    notes: 'Dynamic IP assignment.' },
  { port: 68,    proto: 'UDP', service: 'DHCP Client',       risk: 'low',    notes: 'Rogue DHCP servers can redirect traffic.' },
  { port: 80,    proto: 'TCP', service: 'HTTP',              risk: 'medium', notes: 'Unencrypted web traffic. Vulnerable to MITM attacks.' },
  { port: 110,   proto: 'TCP', service: 'POP3',              risk: 'high',   notes: 'Email retrieval. Sends credentials in plaintext.' },
  { port: 123,   proto: 'UDP', service: 'NTP',               risk: 'medium', notes: 'Time sync. Used in amplification DDoS attacks.' },
  { port: 135,   proto: 'TCP', service: 'MS RPC',            risk: 'high',   notes: 'Microsoft RPC endpoint mapper. Exploited by Blaster worm.' },
  { port: 137,   proto: 'UDP', service: 'NetBIOS Name',      risk: 'high',   notes: 'Windows name resolution. Leaks network information.' },
  { port: 139,   proto: 'TCP', service: 'NetBIOS Session',   risk: 'high',   notes: 'Legacy Windows file sharing.' },
  { port: 143,   proto: 'TCP', service: 'IMAP',              risk: 'medium', notes: 'Email access. Use IMAPS (993) for encrypted version.' },
  { port: 389,   proto: 'TCP', service: 'LDAP',              risk: 'high',   notes: 'Directory services. Sends credentials unencrypted.' },
  { port: 443,   proto: 'TCP', service: 'HTTPS',             risk: 'low',    notes: 'Encrypted web traffic. Standard for secure web.' },
  { port: 445,   proto: 'TCP', service: 'SMB',               risk: 'critical', notes: 'Windows file sharing. Exploited by EternalBlue/WannaCry. Never expose to internet.' },
  { port: 465,   proto: 'TCP', service: 'SMTPS',             risk: 'low',    notes: 'SMTP over SSL. Secure mail submission.' },
  { port: 587,   proto: 'TCP', service: 'SMTP Submission',   risk: 'low',    notes: 'Authenticated SMTP. Standard for email clients.' },
  { port: 636,   proto: 'TCP', service: 'LDAPS',             risk: 'low',    notes: 'LDAP over SSL. Secure directory access.' },
  { port: 993,   proto: 'TCP', service: 'IMAPS',             risk: 'low',    notes: 'IMAP over SSL. Secure email access.' },
  { port: 995,   proto: 'TCP', service: 'POP3S',             risk: 'low',    notes: 'POP3 over SSL.' },
  { port: 1433,  proto: 'TCP', service: 'MSSQL',             risk: 'critical', notes: 'Microsoft SQL Server. Never expose directly to internet.' },
  { port: 1521,  proto: 'TCP', service: 'Oracle DB',         risk: 'critical', notes: 'Oracle database. Highly targeted.' },
  { port: 1337,  proto: 'TCP', service: 'LEET / C2',         risk: 'critical', notes: 'Known malware/C2 port. No legitimate service uses this.' },
  { port: 3306,  proto: 'TCP', service: 'MySQL',             risk: 'critical', notes: 'MySQL database. Frequently targeted for data theft.' },
  { port: 3389,  proto: 'TCP', service: 'RDP',               risk: 'critical', notes: 'Remote Desktop. Top target for ransomware. Never expose publicly.' },
  { port: 4444,  proto: 'TCP', service: 'Metasploit/C2',     risk: 'critical', notes: 'Default Metasploit listener. Indicates active exploitation.' },
  { port: 5432,  proto: 'TCP', service: 'PostgreSQL',        risk: 'critical', notes: 'PostgreSQL database. Restrict to localhost only.' },
  { port: 5900,  proto: 'TCP', service: 'VNC',               risk: 'critical', notes: 'Remote desktop. Weak auth, frequently exploited.' },
  { port: 5985,  proto: 'TCP', service: 'WinRM HTTP',        risk: 'high',   notes: 'Windows Remote Management. Used in lateral movement.' },
  { port: 5986,  proto: 'TCP', service: 'WinRM HTTPS',       risk: 'high',   notes: 'WinRM over SSL.' },
  { port: 6379,  proto: 'TCP', service: 'Redis',             risk: 'critical', notes: 'Redis cache. No auth by default. Exposed instances routinely compromised.' },
  { port: 6667,  proto: 'TCP', service: 'IRC',               risk: 'high',   notes: 'Internet Relay Chat. Historically used for botnet C2.' },
  { port: 8080,  proto: 'TCP', service: 'HTTP Alt',          risk: 'medium', notes: 'Common alternative HTTP port. Often used for dev servers or proxies.' },
  { port: 8443,  proto: 'TCP', service: 'HTTPS Alt',         risk: 'low',    notes: 'Alternative HTTPS port.' },
  { port: 8888,  proto: 'TCP', service: 'HTTP Alt / Jupyter',risk: 'medium', notes: 'Often Jupyter Notebook. Can expose code execution if misconfigured.' },
  { port: 9200,  proto: 'TCP', service: 'Elasticsearch',     risk: 'critical', notes: 'No auth by default. Massive data breaches from exposed clusters.' },
  { port: 27017, proto: 'TCP', service: 'MongoDB',           risk: 'critical', notes: 'No auth by default. Billions of records exposed historically.' },
  { port: 31337, proto: 'TCP', service: 'Back Orifice / C2', risk: 'critical', notes: 'Classic backdoor port. Any traffic here is malicious.' },
];

function PortReference() {
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return PORT_DB;
    return PORT_DB.filter(p =>
      String(p.port).includes(q) ||
      p.service.toLowerCase().includes(q) ||
      p.proto.toLowerCase().includes(q) ||
      p.risk.toLowerCase().includes(q) ||
      p.notes.toLowerCase().includes(q)
    );
  }, [search]);

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <input
          className="input glass-panel"
          placeholder="Search by port number, service name, protocol, or risk level..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>
      <div style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.5)', marginBottom: 12 }}>
        {filtered.length} of {PORT_DB.length} ports shown
      </div>
      <div style={{ overflow: 'auto', maxHeight: 520 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', background: 'transparent' }}>
              <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: 'rgba(255, 255, 255, 0.6)' }}>Port</th>
              <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: 'rgba(255, 255, 255, 0.6)' }}>Proto</th>
              <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: 'rgba(255, 255, 255, 0.6)' }}>Service</th>
              <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: 'rgba(255, 255, 255, 0.6)' }}>Risk</th>
              <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: 'rgba(255, 255, 255, 0.6)' }}>Notes</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(p => (
              <tr key={p.port} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontWeight: 700 }}>{p.port}</td>
                <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: 'rgba(255, 255, 255, 0.5)' }}>{p.proto}</td>
                <td style={{ padding: '8px 12px', fontWeight: 600 }}>{p.service}</td>
                <td style={{ padding: '8px 12px' }}>
                  <span className="badge glass-panel">{p.risk}</span>
                </td>
                <td style={{ padding: '8px 12px', color: 'rgba(255, 255, 255, 0.6)', maxWidth: 400 }}>{p.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Hash Generator ───────────────────────────────────────────────────────────
async function sha(algorithm, message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest(algorithm, msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2,'0')).join('');
}

function HashGenerator() {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState({});

  useEffect(() => {
    if (!input) { setHashes({}); return; }
    const compute = async () => {
      const [h1, h256, h384, h512] = await Promise.all([
        sha('SHA-1', input),
        sha('SHA-256', input),
        sha('SHA-384', input),
        sha('SHA-512', input),
      ]);
      setHashes({ 'SHA-1': h1, 'SHA-256': h256, 'SHA-384': h384, 'SHA-512': h512 });
    };
    compute();
  }, [input]);

  const copyHash = (val) => navigator.clipboard.writeText(val);

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>Input Text</label>
        <textarea
          className="input glass-panel mono"
          rows={4}
          placeholder="Enter text to hash..."
          value={input}
          onChange={e => setInput(e.target.value)}
          style={{ resize: 'vertical' }}
        />
      </div>
      <div style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.5)', marginBottom: 16 }}>
        ⚠ Client-side only — text never leaves your browser. MD5 is not supported by the Web Crypto API (it is cryptographically broken). Use SHA-256 or higher.
      </div>
      {Object.entries(hashes).map(([alg, hash]) => (
        <div key={alg} style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span className="gradient-text" style={{ fontWeight: 700, fontSize: 12 }}>{alg}</span>
            <button
              className="btn-glass"
              onClick={() => copyHash(hash)}
              style={{ padding: "4px 10px", fontSize: 11 }}
            >
              Copy
            </button>
          </div>
          <div style={{
            fontFamily: 'monospace', fontSize: 12, padding: '8px 12px',
            background: 'rgba(255, 255, 255, 0.02)', borderRadius: 6,
            border: '1px solid rgba(255, 255, 255, 0.05)', wordBreak: 'break-all', color: '#fff'
          }}>
            {hash}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Main Decipher Page ───────────────────────────────────────────────────────
const SECURITY_TOOLS = [
  { id: 'jwt',    name: 'JWT Decoder',        icon: '🔑', component: JWTDecoder },
  { id: 'subnet', name: 'Subnet Calculator',  icon: '🌐', component: SubnetCalc },
  { id: 'ports',  name: 'Port Reference',     icon: '🔌', component: PortReference },
  { id: 'hash',   name: 'Hash Generator',     icon: '#',  component: HashGenerator },
];

export default function Decipher() {
  const [tab, setTab] = useState('ciphers');           // 'ciphers' | 'tools'
  const [activeCipher, setActiveCipher] = useState('base64');
  const [activeTool, setActiveTool] = useState('jwt');
  const [mode, setMode] = useState('encode');
  const [input, setInput] = useState('');
  const [cipherKey, setCipherKey] = useState('');
  const [output, setOutput] = useState('');

  // Auto-run cipher
  useEffect(() => {
    if (tab !== 'ciphers') return;
    const tool = ciphers[activeCipher];
    if (tool.requiresKey && !cipherKey) setCipherKey(tool.defaultKey);
    if (!input) { setOutput(''); return; }
    const res = mode === 'encode' ? tool.encode(input, cipherKey) : tool.decode(input, cipherKey);
    setOutput(String(res));
  }, [input, activeCipher, mode, cipherKey, tab]);

  const copyOutput = () => { navigator.clipboard.writeText(output); };
  const swapIO = () => { setInput(output); setOutput(''); };

  const ActiveSecurityTool = SECURITY_TOOLS.find(t => t.id === activeTool)?.component || null;

  return (
    <div className="shell page-decipher animate-fade" style={{ maxWidth: 1400, marginTop: 20 }}>

      {/* Top tab switcher */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: 'rgba(255, 255, 255, 0.03)', padding: 6, borderRadius: 16, border: '1px solid rgba(255, 255, 255, 0.05)', width: 'fit-content', backdropFilter: 'blur(10px)' }}>
        {[{ id: 'ciphers', label: '🔒 Ciphers & Encoders' }, { id: 'tools', label: '🛠 Security Tools' }].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: '8px 20px', borderRadius: 10, border: '1px solid transparent', cursor: 'pointer',
              fontWeight: 600, fontSize: 13,
              background: tab === t.id ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
              color: tab === t.id ? '#fff' : 'rgba(255, 255, 255, 0.5)',
              transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── CIPHERS TAB ── */}
      {tab === 'ciphers' && (
        <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 24, minHeight: '70vh' }}>

          {/* Cipher sidebar */}
          <div className="card glass-panel animate-slide" style={{ padding: 0, overflow: 'hidden', height: 'fit-content' }}>
            <div style={{ padding: '16px 20px', background: 'transparent', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <h3 className="gradient-text" style={{ margin: 0, fontSize: 15 }}>Ciphers & Encoders</h3>
            </div>
            <div style={{ padding: 10 }}>
              {Object.keys(ciphers).map(key => (
                <button
                  key={key}
                  onClick={() => { setActiveCipher(key); setCipherKey(ciphers[key].defaultKey || ''); setInput(''); setOutput(''); }}
                  style={{
                    display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'flex-start', marginBottom: 6,
                    padding: '10px 14px', borderRadius: '8px',
                    background: activeCipher === key ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
                    color: activeCipher === key ? 'white' : 'rgba(255, 255, 255, 0.6)',
                    border: '1px solid transparent',
                    fontWeight: 600, fontSize: 13, cursor: 'pointer',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {ciphers[key].name}
                </button>
              ))}
            </div>
          </div>

          {/* Cipher workspace */}
          <div className="card glass-panel hover-card animate-slide animate-delay-1" style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ marginBottom: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 className="gradient-text" style={{ fontSize: 22, margin: 0 }}>{ciphers[activeCipher].name}</h2>
                <p style={{ margin: 0, color: 'rgba(255, 255, 255, 0.5)', fontSize: 13 }}>{ciphers[activeCipher].desc}</p>
              </div>
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: 4, borderRadius: 8, display: 'flex', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                {['encode','decode'].map(m => (
                  <button key={m} onClick={() => setMode(m)} style={{
                    padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer', fontWeight: 600,
                    background: mode === m ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
                    color: mode === m ? '#fff' : 'rgba(255, 255, 255, 0.4)',
                    boxShadow: mode === m ? '0 2px 8px rgba(0,0,0,0.2)' : 'none',
                    textTransform: 'capitalize',
                    transition: 'all 0.2s ease'
                  }}>{m}</button>
                ))}
              </div>
            </div>

            {ciphers[activeCipher].requiresKey && (
              <div style={{ marginBottom: 16 }}>
                <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>{ciphers[activeCipher].keyLabel}</label>
                <input className="input glass-panel" value={cipherKey} onChange={e => setCipherKey(e.target.value)} placeholder={ciphers[activeCipher].defaultKey} />
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: 12, flex: 1, alignItems: 'start' }}>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>Input</label>
                <textarea className="input glass-panel mono" style={{ flex: 1, resize: 'none', minHeight: 380, fontSize: 13, lineHeight: 1.6 }}
                  placeholder="Paste text here..." value={input} onChange={e => setInput(e.target.value)} />
              </div>

              {/* Swap button */}
              <div style={{ display: 'flex', alignItems: 'center', paddingTop: 28 }}>
                <button className="btn-glass" onClick={swapIO} title="Swap input and output" style={{ padding: '10px 12px', borderRadius: '50%' }}>⇄</button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <label className="label" style={{ color: 'rgba(255, 255, 255, 0.6)' }}>Result</label>
                  <button className="btn-glass" onClick={copyOutput} style={{ padding: '2px 8px', fontSize: 11 }}>Copy</button>
                </div>
                <textarea className="input glass-panel mono" readOnly style={{ flex: 1, resize: 'none', minHeight: 380, fontSize: 13, lineHeight: 1.6, background: 'rgba(255, 255, 255, 0.02)' }}
                  placeholder="Result will appear here..." value={output} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── SECURITY TOOLS TAB ── */}
      {tab === 'tools' && (
        <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 24, minHeight: '70vh' }}>

          {/* Tools sidebar */}
          <div className="card glass-panel" style={{ padding: 0, overflow: 'hidden', height: 'fit-content' }}>
            <div style={{ padding: '16px 20px', background: 'transparent', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <h3 className="gradient-text" style={{ margin: 0, fontSize: 15 }}>Security Tools</h3>
            </div>
            <div style={{ padding: 10 }}>
              {SECURITY_TOOLS.map(t => (
                <button key={t.id} onClick={() => setActiveTool(t.id)} 
                  style={{
                    display: 'flex', alignItems: 'center', width: '100%', justifyContent: 'flex-start', marginBottom: 6,
                    padding: '10px 14px', borderRadius: '8px', cursor: 'pointer',
                    background: activeTool === t.id ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
                    color: activeTool === t.id ? 'white' : 'rgba(255, 255, 255, 0.6)',
                    border: '1px solid transparent',
                    fontWeight: 600, fontSize: 13, gap: 8,
                    transition: 'all 0.2s ease'
                  }}
                >
                  <span>{t.icon}</span> {t.name}
                </button>
              ))}
            </div>
          </div>

          {/* Active tool */}
          <div className="card glass-panel hover-card">
            <div style={{ marginBottom: 20, paddingBottom: 16, borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <h2 className="gradient-text" style={{ fontSize: 20, margin: 0 }}>
                {SECURITY_TOOLS.find(t => t.id === activeTool)?.icon}{' '}
                {SECURITY_TOOLS.find(t => t.id === activeTool)?.name}
              </h2>
            </div>
            {ActiveSecurityTool && <ActiveSecurityTool />}
          </div>
        </div>
      )}
    </div>
  );
}