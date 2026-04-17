# IntelliCloud

**A lightweight Security Operations Platform for real-time threat monitoring, analysis, and investigation.**

Built as a Senior Capstone Project by Raul Cortinas and Bryan Kahl.

---

## What It Is

IntelliCloud is a web-based cybersecurity platform that ingests network traffic and security event data, analyzes it for suspicious behavior, and presents findings through interactive dashboards, alerts, and investigation workflows. It is designed to function like an entry-level fusion of Wireshark, a SIEM dashboard, and a threat intelligence workstation — all in one platform.

---

## Key Features

### Live Traffic Monitoring
- Real-time packet capture via a Python/Scapy sensor agent
- Wireshark-style event stream showing source/destination IPs, protocols, ports, TCP flags, DNS queries, ARP activity, and ICMP
- Flow aggregation and port-scan detection
- ARP spoofing detection with live alerts
- C2 beaconing pattern detection
- Start/stop capture directly from the dashboard UI

### Threat Detection & Alerting
- Automatic threat scoring on ingested traffic
- Detection types: inbound admin port exposure, port scans, C2 indicators, DNS anomalies, beaconing, exposed services
- Alert management with Acknowledge and Close workflows
- IP blocklist support

### AI-Powered Analysis
- Click any traffic event to open an AI analyst panel (powered by Gemini 2.0 Flash)
- Context-aware prompts tailored to each event type — ARP spoofing, DNS responses, TCP RST, flow summaries, ICMP, and more
- Follow-up conversation support for deeper investigation

### Case Management
- Open, track, and close security investigation cases
- Investigation timeline with notes, actions, and escalations
- Priority and status tracking (Open / Investigating / Closed)
- Filter cases by status, priority, and keyword

### Security Tools (Built-in Threat Intelligence)
No need to leave the platform to investigate. All tools are available in one tab:
- **IP Intelligence** — unified lookup across AbuseIPDB, VirusTotal, and IPInfo
- **DNS Interrogation** — full record lookup (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)
- **WHOIS** — domain registration and registrar information
- **File Hash Lookup** — VirusTotal hash check (MD5, SHA1, SHA256)
- **URL Scanner** — redirect chain analysis, typosquatting detection, Google Safe Browsing
- **CVE Search** — NIST NVD vulnerability search by keyword or CVE ID
- **SSL/TLS Inspector** — certificate validity, cipher strength, SANs, expiry, and grading

### Decipher & Encoder Toolkit
- Base64, Hex, Binary, URL, HTML Entity encoding/decoding
- ROT13, Atbash, Vigenère, Rail Fence, Morse Code ciphers
- JWT Decoder with expiry and claim inspection
- Subnet / CIDR Calculator
- Port Reference Database (40+ ports with risk levels and attack notes)
- SHA Hash Generator (SHA-1, SHA-256, SHA-384, SHA-512)

### PCAP Analysis
- Upload `.pcap` files and extract packet-level detail
- Protocol breakdown, flow grouping, top talkers
- Export filtered results as CSV

### Log Analyzer
- Upload and parse log files
- Severity classification, IP extraction, timestamp parsing
- Filter by severity, search by keyword

### Devices / Asset Visibility
- Track network assets with IP, display name, trust status, and notes
- Last seen timestamps and activity context

### Secure Multi-User Access
- Firebase Authentication (login, register, idle session timeout)
- Role-based access control
- Multi-tenant client separation with API key authentication

---

## Tech Stack

**Frontend**
- React 18 with Vite
- Firebase Authentication
- Server-Sent Events (SSE) for live traffic streaming
- Electron (optional desktop app wrapper)

**Backend**
- Python Flask with Gunicorn
- Firebase Admin SDK for token verification
- Flask-Limiter for rate limiting
- GeoIP2 / MaxMind for IP geolocation
- Google Gemini 2.0 Flash for AI analysis
- Scapy for packet capture

**Database**
- PostgreSQL (AWS RDS in production, local Docker container for development)
- psycopg2 with connection pooling

**Infrastructure**
- Docker Compose (backend, frontend, PostgreSQL, Redis)
- Redis for rate limiting storage
- GeoLite2 databases for IP geolocation and ASN lookup
