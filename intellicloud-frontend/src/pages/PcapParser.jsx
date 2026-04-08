import React from "react";

const MAX_BROWSER_FILE_MB = 40;

function bytesToHuman(bytes) {
    const n = Number(bytes || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
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

function topByteCounts(items, keyFn, byteFn, limit = 8) {
    const map = new Map();

    for (const item of items) {
        const key = keyFn(item);
        if (!key) continue;
        map.set(key, (map.get(key) || 0) + Number(byteFn(item) || 0));
    }

    return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, bytes]) => ({ key, bytes }));
}

function downloadCsv(rows, filename) {
    const header = [
    "index",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "length",
    "info",
    ];

    const csv = [
    header.join(","),
    ...rows.map((r) =>
        [
        r.index,
        r.timestamp,
        r.srcIp,
        r.dstIp,
        r.srcPort,
        r.dstPort,
        r.protocol,
        r.length,
        r.info,
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

function groupFlows(packets) {
    const map = new Map();

    for (const p of packets) {
        const a = `${p.srcIp}:${p.srcPort || "-"}`;
        const b = `${p.dstIp}:${p.dstPort || "-"}`;
        const ordered = [a, b].sort();
        const key = `${ordered[0]} <-> ${ordered[1]} [${p.protocol}]`;

        const current = map.get(key) || {
            key,
            protocol: p.protocol,
            left: ordered[0],
            right: ordered[1],
            packets: 0,
            bytes: 0,
            firstTs: p.timestamp,
            lastTs: p.timestamp,
            sampleInfo: p.info,
        };

        current.packets += 1;
        current.bytes += Number(p.length || 0);
        current.lastTs = p.timestamp || current.lastTs;

        map.set(key, current);
    }

    return Array.from(map.values()).sort((a, b) => b.bytes - a.bytes);
}

function findAsciiStringsFromBytes(bytes, minLen = 4) {
    const results = [];
    let current = "";

    for (const byte of bytes) {
        if (byte >= 32 && byte <= 126) {
            current += String.fromCharCode(byte);
        } else {
            if (current.length >= minLen) results.push(current);
            current = "";
        }
    }

    if (current.length >= minLen) results.push(current);

    return results;
}

function getUint16(bytes, offset, littleEndian = false) {
    if (offset + 1 >= bytes.length) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getUint16(offset, littleEndian);
}

function getUint32(bytes, offset, littleEndian = false) {
    if (offset + 3 >= bytes.length) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getUint32(offset, littleEndian);
}

function formatTimestamp(seconds, micros = 0) {
    const ms = seconds * 1000 + Math.floor(micros / 1000);
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return "";
    return d.toISOString();
}

function readCStringLikeDomain(bytes, start) {
    const labels = [];
    let offset = start;

    while (offset < bytes.length) {
    const len = bytes[offset];
    if (len === 0) {
        offset += 1;
        break;
    }

    if (len > 63 || offset + 1 + len > bytes.length) break;

    const labelBytes = bytes.slice(offset + 1, offset + 1 + len);
    const label = Array.from(labelBytes).map((b) => String.fromCharCode(b)).join("");
    labels.push(label);
    offset += 1 + len;
    }

    return {
    name: labels.join("."),
    nextOffset: offset,
    };
}

function parseDnsQuestion(payload) {
    if (!payload || payload.length < 12) return null;

    const qdcount = getUint16(payload, 4);
    if (!qdcount || qdcount < 1) return null;

    const { name, nextOffset } = readCStringLikeDomain(payload, 12);
    if (!name) return null;

    const qtype = getUint16(payload, nextOffset);
    const qclass = getUint16(payload, nextOffset + 2);

    return {
    query: name,
    qtype: qtype ?? null,
    qclass: qclass ?? null,
    };
}

function parseHttpText(asciiText) {
    const text = String(asciiText || "");
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (!lines.length) return null;

    const first = lines[0];

    const reqMatch = first.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP\/[\d.]+$/i);
    if (reqMatch) {
        const hostHeader = lines.find((l) => /^Host:/i.test(l));
        const host = hostHeader ? hostHeader.replace(/^Host:\s*/i, "").trim() : "";
        return {
            kind: "http_request",
            method: reqMatch[1].toUpperCase(),
            path: reqMatch[2],
            host,
            statusCode: null,
            summary: `${reqMatch[1].toUpperCase()} ${reqMatch[2]}${host ? ` @ ${host}` : ""}`,
        };
    }

    const resMatch = first.match(/^HTTP\/[\d.]+\s+(\d{3})\s*(.*)$/i);
    if (resMatch) {
        return {
            kind: "http_response",
            method: "",
            path: "",
            host: "",
            statusCode: resMatch[1],
            summary: `HTTP ${resMatch[1]} ${resMatch[2] || ""}`.trim(),
        };
    }

    return null;
}

function guessPacketInfo({
    protocol,
    srcPort,
    dstPort,
    dns,
    http,
    telnetLike,
    ftpLike,
    tcpFlags,
    }) {
        if (dns?.query) return `DNS query: ${dns.query}`;
        if (http?.summary) return http.summary;
        if (ftpLike) return ftpLike;
        if (telnetLike) return telnetLike;
        if (protocol === "TCP" && tcpFlags) return `TCP flags: ${tcpFlags}`;
        if (protocol === "ICMP") return "ICMP traffic";
        if (protocol === "ARP") return "ARP frame";
        if (srcPort || dstPort) return `Port ${srcPort || "-"} → ${dstPort || "-"}`;
        return protocol || "Packet";
    }

function protocolExplainers() {
    return [
    {
        title: "Top Source IPs",
        text: "Shows which systems sent the most packets in this capture.",
    },
    {
        title: "Top Destination IPs",
        text: "Shows where most of the traffic was going.",
    },
    {
        title: "Protocols",
        text: "Shows the main network protocols observed in the capture.",
    },
    {
        title: "Flows",
        text: "Groups related packets into conversations between two endpoints.",
    },
    {
        title: "DNS Pairs",
        text: "Shows domain lookups and their matching responses when visible.",
    },
    {
        title: "HTTP Pairs",
        text: "Pairs plaintext web requests with their responses when possible.",
    },
    {
        title: "Authentication Clues",
        text: "Highlights usernames, commands, or login-related content visible in plaintext protocols.",
    },
    {
        title: "Outliers",
        text: "Flags traffic that stands out, such as repeated failures, unusual ports, or very dominant hosts.",
    },
    ];
}

function looksLikeFlag(str) {
    const s = String(str || "");
    return (
        /flag\{[^}]+\}/i.test(s) ||
        /\bctf\b/i.test(s) ||
        /\btoken\b/i.test(s) ||
        /\bsecret\b/i.test(s) ||
        /\bpassword\b/i.test(s) ||
        /\bapikey\b/i.test(s)
    );
}

function pairDnsConversations(packets) {
    const pending = new Map();
    const pairs = [];

for (const p of packets) {
    if (!p.dns?.query) continue;

    const txId = p.dns.txId ?? "-";
    const query = p.dns.query;
    const keyForward = `${p.srcIp}|${p.dstIp}|${txId}|${query}`;
    const keyReverse = `${p.dstIp}|${p.srcIp}|${txId}|${query}`;

    if (p.dns.isResponse) {
        const req = pending.get(keyReverse);
        if (req) {
            pairs.push({
                query,
                txId,
                srcIp: req.srcIp,
                dstIp: req.dstIp,
                requestTime: req.timestamp,
                responseTime: p.timestamp,
                latencyMs: req.timestamp && p.timestamp
                ? Math.max(0, new Date(p.timestamp) - new Date(req.timestamp))
                : null,
                info: p.info,
            });
        pending.delete(keyReverse);
        }
    } else {
        pending.set(keyForward, p);
    }
}

return pairs;
}

function pairHttpConversations(packets) {
    const pending = new Map();
    const pairs = [];

    for (const p of packets) {
    if (!p.http) continue;

    const key = `${p.srcIp}:${p.srcPort || "-"}>${p.dstIp}:${p.dstPort || "-"} [${p.protocol}]`;
    const reverseKey = `${p.dstIp}:${p.dstPort || "-"}>${p.srcIp}:${p.srcPort || "-"} [${p.protocol}]`;

    if (p.http.kind === "http_request") {
        pending.set(key, p);
        continue;
    }

    if (p.http.kind === "http_response") {
        const req = pending.get(reverseKey);
        if (req) {
        pairs.push({
            method: req.http.method,
            host: req.http.host,
            path: req.http.path,
            statusCode: p.http.statusCode || "",
            srcIp: req.srcIp,
            dstIp: req.dstIp,
            requestTime: req.timestamp,
            responseTime: p.timestamp,
            latencyMs: req.timestamp && p.timestamp
            ? Math.max(0, new Date(p.timestamp) - new Date(req.timestamp))
            : null,
        });
        pending.delete(reverseKey);
        }
    }
    }

return pairs;
}

async function parsePcapFile(file) {
    const fileBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(fileBuffer);

    if (bytes.length < 24) {
        throw new Error("File is too small to be a valid PCAP.");
    }

    const magicBE = getUint32(bytes, 0, false);
    const magicLE = getUint32(bytes, 0, true);

    let littleEndian = false;
    let isPcapNg = false;

    if (magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d) {
        littleEndian = false;
    } else if (magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d) {
        littleEndian = true;
    } else if (magicBE === 0x0a0d0d0a || magicLE === 0x0a0d0d0a) {
        isPcapNg = true;
    } else {
    throw new Error("Unsupported capture format. This version supports classic PCAP. PCAPNG support is not yet implemented.");
    }

    if (isPcapNg) {
        throw new Error("PCAPNG is not yet supported in this first version. Use classic .pcap for now.");
    }

    const snaplen = getUint32(bytes, 16, littleEndian);
    const network = getUint32(bytes, 20, littleEndian);

    let offset = 24;
    const packets = [];
    let index = 0;

    while (offset + 16 <= bytes.length) {
    const tsSec = getUint32(bytes, offset, littleEndian);
    const tsUsec = getUint32(bytes, offset + 4, littleEndian);
    const inclLen = getUint32(bytes, offset + 8, littleEndian);
    const origLen = getUint32(bytes, offset + 12, littleEndian);

    if (
        tsSec == null ||
        tsUsec == null ||
        inclLen == null ||
        origLen == null ||
        inclLen < 0 ||
        offset + 16 + inclLen > bytes.length
    ) {
        break;
    }

    const packetBytes = bytes.slice(offset + 16, offset + 16 + inclLen);
    const timestamp = formatTimestamp(tsSec, tsUsec);

    const parsed = dissectPacket(packetBytes, {
        timestamp,
        index: index + 1,
        network,
    });

    packets.push({
        index: index + 1,
        timestamp,
        length: inclLen,
        originalLength: origLen,
        rawBytes: packetBytes,
        ...parsed,
    });

    offset += 16 + inclLen;
    index += 1;
    }

    return {
    packets,
    snaplen,
    network,
    };
}

function dissectPacket(packetBytes, meta) {
    const result = {
    srcIp: "",
    dstIp: "",
    srcPort: "",
    dstPort: "",
    protocol: "Unknown",
    info: "Unknown packet",
    layers: [],
    dns: null,
    http: null,
    ftp: "",
    telnet: "",
    authHints: [],
    fileActivityHints: [],
    strings: [],
    tcpFlags: "",
};

    const strings = findAsciiStringsFromBytes(packetBytes, 4);
    result.strings = strings;

    if (meta.network !== 1) {
    result.info = `Unsupported link type ${meta.network}`;
    return result;
    }

    if (packetBytes.length < 14) {
    result.info = "Truncated Ethernet frame";
    return result;
    }

    const etherType = getUint16(packetBytes, 12, false);
    result.layers.push({
    name: "Ethernet",
    explanation: "The Ethernet header identifies the frame type on the local link.",
    fields: [
        { name: "EtherType", value: etherType != null ? `0x${etherType.toString(16)}` : "—", offset: "12-13" },
    ],
    });

    if (etherType === 0x0800 && packetBytes.length >= 34) {
    const ipStart = 14;
    const versionIhl = packetBytes[ipStart];
    const ihl = (versionIhl & 0x0f) * 4;
    const protocolNum = packetBytes[ipStart + 9];
    const srcIp = Array.from(packetBytes.slice(ipStart + 12, ipStart + 16)).join(".");
    const dstIp = Array.from(packetBytes.slice(ipStart + 16, ipStart + 20)).join(".");

    result.srcIp = srcIp;
    result.dstIp = dstIp;

    result.layers.push({
        name: "IPv4",
        explanation: "The IPv4 header identifies the source, destination, and transport protocol.",
        fields: [
        { name: "Source IP", value: srcIp, offset: `${ipStart + 12}-${ipStart + 15}` },
        { name: "Destination IP", value: dstIp, offset: `${ipStart + 16}-${ipStart + 19}` },
        { name: "Protocol", value: String(protocolNum), offset: `${ipStart + 9}` },
        ],
    });

    const transportStart = ipStart + ihl;

    if (protocolNum === 6 && packetBytes.length >= transportStart + 20) {
        result.protocol = "TCP";

        const srcPort = getUint16(packetBytes, transportStart, false);
        const dstPort = getUint16(packetBytes, transportStart + 2, false);
        const dataOffset = ((packetBytes[transportStart + 12] >> 4) & 0x0f) * 4;
        const flagsByte = packetBytes[transportStart + 13];
        const payloadStart = transportStart + dataOffset;
        const payload = packetBytes.slice(payloadStart);

        result.srcPort = srcPort ?? "";
        result.dstPort = dstPort ?? "";

        const flags = [];
        if (flagsByte & 0x01) flags.push("FIN");
        if (flagsByte & 0x02) flags.push("SYN");
        if (flagsByte & 0x04) flags.push("RST");
        if (flagsByte & 0x08) flags.push("PSH");
        if (flagsByte & 0x10) flags.push("ACK");
        if (flagsByte & 0x20) flags.push("URG");
        result.tcpFlags = flags.join(", ");

        result.layers.push({
        name: "TCP",
        explanation: "TCP carries reliable conversations between ports and is used by protocols like HTTP, FTP, and Telnet.",
        fields: [
            { name: "Source Port", value: String(srcPort ?? "—"), offset: `${transportStart}-${transportStart + 1}` },
            { name: "Destination Port", value: String(dstPort ?? "—"), offset: `${transportStart + 2}-${transportStart + 3}` },
            { name: "Flags", value: result.tcpFlags || "—", offset: `${transportStart + 13}` },
        ],
        });

        const ascii = findAsciiStringsFromBytes(payload, 3).join("\n");
        const http = parseHttpText(ascii);
        if (http) {
        result.http = http;
        }

        if ([21, 20].includes(Number(srcPort)) || [21, 20].includes(Number(dstPort))) {
        const ftpCmd = ascii.split(/\r?\n/).find(Boolean) || "";
        result.ftp = ftpCmd || "FTP activity";
        if (/USER\s+/i.test(ftpCmd)) result.authHints.push(`FTP username observed: ${ftpCmd.trim()}`);
        if (/PASS\s+/i.test(ftpCmd)) result.authHints.push(`FTP password-like command observed: ${ftpCmd.trim()}`);
        if (/\b(STOR|RETR|DELE|RNFR|RNTO)\b/i.test(ftpCmd)) {
            result.fileActivityHints.push(`FTP file activity observed: ${ftpCmd.trim()}`);
        }
        }

        if ([23].includes(Number(srcPort)) || [23].includes(Number(dstPort))) {
            const telnetLine = ascii.split(/\r?\n/).find(Boolean) || "";
            result.telnet = telnetLine || "Telnet traffic";
        if (/login|username|password/i.test(ascii)) {
            result.authHints.push("Possible Telnet authentication content observed.");
        }
        if (/\brm\b|\bdel\b|\bcopy\b|\bmv\b|\bls\b|\bcat\b/i.test(ascii)) {
            result.fileActivityHints.push("Possible shell/file command observed in Telnet payload.");
        }
        }

        if (/login|user=|username=|password=|passwd=|auth/i.test(ascii)) {
            result.authHints.push("Possible authentication-related plaintext observed.");
        }

        if (/\bdelete\b|\bremove\b|\bupload\b|\bdownload\b|\bstore\b|\bwrite\b|\bsave\b/i.test(ascii)) {
            result.fileActivityHints.push("Possible file operation keywords observed in payload.");
        }
    } else if (protocolNum === 17 && packetBytes.length >= transportStart + 8) {
        result.protocol = "UDP";

        const srcPort = getUint16(packetBytes, transportStart, false);
        const dstPort = getUint16(packetBytes, transportStart + 2, false);
        const payload = packetBytes.slice(transportStart + 8);

        result.srcPort = srcPort ?? "";
        result.dstPort = dstPort ?? "";

        result.layers.push({
        name: "UDP",
        explanation: "UDP carries lightweight datagrams and is commonly used by DNS and some application traffic.",
        fields: [
            { name: "Source Port", value: String(srcPort ?? "—"), offset: `${transportStart}-${transportStart + 1}` },
            { name: "Destination Port", value: String(dstPort ?? "—"), offset: `${transportStart + 2}-${transportStart + 3}` },
        ],
        });

        if (Number(srcPort) === 53 || Number(dstPort) === 53) {
            const dns = parseDnsQuestion(payload);
            if (dns) {
                const txId = getUint16(payload, 0, false);
                const flags = getUint16(payload, 2, false);
                const isResponse = Boolean(flags && (flags & 0x8000));

                result.dns = {
                ...dns,
                txId: txId ?? null,
                isResponse,
                };

                result.layers.push({
                name: "DNS",
                explanation: "DNS maps human-readable names to addresses and can show what domains were requested.",
                fields: [
                    { name: "Query", value: dns.query || "—", offset: "payload" },
                    { name: "Transaction ID", value: String(txId ?? "—"), offset: "payload 0-1" },
                    { name: "Response", value: isResponse ? "Yes" : "No", offset: "payload 2-3" },
                    ],
                });
            }
        }
    } else if (protocolNum === 1) {
        result.protocol = "ICMP";
        result.layers.push({
        name: "ICMP",
        explanation: "ICMP includes ping requests and replies and basic network error signaling.",
        fields: [],
        });
    }
    } else if (etherType === 0x0806) {
        result.protocol = "ARP";
        result.layers.push({
            name: "ARP",
            explanation: "ARP resolves local IP addresses to MAC addresses on the LAN.",
            fields: [],
    });
    } else if (etherType === 0x86dd) {
        result.protocol = "IPv6";
        result.info = "IPv6 packet detected. Detailed IPv6 parsing is not yet implemented in this version.";
    }

    result.info = guessPacketInfo({
        protocol: result.protocol,
        srcPort: result.srcPort,
        dstPort: result.dstPort,
        dns: result.dns,
        http: result.http,
        telnetLike: result.telnet,
        ftpLike: result.ftp,
        tcpFlags: result.tcpFlags,
    });

    return result;
}

function buildFindings(packets, flows, dnsPairs, httpPairs) {
    const findings = [];

    const uniqueSrc = new Set(packets.map((p) => p.srcIp).filter(Boolean)).size;
    const uniqueDst = new Set(packets.map((p) => p.dstIp).filter(Boolean)).size;
    const totalBytes = packets.reduce((sum, p) => sum + Number(p.length || 0), 0);

    if (packets.length > 0) {
        findings.push(`The capture contains ${packets.length} packets totaling ${bytesToHuman(totalBytes)}.`);
    }

    if (uniqueSrc > 0 || uniqueDst > 0) {
        findings.push(`The capture includes ${uniqueSrc} unique source IPs and ${uniqueDst} unique destination IPs.`);
    }

    const topSource = topCounts(packets, (p) => p.srcIp, 1)[0];
        if (topSource) {
        findings.push(`Source IP ${topSource.key} appears most often with ${topSource.count} packets.`);
    }

    const topFlow = flows[0];
        if (topFlow) {
        findings.push(`The busiest flow is ${topFlow.key} with ${topFlow.packets} packets and ${bytesToHuman(topFlow.bytes)} transferred.`);
    }

    const synHeavy = packets.filter((p) => p.protocol === "TCP" && /\bSYN\b/.test(p.tcpFlags || "")).length;
    const rstHeavy = packets.filter((p) => p.protocol === "TCP" && /\bRST\b/.test(p.tcpFlags || "")).length;

    if (synHeavy >= 10) {
        findings.push(`A high number of SYN packets (${synHeavy}) may indicate scanning or many incomplete TCP connection attempts.`);
    }

    if (rstHeavy >= 5) {
        findings.push(`Multiple TCP reset packets (${rstHeavy}) were observed, which can indicate aborted or refused connections.`);
    }

    const cleartextAuth = packets.filter((p) => (p.authHints || []).length > 0);
        if (cleartextAuth.length > 0) {
        findings.push(`${cleartextAuth.length} packets contained possible plaintext authentication clues.`);
    }

    const fileActivity = packets.filter((p) => (p.fileActivityHints || []).length > 0);
        if (fileActivity.length > 0) {
        findings.push(`${fileActivity.length} packets contained possible file operation clues such as upload, delete, or store actions.`);
    }

    if (dnsPairs.length > 0) {
        findings.push(`${dnsPairs.length} DNS query/response pairs were matched.`);
    }

    if (httpPairs.length > 0) {
        findings.push(`${httpPairs.length} plaintext HTTP request/response pairs were matched.`);
    }

    const suspiciousStrings = packets
    .flatMap((p) => p.strings || [])
    .filter((s) => looksLikeFlag(s));

    if (suspiciousStrings.length > 0) {
        findings.push(`Visible payload strings included ${suspiciousStrings.length} possible flag, token, password, or secret indicators.`);
    }

    return findings.slice(0, 10);
}

export default function PcapParser() {
    const [fileName, setFileName] = React.useState("");
    const [packets, setPackets] = React.useState([]);
    const [flows, setFlows] = React.useState([]);
    const [dnsPairs, setDnsPairs] = React.useState([]);
    const [httpPairs, setHttpPairs] = React.useState([]);
    const [findings, setFindings] = React.useState([]);
    const [loading, setLoading] = React.useState(false);
    const [loadError, setLoadError] = React.useState("");
    const [selectedPacket, setSelectedPacket] = React.useState(null);

    const [search, setSearch] = React.useState("");
    const [protocolFilter, setProtocolFilter] = React.useState("all");
    const [ipFilter, setIpFilter] = React.useState("");

    const handleFile = async (file) => {
    if (!file) return;

    if (file.size > MAX_BROWSER_FILE_MB * 1024 * 1024) {
        setLoadError(
        `This file is ${(file.size / (1024 * 1024)).toFixed(1)} MB, which is above the current browser-analysis limit of ${MAX_BROWSER_FILE_MB} MB. Large-file backend support can be added later.`
        );
        setFileName(file.name);
        setPackets([]);
        setFlows([]);
        setDnsPairs([]);
        setHttpPairs([]);
        setFindings([]);
        return;
    }

    try {
        setLoading(true);
        setLoadError("");
        setFileName(file.name);

        const parsed = await parsePcapFile(file);

        const nextPackets = parsed.packets;
        const nextFlows = groupFlows(nextPackets);
        const nextDnsPairs = pairDnsConversations(nextPackets);
        const nextHttpPairs = pairHttpConversations(nextPackets);
        const nextFindings = buildFindings(nextPackets, nextFlows, nextDnsPairs, nextHttpPairs);

        setPackets(nextPackets);
        setFlows(nextFlows);
        setDnsPairs(nextDnsPairs);
        setHttpPairs(nextHttpPairs);
        setFindings(nextFindings);
        setSelectedPacket(null);
    } catch (error) {
        setLoadError(String(error?.message || error));
        setPackets([]);
        setFlows([]);
        setDnsPairs([]);
        setHttpPairs([]);
        setFindings([]);
        setSelectedPacket(null);
    } finally {
        setLoading(false);
    }
    };

    const onFileChange = (e) => {
    const file = e.target.files?.[0];
    handleFile(file);
    };

    const filteredPackets = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    const ipQ = ipFilter.trim().toLowerCase();

    return packets.filter((p) => {
        const matchesSearch =
        !q ||
        String(p.info || "").toLowerCase().includes(q) ||
        String(p.protocol || "").toLowerCase().includes(q) ||
        String(p.srcIp || "").toLowerCase().includes(q) ||
        String(p.dstIp || "").toLowerCase().includes(q) ||
        String(p.http?.summary || "").toLowerCase().includes(q) ||
        (p.strings || []).some((s) => s.toLowerCase().includes(q));

        const matchesProtocol =
        protocolFilter === "all" ? true : String(p.protocol || "").toLowerCase() === protocolFilter;

        const matchesIp =
        !ipQ ||
        String(p.srcIp || "").toLowerCase().includes(ipQ) ||
        String(p.dstIp || "").toLowerCase().includes(ipQ);

        return matchesSearch && matchesProtocol && matchesIp;
    });
    }, [packets, search, protocolFilter, ipFilter]);

    const summary = React.useMemo(() => {
    const totalPackets = packets.length;
    const totalBytes = packets.reduce((sum, p) => sum + Number(p.length || 0), 0);
    const uniqueSrcIps = new Set(packets.map((p) => p.srcIp).filter(Boolean)).size;
    const uniqueDstIps = new Set(packets.map((p) => p.dstIp).filter(Boolean)).size;
    const protocols = new Set(packets.map((p) => p.protocol).filter(Boolean)).size;
    const authHints = packets.reduce((sum, p) => sum + (p.authHints?.length || 0), 0);
    const fileHints = packets.reduce((sum, p) => sum + (p.fileActivityHints?.length || 0), 0);

    let durationMs = 0;
    if (packets.length >= 2) {
        const first = new Date(packets[0].timestamp).getTime();
        const last = new Date(packets[packets.length - 1].timestamp).getTime();
        if (Number.isFinite(first) && Number.isFinite(last)) {
        durationMs = Math.max(0, last - first);
        }
    }

    return {
        totalPackets,
        totalBytes,
        durationMs,
        uniqueSrcIps,
        uniqueDstIps,
        protocols,
        totalFlows: flows.length,
        authHints,
        fileHints,
    };
    }, [packets, flows]);

    const topSources = React.useMemo(() => topCounts(packets, (p) => p.srcIp, 8), [packets]);
    const topDestinations = React.useMemo(() => topCounts(packets, (p) => p.dstIp, 8), [packets]);
    const topProtocols = React.useMemo(() => topCounts(packets, (p) => p.protocol, 8), [packets]);
    const topPorts = React.useMemo(
        () => topCounts(packets, (p) => p.dstPort || p.srcPort, 8),
        [packets]
    );
    const topTalkersByBytes = React.useMemo(
        () => topByteCounts(packets, (p) => p.srcIp, (p) => p.length, 8),
        [packets]
    );

    const visibleStrings = React.useMemo(() => {
    return packets
        .flatMap((p) =>
        (p.strings || []).map((s) => ({
            packetIndex: p.index,
            text: s,
            protocol: p.protocol,
            srcIp: p.srcIp,
            dstIp: p.dstIp,
        }))
        )
        .filter((x) => looksLikeFlag(x.text))
        .slice(0, 20);
    }, [packets]);

    const protocolHelp = protocolExplainers();

    const applyIpFilter = (value) => setIpFilter(value || "");
    const applyProtocolFilter = (value) => setProtocolFilter(String(value || "all").toLowerCase());
    const applySearch = (value) => setSearch(value || "");

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
            <div style={{ fontWeight: 800, fontSize: 18 }}>PCAP Analyzer</div>
            <div className="helper">
            Upload a capture and review flows, protocol breakdowns, authentication clues, file activity, and matched request/response behavior
            </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <label className="btn primary" style={{ cursor: "pointer" }}>
            Upload PCAP
            <input
                type="file"
                accept=".pcap,.pcapng"
                onChange={onFileChange}
                style={{ display: "none" }}
            />
            </label>

            <button
            className="btn"
            onClick={() => downloadCsv(filteredPackets, `pcap-analysis-${Date.now()}.csv`)}
            disabled={!filteredPackets.length}
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
            {fileName ? `Loaded: ${fileName}` : "Drop in a PCAP file or use Upload PCAP"}
        </div>
        <div className="helper">
            Current browser support: classic .pcap parsing, common protocols, plaintext HTTP/FTP/Telnet clues, DNS extraction, and flow grouping
        </div>
        {loading ? <div style={{ marginTop: 10 }}>Parsing capture…</div> : null}
        {loadError ? <div style={{ marginTop: 10, color: "var(--danger)" }}>{loadError}</div> : null}
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
            { label: "Packets", value: summary.totalPackets },
            { label: "Bytes", value: bytesToHuman(summary.totalBytes) },
            { label: "Duration", value: `${(summary.durationMs / 1000).toFixed(2)}s` },
            { label: "Source IPs", value: summary.uniqueSrcIps },
            { label: "Destination IPs", value: summary.uniqueDstIps },
            { label: "Protocols", value: summary.protocols },
            { label: "Flows", value: summary.totalFlows },
            { label: "Auth Clues", value: summary.authHints },
        ].map((card) => (
            <div key={card.label} className="card" style={{ padding: 16 }}>
            <div className="helper" style={{ marginBottom: 8 }}>{card.label}</div>
            <div style={{ fontSize: 22, fontWeight: 800 }}>{card.value}</div>
            </div>
        ))}
        </div>

        <div className="grid-halves" style={{ marginBottom: 16 }}>
        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Findings Summary</h3>
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
            {findings.map((f, idx) => (
                <li key={idx}>{f}</li>
            ))}
            {!findings.length && <li className="helper">Upload a capture to generate findings.</li>}
            </ul>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>What These Sections Mean</h3>
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
            {protocolHelp.map((item) => (
                <li key={item.title}>
                <strong>{item.title}:</strong> {item.text}
                </li>
            ))}
            </ul>
        </div>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
        <div
            style={{
            display: "grid",
            gridTemplateColumns: "minmax(260px, 1.6fr) minmax(180px, 220px) minmax(180px, 220px)",
            gap: 12,
            }}
        >
            <input
            className="input"
            value={search}
            placeholder="Search packets, visible strings, methods, hosts, info"
            onChange={(e) => setSearch(e.target.value)}
            />

            <select
            className="input"
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            >
            <option value="all">All Protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
            <option value="arp">ARP</option>
            <option value="ipv6">IPv6</option>
            <option value="unknown">Unknown</option>
            </select>

            <input
            className="input"
            value={ipFilter}
            placeholder="Filter by IP"
            onChange={(e) => setIpFilter(e.target.value)}
            />
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
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Source IPs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>IP</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topSources.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyIpFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topSources.length && (
                <tr>
                    <td colSpan="2" className="helper">No source IPs identified yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Destination IPs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>IP</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topDestinations.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyIpFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topDestinations.length && (
                <tr>
                    <td colSpan="2" className="helper">No destination IPs identified yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Protocols</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Protocol</th>
                <th style={{ width: 90 }}>Count</th>
                </tr>
            </thead>
            <tbody>
                {topProtocols.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyProtocolFilter(x.key)}>
                    <td>{x.key}</td>
                    <td className="mono">{x.count}</td>
                </tr>
                ))}
                {!topProtocols.length && (
                <tr>
                    <td colSpan="2" className="helper">No protocol data available yet.</td>
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
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applySearch(String(x.key))}>
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
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Talkers by Bytes</h3>
            <table className="table">
            <thead>
                <tr>
                <th>IP</th>
                <th style={{ width: 110 }}>Bytes</th>
                </tr>
            </thead>
            <tbody>
                {topTalkersByBytes.map((x) => (
                <tr key={x.key} style={{ cursor: "pointer" }} onClick={() => applyIpFilter(x.key)}>
                    <td className="mono">{x.key}</td>
                    <td className="mono">{bytesToHuman(x.bytes)}</td>
                </tr>
                ))}
                {!topTalkersByBytes.length && (
                <tr>
                    <td colSpan="2" className="helper">No byte leaders yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Visible Flag / Secret Clues</h3>
            <table className="table">
            <thead>
                <tr>
                <th style={{ width: 70 }}>Pkt</th>
                <th>String</th>
                </tr>
            </thead>
            <tbody>
                {visibleStrings.map((x) => (
                <tr key={`${x.packetIndex}-${x.text}`} style={{ cursor: "pointer" }} onClick={() => setSelectedPacket(packets.find((p) => p.index === x.packetIndex) || null)}>
                    <td className="mono">{x.packetIndex}</td>
                    <td>
                    <div style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 380 }}>
                        {x.text}
                    </div>
                    </td>
                </tr>
                ))}
                {!visibleStrings.length && (
                <tr>
                    <td colSpan="2" className="helper">No obvious flag, token, or secret strings were found in visible payload text.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>
        </div>

        <div className="grid-halves" style={{ marginBottom: 16 }}>
        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>DNS Pairs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Query</th>
                <th style={{ width: 120 }}>Latency</th>
                </tr>
            </thead>
            <tbody>
                {dnsPairs.slice(0, 12).map((x, idx) => (
                <tr key={`${idx}-${x.query}`}>
                    <td>{x.query}</td>
                    <td className="mono">{x.latencyMs != null ? `${x.latencyMs} ms` : "—"}</td>
                </tr>
                ))}
                {!dnsPairs.length && (
                <tr>
                    <td colSpan="2" className="helper">No DNS query/response pairs matched.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>

        <div className="card">
            <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>HTTP Request / Response Pairs</h3>
            <table className="table">
            <thead>
                <tr>
                <th>Request</th>
                <th style={{ width: 90 }}>Status</th>
                <th style={{ width: 120 }}>Latency</th>
                </tr>
            </thead>
            <tbody>
                {httpPairs.slice(0, 12).map((x, idx) => (
                <tr key={`${idx}-${x.method}-${x.path}`}>
                    <td>
                    <div style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 420 }}>
                        {x.method} {x.path}{x.host ? ` @ ${x.host}` : ""}
                    </div>
                    </td>
                    <td className="mono">{x.statusCode || "—"}</td>
                    <td className="mono">{x.latencyMs != null ? `${x.latencyMs} ms` : "—"}</td>
                </tr>
                ))}
                {!httpPairs.length && (
                <tr>
                    <td colSpan="3" className="helper">No plaintext HTTP request/response pairs matched.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
        <h3 className="h1" style={{ marginTop: 0, fontSize: 16 }}>Top Flows / Conversations</h3>
        <table className="table">
            <thead>
            <tr>
                <th>Conversation</th>
                <th style={{ width: 90 }}>Proto</th>
                <th style={{ width: 90 }}>Packets</th>
                <th style={{ width: 110 }}>Bytes</th>
            </tr>
            </thead>
            <tbody>
            {flows.slice(0, 12).map((flow) => (
                <tr key={flow.key}>
                <td className="mono">{flow.key}</td>
                <td>{flow.protocol}</td>
                <td className="mono">{flow.packets}</td>
                <td className="mono">{bytesToHuman(flow.bytes)}</td>
                </tr>
            ))}
            {!flows.length && (
                <tr>
                <td colSpan="4" className="helper">No flows grouped yet.</td>
                </tr>
            )}
            </tbody>
        </table>
        </div>

        <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: 10 }}>
            <h3 className="h1" style={{ margin: 0, fontSize: 18 }}>Parsed Packets</h3>
            <span className="helper">{filteredPackets.length} matching packets</span>
        </div>

        <div style={{ overflow: "auto", maxHeight: 560 }}>
            <table className="table">
            <thead>
                <tr>
                <th style={{ width: 70 }}>#</th>
                <th style={{ width: 180 }}>Timestamp</th>
                <th style={{ width: 140 }}>Source</th>
                <th style={{ width: 140 }}>Destination</th>
                <th style={{ width: 90 }}>Proto</th>
                <th style={{ width: 80 }}>Len</th>
                <th>Info</th>
                </tr>
            </thead>
            <tbody>
                {filteredPackets.map((p) => (
                <tr key={p.index} style={{ cursor: "pointer" }} onClick={() => setSelectedPacket(p)}>
                    <td className="mono">{p.index}</td>
                    <td className="mono">{p.timestamp || "—"}</td>
                    <td className="mono">
                    {p.srcIp || "—"}{p.srcPort ? `:${p.srcPort}` : ""}
                    </td>
                    <td className="mono">
                    {p.dstIp || "—"}{p.dstPort ? `:${p.dstPort}` : ""}
                    </td>
                    <td>{p.protocol || "—"}</td>
                    <td className="mono">{p.length}</td>
                    <td>
                    <div style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 560 }}>
                        {p.info}
                    </div>
                    </td>
                </tr>
                ))}
                {!filteredPackets.length && (
                <tr>
                    <td colSpan="7" className="helper">No packets to display yet.</td>
                </tr>
                )}
            </tbody>
            </table>
        </div>
        </div>

        {selectedPacket && (
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
                width: 760,
                height: "100%",
                borderRadius: 0,
                overflow: "auto",
                padding: 18,
            }}
            >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                <div style={{ fontSize: 18, fontWeight: 900 }}>
                    Packet <span className="mono">#{selectedPacket.index}</span>
                </div>
                <div className="helper">
                    {selectedPacket.timestamp || "No timestamp"} · {selectedPacket.protocol} · {selectedPacket.length} bytes
                </div>
                </div>
                <button className="btn" onClick={() => setSelectedPacket(null)}>✕</button>
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
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Endpoints</div>
                <div className="mono">{selectedPacket.srcIp || "—"}{selectedPacket.srcPort ? `:${selectedPacket.srcPort}` : ""}</div>
                <div className="mono" style={{ margin: "6px 0" }}>↓</div>
                <div className="mono">{selectedPacket.dstIp || "—"}{selectedPacket.dstPort ? `:${selectedPacket.dstPort}` : ""}</div>
                </div>

                <div className="card" style={{ padding: 12 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 6 }}>Quick Interpretation</div>
                <div style={{ lineHeight: 1.6 }}>{selectedPacket.info}</div>
                {selectedPacket.tcpFlags ? (
                    <div className="helper" style={{ marginTop: 8 }}>TCP Flags: {selectedPacket.tcpFlags}</div>
                ) : null}
                </div>
            </div>

            {(selectedPacket.authHints?.length || selectedPacket.fileActivityHints?.length) ? (
                <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 8 }}>Authentication / File Clues</div>
                <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                    {selectedPacket.authHints?.map((x, idx) => <li key={`a-${idx}`}>{x}</li>)}
                    {selectedPacket.fileActivityHints?.map((x, idx) => <li key={`f-${idx}`}>{x}</li>)}
                </ul>
                </div>
            ) : null}

            {selectedPacket.layers?.length ? (
                <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 8 }}>Packet Dissection</div>
                {selectedPacket.layers.map((layer) => (
                    <div key={layer.name} className="card" style={{ padding: 12, marginBottom: 10 }}>
                    <div style={{ fontWeight: 800, marginBottom: 4 }}>{layer.name}</div>
                    <div className="helper" style={{ marginBottom: 8 }}>{layer.explanation}</div>
                    <table className="table">
                        <thead>
                        <tr>
                            <th>Field</th>
                            <th>Value</th>
                            <th style={{ width: 110 }}>Offset</th>
                        </tr>
                        </thead>
                        <tbody>
                        {layer.fields?.length ? layer.fields.map((field) => (
                            <tr key={`${layer.name}-${field.name}`}>
                            <td>{field.name}</td>
                            <td className="mono">{field.value}</td>
                            <td className="mono">{field.offset}</td>
                            </tr>
                        )) : (
                            <tr>
                            <td colSpan="3" className="helper">No detailed field breakdown available for this layer in version 1.</td>
                            </tr>
                        )}
                        </tbody>
                    </table>
                    </div>
                ))}
                </div>
            ) : null}

            {selectedPacket.http ? (
                <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 8 }}>HTTP Details</div>
                <div className="card" style={{ padding: 12 }}>
                    <div>Kind: <span className="mono">{selectedPacket.http.kind}</span></div>
                    {selectedPacket.http.method ? <div>Method: <span className="mono">{selectedPacket.http.method}</span></div> : null}
                    {selectedPacket.http.path ? <div>Path: <span className="mono">{selectedPacket.http.path}</span></div> : null}
                    {selectedPacket.http.host ? <div>Host: <span className="mono">{selectedPacket.http.host}</span></div> : null}
                    {selectedPacket.http.statusCode ? <div>Status: <span className="mono">{selectedPacket.http.statusCode}</span></div> : null}
                </div>
                </div>
            ) : null}

            {selectedPacket.dns ? (
                <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 8 }}>DNS Details</div>
                <div className="card" style={{ padding: 12 }}>
                    <div>Query: <span className="mono">{selectedPacket.dns.query}</span></div>
                    <div>Transaction ID: <span className="mono">{selectedPacket.dns.txId ?? "—"}</span></div>
                    <div>Response: <span className="mono">{selectedPacket.dns.isResponse ? "Yes" : "No"}</span></div>
                </div>
                </div>
            ) : null}

            {selectedPacket.strings?.length ? (
                <div style={{ marginTop: 16 }}>
                <div className="helper" style={{ fontWeight: 800, marginBottom: 8 }}>Visible Payload Strings</div>
                <div className="card" style={{ padding: 12 }}>
                    <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                    {selectedPacket.strings.slice(0, 20).map((s, idx) => (
                        <li key={idx} className="mono">{s}</li>
                    ))}
                    </ul>
                </div>
                </div>
            ) : null}
            </div>
        </div>
        )}
    </div>
    );
}