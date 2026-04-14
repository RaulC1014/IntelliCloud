import time
import math
import collections

# --- Timing windows ---
_SCAN_WINDOW_S = 15
_SCAN_MIN_UNIQUE_PORTS = 12
_SCAN_MIN_EVENTS = 20

_BEACON_WINDOW_S = 120
_BEACON_MIN_EVENTS = 5
_BEACON_INTERVAL_JITTER = 0.20   # 20% jitter tolerance

_scan_buf   = collections.defaultdict(collections.deque)
_beacon_buf = collections.defaultdict(list)   # src -> [timestamps]

# --- Port sets ---
# High-risk only when INBOUND from external
INBOUND_HIGH_PORTS = {22, 23, 3389, 5900, 5985, 5986}   # SSH, Telnet, RDP, VNC, WinRM

# High-risk regardless of direction (C2/malware)
ALWAYS_HIGH_PORTS = {4444, 1337, 31337, 6667, 6697}      # common C2 / IRC

# Medium-risk: worth logging but not alarming
MEDIUM_TCP_PORTS = {21, 25, 110, 143, 445, 1433, 3306, 5432, 27017}
MEDIUM_UDP_PORTS = {53, 123, 1900, 5353}

RFC1918 = [
    (0x0A000000, 0xFF000000),    # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),    # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),    # 192.168.0.0/16
]

def _is_private(ip: str) -> bool:
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        n = 0
        for p in parts:
            n = (n << 8) | int(p)
        return any((n & mask) == net for net, mask in RFC1918)
    except Exception:
        return False


def _infer_direction(src: str, dst: str) -> str:
    src_priv = _is_private(src)
    dst_priv = _is_private(dst)
    if src_priv and not dst_priv:
        return "outbound"
    if not src_priv and dst_priv:
        return "inbound"
    if src_priv and dst_priv:
        return "internal"
    return "external"


def _check_beacon(src: str, dst: str, now: float) -> bool:
    """True if src->dst shows regular beaconing pattern."""
    key = f"{src}->{dst}"
    buf = _beacon_buf[key]
    buf.append(now)

    # Evict old entries
    cutoff = now - _BEACON_WINDOW_S
    while buf and buf[0] < cutoff:
        buf.pop(0)

    if len(buf) < _BEACON_MIN_EVENTS:
        return False

    intervals = [buf[i+1] - buf[i] for i in range(len(buf)-1)]
    avg = sum(intervals) / len(intervals)
    if avg < 1:
        return False
    std = math.sqrt(sum((x - avg)**2 for x in intervals) / len(intervals))
    jitter = std / avg
    return jitter < _BEACON_INTERVAL_JITTER


def score_event(norm: dict) -> tuple[str, str, str]:
    proto  = (norm.get("proto") or "").lower()
    dport  = norm.get("dport")
    src    = norm.get("src") or ""
    dst    = norm.get("dst") or ""
    dns    = (norm.get("dns") or "").strip()
    given_dir = (norm.get("dir") or "").lower()

    direction = given_dir if given_dir in ("inbound", "outbound", "internal", "external") \
                else _infer_direction(src, dst)

    now = time.time()

    # ── Always-High ports (C2 / known malware) ──
    if proto == "tcp" and dport in ALWAYS_HIGH_PORTS:
        return ("High",
                f"TCP/{dport} is associated with known malware/C2 tools",
                "c2_indicator")

    # ── Inbound admin ports ──
    if proto == "tcp" and dport in INBOUND_HIGH_PORTS and direction == "inbound":
        return ("High",
                f"Inbound TCP/{dport} from external source (possible unauthorized admin access)",
                "inbound_admin_port")

    # ── Medium TCP service ports ──
    if proto == "tcp" and dport in MEDIUM_TCP_PORTS:
        return ("Medium",
                f"TCP/{dport} exposed — verify this service is intentionally public",
                "exposed_service")

    # ── Suspicious UDP ──
    if proto == "udp" and dport in MEDIUM_UDP_PORTS:
        return ("Medium",
                f"UDP/{dport} — verify legitimate use; common abuse vector",
                "suspicious_udp_service")

    # ── DNS anomalies ──
    if dns:
        if len(dns) >= 55:
            return ("Medium",
                    "Unusually long DNS hostname (possible DGA or DNS tunneling)",
                    "dns_length_anomaly")
        labels = dns.split(".")
        avg_label_len = sum(len(l) for l in labels) / max(len(labels), 1)
        if avg_label_len > 12:
            return ("Medium",
                    "High-entropy DNS hostname (possible DGA)",
                    "dns_entropy_anomaly")

    # ── Port scan detection ──
    if src and dport is not None and dst:
        dq = _scan_buf[src]
        dq.append((now, int(dport), dst))
        cutoff = now - _SCAN_WINDOW_S
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ports = {p for (_, p, _) in dq}
        if len(dq) >= _SCAN_MIN_EVENTS and len(unique_ports) >= _SCAN_MIN_UNIQUE_PORTS:
            return ("High",
                    f"Possible port scan: {len(unique_ports)} unique ports in {_SCAN_WINDOW_S}s",
                    "port_scan")

    # ── Beaconing detection ──
    if src and dst:
        if _check_beacon(src, dst, now):
            return ("Medium",
                    f"Regular connection intervals detected from {src} to {dst} — possible C2 beaconing",
                    "beaconing")

    # ── Missing/invalid port data ──
    if proto in {"tcp", "udp"} and (dport is None or dport == 0):
        return ("Low",
                "Missing or invalid destination port in packet metadata",
                "invalid_port_data")

    return ("Low", "No suspicious indicators detected", "benign_default")