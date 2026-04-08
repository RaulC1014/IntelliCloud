import time
import collections

_SCAN_WINDOW_S = 15
_SCAN_MIN_UNIQUE_PORTS = 12
_SCAN_MIN_EVENTS = 20

_scan_buf = collections.defaultdict(collections.deque)

SUSPICIOUS_TCP_PORTS = {22, 23, 25, 445, 3389, 5900, 1433}
SUSPICIOUS_UDP_PORTS = {53, 123, 1900}


def score_event(norm: dict) -> tuple[str, str, str]:
    proto = (norm.get("proto") or "").lower()
    dport = norm.get("dport")
    src = norm.get("src")
    dst = norm.get("dst")

    if proto == "tcp" and dport in SUSPICIOUS_TCP_PORTS:
        return (
            "High",
            f"TCP/{dport} is a commonly abused/admin port",
            "suspicious_service_exposure",
        )

    if proto == "udp" and dport in SUSPICIOUS_UDP_PORTS:
        return (
            "Medium",
            f"UDP/{dport} can be abused; requires context",
            "suspicious_udp_service",
        )

    dns = (norm.get("dns") or "").strip()
    if dns and len(dns) >= 55:
        return (
            "Medium",
            "Unusually long DNS name (possible DGA/tunneling)",
            "dns_anomaly",
        )

    if proto in {"tcp", "udp"} and (dport is None or dport == 0):
        return (
            "Medium",
            "Missing/invalid destination port",
            "invalid_port_data",
        )

    if src and (dport is not None) and dst:
        now = time.time()
        dq = _scan_buf[src]
        dq.append((now, int(dport), dst))

        cutoff = now - _SCAN_WINDOW_S
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ports = {p for (_t, p, _dst) in dq}

        if len(dq) >= _SCAN_MIN_EVENTS and len(unique_ports) >= _SCAN_MIN_UNIQUE_PORTS:
            return (
                "High",
                f"Possible port scan: {len(unique_ports)} unique ports in {_SCAN_WINDOW_S}s",
                "port_scan",
            )

    return (
        "Low",
        "Benign default based on current heuristic",
        "benign_default",
    )