#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import json
import socket
import threading
import queue
import argparse
from typing import Optional, Dict, Any, Set, Tuple
from dotenv import load_dotenv
from pathlib import Path

import requests

try:
    import psutil
except Exception:
    psutil = None

# Scapy capture/parsing
from scapy.all import sniff, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR

DOTENV_PATH = Path(__file__).with_name(".env")
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

API_BASE = (os.getenv("IC_API") or os.getenv("IC_API_BASE") or "http://localhost:5000").rstrip("/")
IC_CLIENT_KEY = os.getenv("IC_CLIENT_KEY", "")

BATCH_MAX = int(os.getenv("IC_BATCH_MAX", "2000"))
BATCH_SEC = float(os.getenv("IC_BATCH_SEC", "2.0"))
QUEUE_MAX = int(os.getenv("IC_QUEUE_MAX", "50000"))

# Reasonable defaults for “important, not everything”
BPF_DEFAULT = os.getenv(
    "IC_BPF",
    "(arp or icmp or icmp6 or tcp or udp) "
    "and not (udp port 5353 or udp port 1900 or udp port 137 or udp port 138)"
)
VERIFY_TLS = os.getenv("IC_VERIFY_TLS", "true").lower() in ("1", "true", "yes", "y")

# Emission mode: IMPORTANT is recommended for home usability
EMIT_MODE = os.getenv("IC_EMIT_MODE", "important").lower()  # important|packets
EMIT_FLOW_SUMMARY = os.getenv("IC_EMIT_FLOW_SUMMARY", "true").lower() in ("1", "true", "yes", "y")

FLOW_FLUSH_SEC = float(os.getenv("IC_FLOW_FLUSH_SEC", "2.0"))
FLOW_IDLE_EVICT_SEC = float(os.getenv("IC_FLOW_IDLE_EVICT_SEC", "30.0"))
FLOW_MAX = int(os.getenv("IC_FLOW_MAX", "20000"))

print(f"[config] IC_BATCH_MAX={BATCH_MAX} IC_BATCH_SEC={BATCH_SEC} IC_QUEUE_MAX={QUEUE_MAX}")
print(f"[config] IC_API={API_BASE} IC_CLIENT_KEY={'set' if bool(IC_CLIENT_KEY) else 'MISSING'}")
print(f"[config] IC_EMIT_MODE={EMIT_MODE} IC_EMIT_FLOW_SUMMARY={EMIT_FLOW_SUMMARY}")
print(f"[config] IC_BPF={BPF_DEFAULT}")

# -------------------------
# Interface helpers
# -------------------------

def list_local_ips_for_iface(iface: str) -> Set[str]:
    ips: Set[str] = set()
    if psutil is None:
        return ips
    addrs = psutil.net_if_addrs().get(iface, [])
    for a in addrs:
        if a.family in (socket.AF_INET, socket.AF_INET6):
            ip = a.address.split("%")[0]
            if ip and not ip.startswith("127.") and ip != "::1":
                ips.add(ip)
    return ips


def best_effort_pick_iface() -> Optional[str]:
    if psutil is None:
        return None
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    candidates: list[str] = []
    for iface, st in stats.items():
        if not st.isup:
            continue
        if iface.lower() in ("lo", "loopback"):
            continue
        has_ip = False
        for a in addrs.get(iface, []):
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ip = a.address.split("%")[0]
                if ip and not ip.startswith("127.") and ip != "::1":
                    has_ip = True
                    break
        if has_ip:
            candidates.append(iface)

    preferred_keywords = ("wi-fi", "wifi", "wlan", "ethernet", "en", "eth")
    candidates.sort(key=lambda x: (0 if any(k in x.lower() for k in preferred_keywords) else 1, x.lower()))
    return candidates[0] if candidates else None


def resolve_iface(user_iface: str) -> str:
    user_iface = user_iface.strip()
    if not user_iface:
        raise ValueError("empty iface")

    try:
        if user_iface in conf.ifaces:
            return user_iface
    except Exception:
        pass

    try:
        for iface in conf.ifaces.values():
            name = str(getattr(iface, "name", ""))
            desc = str(getattr(iface, "description", ""))
            if user_iface.lower() in name.lower() or user_iface.lower() in desc.lower():
                return name
    except Exception:
        pass

    return user_iface


def compute_direction(src_ip: str, dst_ip: str, local_ips: Set[str]) -> str:
    if local_ips:
        if src_ip in local_ips and dst_ip not in local_ips:
            return "outbound"
        if dst_ip in local_ips and src_ip not in local_ips:
            return "inbound"
    return "unknown"


# -------------------------
# “Wireshark-like” helpers
# -------------------------

def decode_tcp_flags(flags_int: int) -> str:
    bits = [
        ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
        ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
        ("ECE", 0x40), ("CWR", 0x80),
    ]
    on = [name for name, bit in bits if flags_int & bit]
    return ",".join(on) if on else ""


def app_hint(protocol: str, sport: Optional[int], dport: Optional[int], ev: Dict[str, Any]) -> str:
    ports = {sport, dport}
    if protocol == "UDP" and "dns_qname" in ev:
        return "DNS"
    if 53 in ports:
        return "DNS"
    if 67 in ports or 68 in ports:
        return "DHCP"
    if 80 in ports:
        return "HTTP"
    if 443 in ports:
        return "TLS"
    if 22 in ports:
        return "SSH"
    if 3389 in ports:
        return "RDP"
    if 445 in ports:
        return "SMB"
    return ""


# -------------------------
# Sender thread (batch ingest)
# -------------------------

def sender_thread(q: "queue.Queue[Dict[str, Any]]", url: str, client_key: str, stop: threading.Event) -> None:
    sess = requests.Session()
    headers = {"X-Client-Key": client_key} if client_key else {}

    buf: list[Dict[str, Any]] = []
    last_flush = time.time()

    while not stop.is_set():
        try:
            item = q.get(timeout=0.2)
            buf.append(item)
        except queue.Empty:
            pass

        now = time.time()
        if buf and (len(buf) >= BATCH_MAX or (now - last_flush) >= BATCH_SEC):
            try:
                r = sess.post(url, headers=headers, json={"items": buf}, timeout=5, verify=VERIFY_TLS)
                print(f"[sent] {len(buf)} status={r.status_code}")
            except Exception as e:
                print(f"[send-error] {e}")
            buf.clear()
            last_flush = now


# -------------------------
# Flow aggregation (important-only)
# -------------------------

FlowKey = Tuple[str, str, str, Optional[int], Optional[int]]  # src_ip, dst_ip, protocol, sport, dport

class FlowTable:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._flows: Dict[FlowKey, Dict[str, Any]] = {}

    def update(self, key: FlowKey, ts: float, length: int) -> None:
        with self._lock:
            f = self._flows.get(key)
            if f is None:
                f = {
                    "first_ts": ts,
                    "last_ts": ts,
                    "packets_total": 0,
                    "bytes_total": 0,
                    "packets_sent": 0,
                    "bytes_sent": 0,
                }
                self._flows[key] = f
            f["last_ts"] = ts
            f["packets_total"] += 1
            f["bytes_total"] += length

            # Simple table pressure control
            if len(self._flows) > FLOW_MAX:
                # Evict oldest by last_ts (approximate, low overhead)
                oldest = min(self._flows.items(), key=lambda kv: kv[1]["last_ts"])[0]
                self._flows.pop(oldest, None)

    def snapshot_deltas(self, now: float) -> list[Tuple[FlowKey, Dict[str, Any]]]:
        out: list[Tuple[FlowKey, Dict[str, Any]]] = []
        with self._lock:
            # Evict idle flows
            idle_cutoff = now - FLOW_IDLE_EVICT_SEC
            to_evict = [k for k, v in self._flows.items() if v["last_ts"] < idle_cutoff]
            for k in to_evict:
                self._flows.pop(k, None)

            # Create delta snapshots
            for k, v in self._flows.items():
                pkt_delta = v["packets_total"] - v["packets_sent"]
                byte_delta = v["bytes_total"] - v["bytes_sent"]
                if pkt_delta <= 0 and byte_delta <= 0:
                    continue

                snap = dict(v)
                snap["packets_delta"] = pkt_delta
                snap["bytes_delta"] = byte_delta

                # Mark as sent
                v["packets_sent"] = v["packets_total"]
                v["bytes_sent"] = v["bytes_total"]

                out.append((k, snap))
        return out


def flow_flush_thread(flow_table: FlowTable, q: "queue.Queue[Dict[str, Any]]", iface: str, local_ips: Set[str], stop: threading.Event) -> None:
    while not stop.is_set():
        time.sleep(FLOW_FLUSH_SEC)
        if not EMIT_FLOW_SUMMARY:
            continue

        now = time.time()
        deltas = flow_table.snapshot_deltas(now)
        for (src_ip, dst_ip, proto, sport, dport), snap in deltas:
            ev = {
                "ts": now,
                "iface": iface,
                "event_type": "FLOW_SUMMARY",
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "direction": compute_direction(src_ip, dst_ip, local_ips) if src_ip and dst_ip else "unknown",
                "first_ts": snap["first_ts"],
                "last_ts": snap["last_ts"],
                "packets_delta": snap["packets_delta"],
                "bytes_delta": snap["bytes_delta"],
                "packets_total": snap["packets_total"],
                "bytes_total": snap["bytes_total"],
            }
            hint = app_hint(proto, sport, dport, ev)
            if hint:
                ev["app"] = hint
            try:
                nev = _normalize_for_backend(ev)
                print("[flow-debug]", json.dumps(nev, default=str))
                q.put_nowait(nev)
            except queue.Full:
                pass
            except Exception as e:
                print(f"[flow-flush-error] {e}")
            




# -------------------------
# Packet parsing -> important events
# -------------------------

def packet_to_important_events(pkt, iface: str, local_ips: Set[str], flow_table: FlowTable) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    ts = float(getattr(pkt, "time", time.time()))

    src_mac = dst_mac = None
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    # ARP: high value for “who is on the LAN”
    if ARP in pkt:
        a = pkt[ARP]
        ev = {
            "ts": ts,
            "iface": iface,
            "event_type": "ARP",
            "protocol": "ARP",
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": a.psrc,
            "dst_ip": a.pdst,
            "arp_op": int(a.op),  # 1=request, 2=reply
            "length": int(len(pkt)),
            "direction": compute_direction(a.psrc, a.pdst, local_ips),
        }
        events.append(ev)
        return events  # ARP is its own thing; do not try to flow-aggregate it

    # L3
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    else:
        return events

    length = int(len(pkt))

    # L4 protocol extraction
    protocol = "OTHER"
    sport = dport = None

    if TCP in pkt:
        protocol = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        protocol = "UDP"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"

    # Update flow table for summaries
    if protocol in ("TCP", "UDP") and src_ip and dst_ip:
        flow_table.update((src_ip, dst_ip, protocol, sport, dport), ts, length)

    # DNS query (UDP) is a core “important event”
    if protocol == "UDP" and DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
        qname = ""
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except Exception:
            qname = ""
        ev = {
            "ts": ts,
            "iface": iface,
            "event_type": "DNS_QUERY",
            "protocol": "UDP",
            "app": "DNS",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "dns_qname": qname,
            "length": length,
            "direction": compute_direction(src_ip, dst_ip, local_ips),
        }
        events.append(ev)

    # TCP connect attempt (SYN without ACK)
    if protocol == "TCP":
        flags_int = int(pkt[TCP].flags)
        flags_str = decode_tcp_flags(flags_int)
        if ("SYN" in flags_str) and ("ACK" not in flags_str):
            ev = {
                "ts": ts,
                "iface": iface,
                "event_type": "TCP_CONNECT_ATTEMPT",
                "protocol": "TCP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "tcp_flags": flags_int,
                "tcp_flags_str": flags_str,
                "length": length,
                "direction": compute_direction(src_ip, dst_ip, local_ips),
            }
            hint = app_hint("TCP", sport, dport, ev)
            if hint:
                ev["app"] = hint
            events.append(ev)

    # Optional: ICMP unreachable can indicate blocked/failed routes (kept minimal)
    if protocol == "ICMP" and ICMP in pkt:
        try:
            ev = {
                "ts": ts,
                "iface": iface,
                "event_type": "ICMP",
                "protocol": "ICMP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "icmp_type": int(pkt[ICMP].type),
                "icmp_code": int(pkt[ICMP].code),
                "length": length,
                "direction": compute_direction(src_ip, dst_ip, local_ips),
            }
            events.append(ev)
        except Exception:
            pass

    return events


def packet_to_packet_event(pkt, iface: str, local_ips: Set[str]) -> Optional[Dict[str, Any]]:
    # If you ever want “packet mode,” keep a single unified event.
    try:
        ts = float(getattr(pkt, "time", time.time()))

        src_mac = dst_mac = None
        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        if ARP in pkt:
            a = pkt[ARP]
            return {
                "ts": ts, "iface": iface, "protocol": "ARP",
                "src_mac": src_mac, "dst_mac": dst_mac,
                "src_ip": a.psrc, "dst_ip": a.pdst,
                "arp_op": int(a.op), "length": int(len(pkt)),
                "direction": compute_direction(a.psrc, a.pdst, local_ips),
            }

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None

        protocol = "OTHER"
        sport = dport = None
        flags_int = None
        flags_str = ""

        if TCP in pkt:
            protocol = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags_int = int(pkt[TCP].flags)
            flags_str = decode_tcp_flags(flags_int)
        elif UDP in pkt:
            protocol = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            protocol = "ICMP"

        ev: Dict[str, Any] = {
            "ts": ts,
            "iface": iface,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "length": int(len(pkt)),
            "direction": compute_direction(src_ip, dst_ip, local_ips),
        }

        if flags_int is not None:
            ev["tcp_flags"] = flags_int
            ev["tcp_flags_str"] = flags_str

        if protocol == "UDP" and DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            try:
                ev["dns_qname"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                ev["app"] = "DNS"
            except Exception:
                pass

        hint = app_hint(protocol, sport, dport, ev)
        if hint and "app" not in ev:
            ev["app"] = hint

        return ev
    except Exception:
        return None


def _build_ingest_url(base: str) -> str:
        b = base.rstrip("/")
        if b.endswith("/api"):
            return b + "/traffic/ingest"
        return b + "/api/traffic/ingest"


# -------------------------
# Main
# -------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="IntelliCloud IC Agent (Wireshark-like, important-only by default).")
    ap.add_argument("--iface", default=os.getenv("IC_IFACE", ""), help="Interface name (e.g., Wi-Fi, Ethernet).")
    ap.add_argument("--api", default=API_BASE, help="Base API URL (e.g., http://localhost:5000).")
    ap.add_argument("--bpf", default=os.getenv("IC_BPF", BPF_DEFAULT), help="BPF filter (default is sane + low-noise).")
    ap.add_argument("--emit", default=EMIT_MODE, choices=["important", "packets"], help="Emit mode.")
    args = ap.parse_args()

    if not IC_CLIENT_KEY:
        print("ERROR: IC_CLIENT_KEY is missing. Put it in ic_agent/.env or export it.")
        return 2

    iface = args.iface.strip()
    if not iface:
        iface = best_effort_pick_iface() or ""
        if not iface:
            print("ERROR: No interface provided and auto-detect unavailable. Install psutil or pass --iface.")
            return 2

    iface = resolve_iface(iface)
    ingest_url = _build_ingest_url(args.api)

    local_ips = list_local_ips_for_iface(iface)
    bpf = args.bpf

    print(json.dumps({
        "ok": True,
        "iface": iface,
        "local_ips": sorted(local_ips),
        "ingest_url": ingest_url,
        "bpf": bpf,
        "batch_max": BATCH_MAX,
        "batch_sec": BATCH_SEC,
        "emit_mode": args.emit,
        "flow_summary": EMIT_FLOW_SUMMARY,
        "flow_flush_sec": FLOW_FLUSH_SEC,
    }, indent=2))

    q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=QUEUE_MAX)
    stop = threading.Event()

    sender = threading.Thread(target=sender_thread, args=(q, ingest_url, IC_CLIENT_KEY, stop), daemon=True)
    sender.start()

    flow_table = FlowTable()
    flusher = threading.Thread(target=flow_flush_thread, args=(flow_table, q, iface, local_ips, stop), daemon=True)
    flusher.start()

    def handler(pkt):
        if args.emit == "packets":
            ev = packet_to_packet_event(pkt, iface, local_ips)
            if ev is None:
                return
            nev = _normalize_for_backend(ev)
            try:
                q.put_nowait(nev)
            except queue.Full:
                pass
            return

        # IMPORTANT mode
        evs = packet_to_important_events(pkt, iface, local_ips, flow_table)
        for ev in evs:
            nev = _normalize_for_backend(ev)
            try:
                q.put_nowait(nev)
            except queue.Full:
                break

    try:
        sniff(iface=iface, filter=bpf, prn=handler, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()

    return 0

def classify_zone(ip: str) -> str:
    if not ip:
        return "unknown"

    if ip.startswith("172.18.") or ip.startswith("172.17."):
        return "docker"

    if ip.startswith("10.") or ip.startswith("192.168."):
        return "private"

    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return "private"
        except Exception:
            pass

    if ":" in ip:
        lowered = ip.lower()
        if lowered.startswith("fe80:"):
            return "link-local-ipv6"
        if lowered.startswith("fd") or lowered.startswith("fc"):
            return "private-ipv6"
        return "public-ipv6"

    return "public"


def build_sensor_id(iface: str) -> str:
    explicit = os.getenv("IC_SENSOR_ID", "").strip()
    if explicit:
        return explicit
    return f"sensor-{iface or 'unknown'}"


def _normalize_for_backend(ev: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(ev)

    # protocol → proto (lowercase)
    proto = (ev.get("protocol") or ev.get("proto") or "")
    if proto:
        out["proto"] = str(proto).lower()

    # src/dst IPs
    if "src_ip" in ev:
        out["src"] = ev["src_ip"]
    if "dst_ip" in ev:
        out["dst"] = ev["dst_ip"]

    # ports
    if "src_port" in ev:
        out["sport"] = ev["src_port"]
    if "dst_port" in ev:
        out["dport"] = ev["dst_port"]

    # DNS (qname → dns)
    if "dns_qname" in ev and ev["dns_qname"]:
        out["dns"] = ev["dns_qname"]

    # direction → dir
    if "direction" in ev:
        out["dir"] = ev["direction"]

    # Ensure ts is a float seconds epoch
    if "ts" in ev:
        try:
            out["ts"] = float(ev["ts"])
        except Exception:
            pass

    # Sensor identity
    iface = str(ev.get("iface") or "")
    out["sensor_id"] = build_sensor_id(iface)

    # Zone tagging
    src = out.get("src")
    dst = out.get("dst")

    src_zone = classify_zone(src) if src else "unknown"
    dst_zone = classify_zone(dst) if dst else "unknown"

    out["src_zone"] = src_zone
    out["dst_zone"] = dst_zone

    # High-level scope for easier UI filtering
    zones = {src_zone, dst_zone}
    if "docker" in zones:
        out["network_scope"] = "docker"
    elif any(z in zones for z in ("private", "private-ipv6", "link-local-ipv6")):
        out["network_scope"] = "private"
    elif any(z in zones for z in ("public", "public-ipv6")):
        out["network_scope"] = "public"
    else:
        out["network_scope"] = "unknown"
    
    return out

if __name__ == "__main__":
    raise SystemExit(main())
