#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import json
import socket
import threading
import queue
import argparse
import collections
from typing import Optional, Dict, Any, Set, Tuple
from dotenv import load_dotenv
from pathlib import Path

import requests

try:
    import psutil
except Exception:
    psutil = None

from scapy.all import sniff, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR

load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

API_BASE        = (os.getenv("IC_API") or os.getenv("IC_API_BASE") or "http://localhost:5000").rstrip("/")
IC_CLIENT_KEY   = os.getenv("IC_CLIENT_KEY", "")
BATCH_MAX       = int(os.getenv("IC_BATCH_MAX", "500"))
BATCH_SEC       = float(os.getenv("IC_BATCH_SEC", "2.0"))
QUEUE_MAX       = int(os.getenv("IC_QUEUE_MAX", "50000"))
VERIFY_TLS      = os.getenv("IC_VERIFY_TLS", "true").lower() in ("1", "true", "yes", "y")
EMIT_MODE       = os.getenv("IC_EMIT_MODE", "important").lower()
EMIT_FLOW_SUMMARY = os.getenv("IC_EMIT_FLOW_SUMMARY", "true").lower() in ("1", "true", "yes", "y")
FLOW_FLUSH_SEC  = float(os.getenv("IC_FLOW_FLUSH_SEC", "2.0"))
FLOW_IDLE_EVICT_SEC = float(os.getenv("IC_FLOW_IDLE_EVICT_SEC", "30.0"))
FLOW_MAX        = int(os.getenv("IC_FLOW_MAX", "20000"))
SENDER_RETRY_MAX = int(os.getenv("IC_SENDER_RETRY_MAX", "3"))
IC_POLL_ENABLED = os.getenv("IC_POLL_ENABLED", "true").lower() != "false"

BPF_DEFAULT = os.getenv(
    "IC_BPF",
    "(arp or icmp or icmp6 or tcp or udp) "
    "and not (udp port 5353 or udp port 1900 or udp port 137 or udp port 138)"
)

print(f"[config] API={API_BASE}  CLIENT_KEY={'set' if IC_CLIENT_KEY else 'MISSING'}")
print(f"[config] EMIT_MODE={EMIT_MODE}  FLOW_SUMMARY={EMIT_FLOW_SUMMARY}")
print(f"[config] BATCH_MAX={BATCH_MAX}  BATCH_SEC={BATCH_SEC}  QUEUE_MAX={QUEUE_MAX}")
print(f"[config] BPF={BPF_DEFAULT}")


# ─────────────────────────────────────────────────────────────
# Interface helpers
# ─────────────────────────────────────────────────────────────

def list_local_ips_for_iface(iface: str) -> Set[str]:
    ips: Set[str] = set()
    if psutil is None:
        return ips
    for a in psutil.net_if_addrs().get(iface, []):
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
        if not st.isup or iface.lower() in ("lo", "loopback"):
            continue
        if any(
            a.family in (socket.AF_INET, socket.AF_INET6)
            and not a.address.startswith("127.")
            and a.address != "::1"
            for a in addrs.get(iface, [])
        ):
            candidates.append(iface)
    preferred = ("wi-fi", "wifi", "wlan", "ethernet", "en", "eth")
    candidates.sort(key=lambda x: (0 if any(k in x.lower() for k in preferred) else 1, x.lower()))
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


def build_sensor_id(iface: str) -> str:
    explicit = os.getenv("IC_SENSOR_ID", "").strip()
    return explicit if explicit else f"sensor-{iface or 'unknown'}"


# ─────────────────────────────────────────────────────────────
# Zone / direction helpers
# ─────────────────────────────────────────────────────────────

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


def compute_direction(src_ip: str, dst_ip: str, local_ips: Set[str]) -> str:
    if local_ips:
        if src_ip in local_ips and dst_ip not in local_ips:
            return "outbound"
        if dst_ip in local_ips and src_ip not in local_ips:
            return "inbound"
    return "unknown"


# ─────────────────────────────────────────────────────────────
# Protocol / application labeling  (expanded)
# ─────────────────────────────────────────────────────────────

# Port → application label (covers what analysts actually care about)
PORT_APP_MAP: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP",
    389: "LDAP", 443: "TLS/HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-SUBMISSION",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE-DB",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES",
    5900: "VNC", 5985: "WINRM-HTTP", 5986: "WINRM-HTTPS",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    8888: "HTTP-ALT", 9200: "ELASTICSEARCH",
    27017: "MONGODB", 6667: "IRC", 6697: "IRC-TLS",
    4444: "METERPRETER", 1337: "LEET-PORT", 31337: "ELITE-PORT",
}


def app_hint(protocol: str, sport: Optional[int], dport: Optional[int], ev: Dict[str, Any]) -> str:
    # DNS event already labeled
    if "dns_qname" in ev or "dns_answer" in ev:
        return "DNS"
    # Check destination port first, then source
    for port in (dport, sport):
        if port and port in PORT_APP_MAP:
            return PORT_APP_MAP[port]
    return ""


def decode_tcp_flags(flags_int: int) -> str:
    bits = [
        ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
        ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
        ("ECE", 0x40), ("CWR", 0x80),
    ]
    on = [name for name, bit in bits if flags_int & bit]
    return ",".join(on) if on else ""


# ─────────────────────────────────────────────────────────────
# ARP cache — for poisoning detection
# ─────────────────────────────────────────────────────────────

class ARPCache:
    """
    Tracks IP→MAC mappings seen on the wire.
    Fires a warning when an IP changes to a different MAC (ARP spoofing indicator).
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[str, str] = {}   # ip → mac

    def check_and_update(self, ip: str, mac: str) -> Optional[str]:
        """
        Returns a warning string if this looks like ARP spoofing, else None.
        Always updates the cache to the new MAC.
        """
        if not ip or not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None
        with self._lock:
            known = self._cache.get(ip)
            self._cache[ip] = mac
            if known and known != mac:
                return f"ARP cache conflict: {ip} was {known}, now {mac} — possible ARP spoofing"
        return None


arp_cache = ARPCache()


# ─────────────────────────────────────────────────────────────
# Flow table
# ─────────────────────────────────────────────────────────────

FlowKey = Tuple[str, str, str, Optional[int], Optional[int]]


class FlowTable:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._flows: Dict[FlowKey, Dict[str, Any]] = {}

    def update(self, key: FlowKey, ts: float, length: int) -> None:
        with self._lock:
            f = self._flows.get(key)
            if f is None:
                if len(self._flows) >= FLOW_MAX:
                    oldest = min(self._flows.items(), key=lambda kv: kv[1]["last_ts"])[0]
                    self._flows.pop(oldest, None)
                f = {
                    "first_ts": ts, "last_ts": ts,
                    "packets_total": 0, "bytes_total": 0,
                    "packets_sent": 0,  "bytes_sent": 0,
                }
                self._flows[key] = f
            f["last_ts"] = ts
            f["packets_total"] += 1
            f["bytes_total"] += length

    def snapshot_deltas(self, now: float) -> list[Tuple[FlowKey, Dict[str, Any]]]:
        out: list[Tuple[FlowKey, Dict[str, Any]]] = []
        with self._lock:
            idle_cutoff = now - FLOW_IDLE_EVICT_SEC
            stale = [k for k, v in self._flows.items() if v["last_ts"] < idle_cutoff]
            for k in stale:
                self._flows.pop(k, None)

            for k, v in self._flows.items():
                pkt_delta  = v["packets_total"] - v["packets_sent"]
                byte_delta = v["bytes_total"]   - v["bytes_sent"]
                if pkt_delta <= 0:
                    continue
                snap = dict(v)
                snap["packets_delta"] = pkt_delta
                snap["bytes_delta"]   = byte_delta
                v["packets_sent"] = v["packets_total"]
                v["bytes_sent"]   = v["bytes_total"]
                out.append((k, snap))
        return out


# ─────────────────────────────────────────────────────────────
# Backend normalization
# ─────────────────────────────────────────────────────────────

def _normalize_for_backend(ev: Dict[str, Any], iface: str = "") -> Dict[str, Any]:
    out = dict(ev)

    proto = (ev.get("protocol") or ev.get("proto") or "")
    if proto:
        out["proto"] = str(proto).lower()

    if "src_ip" in ev:
        out["src"] = ev["src_ip"]
    if "dst_ip" in ev:
        out["dst"] = ev["dst_ip"]
    if "src_port" in ev:
        out["sport"] = ev["src_port"]
    if "dst_port" in ev:
        out["dport"] = ev["dst_port"]
    if "dns_qname" in ev and ev["dns_qname"]:
        out["dns"] = ev["dns_qname"]
    if "direction" in ev:
        out["dir"] = ev["direction"]

    try:
        out["ts"] = float(ev["ts"])
    except Exception:
        out["ts"] = time.time()

    out["sensor_id"] = build_sensor_id(iface or str(ev.get("iface", "")))

    src = out.get("src") or ""
    dst = out.get("dst") or ""
    src_zone = classify_zone(src)
    dst_zone  = classify_zone(dst)
    out["src_zone"] = src_zone
    out["dst_zone"]  = dst_zone

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


def _build_ingest_url(base: str) -> str:
    b = base.rstrip("/")
    if b.endswith("/api"):
        return b + "/traffic/ingest"
    return b + "/api/traffic/ingest"


# ─────────────────────────────────────────────────────────────
# Sender thread — with retry buffer
# ─────────────────────────────────────────────────────────────

def sender_thread(
    q: "queue.Queue[Dict[str, Any]]",
    url: str,
    client_key: str,
    stop: threading.Event,
) -> None:
    sess = requests.Session()
    headers = {"X-Client-Key": client_key} if client_key else {}
    buf: list[Dict[str, Any]] = []
    retry_buf: list[Dict[str, Any]] = []   # events that failed last send
    last_flush = time.time()

    while not stop.is_set():
        try:
            item = q.get(timeout=0.2)
            buf.append(item)
        except queue.Empty:
            pass

        now = time.time()
        should_flush = buf and (len(buf) >= BATCH_MAX or (now - last_flush) >= BATCH_SEC)

        if should_flush:
            payload = retry_buf + buf   # prepend any previously failed events
            retry_buf.clear()
            buf.clear()
            last_flush = now

            success = False
            for attempt in range(1, SENDER_RETRY_MAX + 1):
                try:
                    r = sess.post(url, headers=headers, json={"items": payload},
                                timeout=5, verify=VERIFY_TLS)
                    if r.status_code < 500:
                        print(f"[sent] {len(payload)} events  status={r.status_code}")
                        success = True
                        break
                    print(f"[send-warn] attempt {attempt} status={r.status_code}")
                except Exception as e:
                    print(f"[send-error] attempt {attempt}: {e}")
                time.sleep(0.5 * attempt)   # brief back-off between retries

            if not success:
                # Keep the most recent half to avoid unbounded memory growth
                retry_buf = payload[-(BATCH_MAX // 2):]
                print(f"[send-failed] {len(retry_buf)} events queued for next retry")


# ─────────────────────────────────────────────────────────────
# Flow flush thread
# ─────────────────────────────────────────────────────────────

def flow_flush_thread(
    flow_table: FlowTable,
    q: "queue.Queue[Dict[str, Any]]",
    iface: str,
    local_ips: Set[str],
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        time.sleep(FLOW_FLUSH_SEC)
        if not EMIT_FLOW_SUMMARY:
            continue
        now = time.time()
        for (src_ip, dst_ip, proto, sport, dport), snap in flow_table.snapshot_deltas(now):
            ev = {
                "ts": now,
                "iface": iface,
                "event_type": "FLOW_SUMMARY",
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "direction": compute_direction(src_ip, dst_ip, local_ips),
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
                q.put_nowait(_normalize_for_backend(ev, iface))
            except queue.Full:
                pass


# ─────────────────────────────────────────────────────────────
# Packet parsing → important events  (Wireshark-like)
# ─────────────────────────────────────────────────────────────

def packet_to_important_events(
    pkt,
    iface: str,
    local_ips: Set[str],
    flow_table: FlowTable,
) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    ts = float(getattr(pkt, "time", time.time()))

    src_mac = dst_mac = None
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    # ── ARP (LAN discovery + spoofing detection) ──────────────
    if ARP in pkt:
        a = pkt[ARP]
        warning = arp_cache.check_and_update(a.psrc, a.hwsrc) if a.op == 2 else None
        ev: Dict[str, Any] = {
            "ts": ts, "iface": iface,
            "event_type": "ARP_SPOOFING_ALERT" if warning else "ARP",
            "protocol": "ARP",
            "src_mac": src_mac, "dst_mac": dst_mac,
            "src_ip": a.psrc, "dst_ip": a.pdst,
            "hw_src": a.hwsrc, "hw_dst": a.hwdst,
            "arp_op": int(a.op),   # 1=request, 2=reply
            "arp_op_name": "reply" if a.op == 2 else "request",
            "length": int(len(pkt)),
            "direction": compute_direction(a.psrc, a.pdst, local_ips),
        }
        if warning:
            ev["warning"] = warning
            print(f"[ARP-SPOOF] {warning}")
        events.append(ev)
        return events

    # ── L3 extraction ──────────────────────────────────────────
    if IP in pkt:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        ttl = pkt[IP].ttl
    elif IPv6 in pkt:
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        ttl = pkt[IPv6].hlim
    else:
        return events

    length = int(len(pkt))

    # ── L4 extraction ─────────────────────────────────────────
    protocol = "OTHER"
    sport = dport = None
    flags_int = None
    flags_str = ""

    if TCP in pkt:
        protocol  = "TCP"
        sport     = int(pkt[TCP].sport)
        dport     = int(pkt[TCP].dport)
        flags_int = int(pkt[TCP].flags)
        flags_str = decode_tcp_flags(flags_int)
    elif UDP in pkt:
        protocol = "UDP"
        sport    = int(pkt[UDP].sport)
        dport    = int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"

    direction = compute_direction(src_ip, dst_ip, local_ips)

    # Update flow table for summaries
    if protocol in ("TCP", "UDP") and src_ip and dst_ip:
        flow_table.update((src_ip, dst_ip, protocol, sport, dport), ts, length)

    # ── DNS query + response ───────────────────────────────────
    if protocol == "UDP" and DNS in pkt and DNSQR in pkt:
        dns_layer = pkt[DNS]

        if dns_layer.qr == 0:   # query
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = ""
            ev = {
                "ts": ts, "iface": iface,
                "event_type": "DNS_QUERY",
                "protocol": "UDP", "app": "DNS",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": sport, "dst_port": dport,
                "src_mac": src_mac, "dst_mac": dst_mac,
                "dns_qname": qname,
                "dns_qtype": int(pkt[DNSQR].qtype),
                "length": length,
                "direction": direction,
            }
            events.append(ev)

        elif dns_layer.qr == 1:  # response — NEW
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = ""

            answers: list[str] = []
            try:
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an
                    for _ in range(i):
                        rr = rr.payload
                    if hasattr(rr, "rdata"):
                        answers.append(str(rr.rdata))
            except Exception:
                pass

            if qname or answers:
                ev = {
                    "ts": ts, "iface": iface,
                    "event_type": "DNS_RESPONSE",
                    "protocol": "UDP", "app": "DNS",
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": sport, "dst_port": dport,
                    "dns_qname": qname,
                    "dns_answers": answers,
                    "dns_answer_count": len(answers),
                    "length": length,
                    "direction": direction,
                }
                events.append(ev)

    # ── TCP events ─────────────────────────────────────────────
    if protocol == "TCP" and flags_int is not None:

        base_tcp: Dict[str, Any] = {
            "ts": ts, "iface": iface,
            "protocol": "TCP",
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport,
            "src_mac": src_mac, "dst_mac": dst_mac,
            "tcp_flags": flags_int,
            "tcp_flags_str": flags_str,
            "ttl": ttl,
            "length": length,
            "direction": direction,
        }
        hint = app_hint("TCP", sport, dport, base_tcp)
        if hint:
            base_tcp["app"] = hint

        # SYN — connection attempt
        if "SYN" in flags_str and "ACK" not in flags_str:
            ev = dict(base_tcp)
            ev["event_type"] = "TCP_SYN"
            events.append(ev)

        # RST — connection rejected or torn down
        elif "RST" in flags_str:
            ev = dict(base_tcp)
            ev["event_type"] = "TCP_RST"
            events.append(ev)

        # FIN — graceful close
        elif "FIN" in flags_str and "ACK" in flags_str:
            ev = dict(base_tcp)
            ev["event_type"] = "TCP_FIN"
            events.append(ev)

    # ── ICMP ──────────────────────────────────────────────────
    if protocol == "ICMP" and ICMP in pkt:
        icmp_type = int(pkt[ICMP].type)
        icmp_code = int(pkt[ICMP].code)

        # Only emit meaningful ICMP types
        ICMP_NAMES = {
            0: "echo-reply", 3: "dest-unreachable",
            8: "echo-request", 11: "time-exceeded",
            5: "redirect",
        }
        type_name = ICMP_NAMES.get(icmp_type, f"type-{icmp_type}")

        ev = {
            "ts": ts, "iface": iface,
            "event_type": "ICMP",
            "protocol": "ICMP",
            "src_ip": src_ip, "dst_ip": dst_ip,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_type_name": type_name,
            "ttl": ttl,
            "length": length,
            "direction": direction,
        }
        events.append(ev)

    return events


def packet_to_packet_event(pkt, iface: str, local_ips: Set[str]) -> Optional[Dict[str, Any]]:
    """Raw packet mode — one event per packet."""
    try:
        ts = float(getattr(pkt, "time", time.time()))
        src_mac = dst_mac = None
        if Ether in pkt:
            src_mac, dst_mac = pkt[Ether].src, pkt[Ether].dst

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
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None

        protocol = "OTHER"
        sport = dport = flags_int = None
        flags_str = ""

        if TCP in pkt:
            protocol  = "TCP"
            sport     = int(pkt[TCP].sport)
            dport     = int(pkt[TCP].dport)
            flags_int = int(pkt[TCP].flags)
            flags_str = decode_tcp_flags(flags_int)
        elif UDP in pkt:
            protocol = "UDP"
            sport    = int(pkt[UDP].sport)
            dport    = int(pkt[UDP].dport)
        elif ICMP in pkt:
            protocol = "ICMP"

        ev: Dict[str, Any] = {
            "ts": ts, "iface": iface,
            "protocol": protocol,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport,
            "src_mac": src_mac, "dst_mac": dst_mac,
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
    
def _check_enabled(sess, api_base, client_key, verify_tls):
    """Ask the backend if capture should be running."""
    try:
        r = sess.get(
            f"{api_base}/api/agent/enabled",
            params={"client_key": client_key},
            timeout=3,
            verify=verify_tls,
        )
        return r.json().get("enabled", True)
    except Exception:
        return True  # If backend unreachable, keep running

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="IntelliCloud IC Agent")
    ap.add_argument("--iface",  default=os.getenv("IC_IFACE", ""),       help="Network interface")
    ap.add_argument("--api",    default=API_BASE,                         help="Backend API base URL")
    ap.add_argument("--bpf",    default=os.getenv("IC_BPF", BPF_DEFAULT), help="BPF capture filter")
    ap.add_argument("--emit",   default=EMIT_MODE, choices=["important", "packets"])
    args = ap.parse_args()

    if not IC_CLIENT_KEY:
        print("ERROR: IC_CLIENT_KEY is not set. Add it to your .env file.")
        return 2

    iface = args.iface.strip() or best_effort_pick_iface() or ""
    if not iface:
        print("ERROR: No interface found. Install psutil or pass --iface.")
        return 2

    iface = resolve_iface(iface)
    ingest_url = _build_ingest_url(args.api)
    local_ips  = list_local_ips_for_iface(iface)

    print(json.dumps({
        "ok": True, "iface": iface,
        "local_ips": sorted(local_ips),
        "ingest_url": ingest_url,
        "bpf": args.bpf,
        "emit_mode": args.emit,
        "flow_summary": EMIT_FLOW_SUMMARY,
    }, indent=2))

    q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=QUEUE_MAX)
    stop = threading.Event()

    threading.Thread(
        target=sender_thread,
        args=(q, ingest_url, IC_CLIENT_KEY, stop),
        daemon=True,
    ).start()

    flow_table = FlowTable()
    threading.Thread(
        target=flow_flush_thread,
        args=(flow_table, q, iface, local_ips, stop),
        daemon=True,
    ).start()

    def handler(pkt):
        if args.emit == "packets":
            ev = packet_to_packet_event(pkt, iface, local_ips)
            if ev:
                try:
                    q.put_nowait(_normalize_for_backend(ev, iface))
                except queue.Full:
                    pass
            return
        for ev in packet_to_important_events(pkt, iface, local_ips, flow_table):
            try:
                q.put_nowait(_normalize_for_backend(ev, iface))
            except queue.Full:
                break

    # Auto-restart sniff on non-keyboard errors
    # Auto-restart sniff on non-keyboard errors
    check_sess = requests.Session()

    while True:
        try:
            if IC_POLL_ENABLED and not _check_enabled(check_sess, args.api, IC_CLIENT_KEY, VERIFY_TLS):
                print("[agent] Waiting for start signal from dashboard...")
                time.sleep(3)
                continue

            print(f"[sniff] Starting capture on {iface}  BPF: {args.bpf}")
            sniff(
                iface=iface,
                filter=args.bpf,
                prn=handler,
                store=False,
                stop_filter=lambda _: (
                    IC_POLL_ENABLED and
                    not _check_enabled(check_sess, args.api, IC_CLIENT_KEY, VERIFY_TLS)
                ),
            )
            print("[agent] Capture stopped by dashboard signal.")
        except KeyboardInterrupt:
            print("[agent] Stopped by user.")
            break
        except Exception as e:
            print(f"[sniff-error] Interface '{iface}' not found ! — restarting in 3s")
            time.sleep(3)

    stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())