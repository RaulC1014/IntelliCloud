#!/usr/bin/env python3
import os, time, socket, json, threading, queue, argparse, requests
import pcapy  # pcapy-ng
import dpkt

API = os.getenv("IC_API", "http://localhost:5000")
INGEST = API.rstrip("/") + "/api/traffic/ingest"
BATCH_MAX = int(os.getenv("IC_BATCH_MAX", "200"))
BATCH_SEC = float(os.getenv("IC_BATCH_SEC", "1.0"))

def pkt_iter(dev, bpf):
    cap = pcapy.open_live(dev, 96, 1, 50)  # snaplen, promiscuous=1, timeout ms
    if bpf: cap.setfilter(bpf)
    while True:
        hdr, data = cap.next()
        if not hdr: 
            yield None
            continue
        yield (hdr, data)

def parse_ip(data):
    try:
        eth = dpkt.ethernet.Ethernet(data)
        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)): 
            return None
        ts = time.time()
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            proto = ip.p
            src = socket.inet_ntop(socket.AF_INET, ip.src)
            dst = socket.inet_ntop(socket.AF_INET, ip.dst)
        else:
            ip = eth.data
            proto = ip.nxt
            src = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst = socket.inet_ntop(socket.AF_INET6, ip.dst)

        sport = dport = None
        pname = "ip"
        if isinstance(ip.data, dpkt.tcp.TCP):
            pname = "tcp"; sport = int(ip.data.sport); dport = int(ip.data.dport)
        elif isinstance(ip.data, dpkt.udp.UDP):
            pname = "udp"; sport = int(ip.data.sport); dport = int(ip.data.dport)

        ev = {
            "ts": ts, "src": src, "dst": dst,
            "proto": pname, "sport": sport, "dport": dport,
            "len": len(data),
        }
        # optional DNS Q name (very light)
        try:
            if pname == "udp" and dport in (53, 5353, 853) or sport in (53, 5353, 853):
                dns = dpkt.dns.DNS(ip.data.data)
                if dns.qr == 0 and dns.qd:
                    ev["dns"] = dns.qd[0].name
        except Exception:
            pass
        return ev
    except Exception:
        return None

def sender(q: queue.Queue, url: str):
    sess = requests.Session()
    buf, last = [], time.time()
    while True:
        try:
            item = q.get(timeout=0.2)
            if item is None: break
            buf.append(item)
        except queue.Empty:
            pass
        now = time.time()
        if buf and (len(buf) >= BATCH_MAX or (now - last) >= BATCH_SEC):
            try:
                sess.post(url, json={"items": buf}, timeout=3)
            except Exception:
                pass
            buf.clear(); last = now

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True, help="Interface (e.g., eth0, en0)")
    ap.add_argument("--bpf", default="ip or ip6", help="BPF filter")
    ap.add_argument("--api", default=API)
    args = ap.parse_args()

    url = args.api.rstrip("/") + "/api/traffic/ingest"
    q = queue.Queue(maxsize=10000)
    t = threading.Thread(target=sender, args=(q, url), daemon=True); t.start()

    for p in pkt_iter(args.iface, args.bpf):
        if p is None: 
            continue
        _, data = p
        ev = parse_ip(data)
        if ev:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass

if __name__ == "__main__":
    main()
