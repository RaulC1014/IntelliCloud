import json, time, queue, collections, uuid, ipaddress, os
from flask import Blueprint, Response, request, current_app
from routes.audit import log_event
from services.geo import enrich_pair

bp = Blueprint("traffic", __name__)

last_event_ts = 0.0
subscribers = set()
MAX_BACKLOG = int(os.getenv("TRAFFIC_BACKLOG", "1000"))
backlog = collections.deque(maxlen=MAX_BACKLOG)


RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _is_inside(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_loopback or obj.is_link_local:
            return True
        return any(obj in net for net in RFC1918)
    except Exception:
        return False

def _to_int(x):
    try: return int(x)
    except: return None

def _infer_dir(src, dst):
    if _is_inside(src) and not _is_inside(dst): return "outbound"
    if not _is_inside(src) and _is_inside(dst): return "inbound"
    if _is_inside(src) and _is_inside(dst):     return "internal"
    return "external"

def _score_level(norm):
    suspicious = {22, 23, 25, 445, 3389, 5900, 1433}
    proto = (norm.get("proto") or "").lower()
    dport = norm.get("dport") or 0
    return "High" if (proto == "tcp" and dport in suspicious) else "Low"

def _broadcast(ev: dict):
    backlog.append(ev)
    dead = []
    for q in list(subscribers):
        try:
            q.put_nowait(ev)
        except Exception:
            dead.append(q)
    for q in dead:
        subscribers.discard(q)

@bp.route("/stream/traffic")
def stream():
    def event_stream():
        q = queue.Queue()
        subscribers.add(q)
        try:
            for ev in list(backlog):
                yield f"data: {json.dumps(ev)}\n\n"
            last_beat = 0.0
            while True:
                try:
                    ev = q.get(timeout=1.0)
                    yield f"data: {json.dumps(ev)}\n\n"
                except queue.Empty:
                    pass
                now = time.time()
                if now - last_beat >= 3.0:
                    yield ": keep-alive\n\n"
                    last_beat = now
        finally:
            subscribers.discard(q)
    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)

@bp.route("/traffic/ingest", methods=["POST"])
def ingest():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return {"error": "bad_json"}, 400
    items = data if isinstance(data, list) else data.get("items", [])
    if not isinstance(items, list):
        return {"error": "items_must_be_list"}, 400

    readers = (
        current_app.extensions.get("geo")
        or current_app.config.get("GEO_READERS")
        or {}
    )

    global last_event_ts
    count = 0
    for ev in items:
        if not isinstance(ev, dict):
            continue
        norm = {
            "eid": str(uuid.uuid4()),
            "ts": ev.get("ts", time.time()),
            "src": ev.get("src"),
            "dst": ev.get("dst"),
            "proto": ev.get("proto", "ip"),
            "sport": _to_int(ev.get("sport")),
            "dport": _to_int(ev.get("dport")),
            "dns":  ev.get("dns") or "",
        }
        norm["dir"]   = _infer_dir(norm.get("src"), norm.get("dst"))
        norm["level"] = _score_level(norm)

        try:
            s_geo, d_geo = enrich_pair(norm.get("src"), norm.get("dst"), readers)
            if s_geo: norm["src_geo"] = s_geo
            if d_geo: norm["dst_geo"] = d_geo
        except Exception:
            pass

        if norm["level"] == "High":
            tgt = f"{norm.get('src')}:{norm.get('sport')} -> {norm.get('dst')}:{norm.get('dport')}"
            det = f"{(norm.get('proto') or '').upper()}/{norm.get('dport')} classified High"
            log_event(actor="system", action="alert", target=tgt, details=det)

        _broadcast(norm)
        last_event_ts = float(norm["ts"]) or time.time()
        count += 1

    current_app.logger.info("Traffic ingest: %s events", count)
    return {"ok": True, "received": count}, 200
