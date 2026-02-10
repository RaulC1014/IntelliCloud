import os, json, time, queue, collections, uuid, ipaddress, subprocess, signal, sys, threading
from datetime import datetime, timezone

from flask import Blueprint, Response, request, current_app
from flask_limiter.util import get_remote_address
from psycopg2.extras import execute_values
from services.traffic_detect import score_event
from extensions import limiter
from routes.audit import log_event
from services.geo import enrich_pair
from models.db import get_db_connection, put_db_connection

bp = Blueprint("traffic", __name__)

subscribers = set()
MAX_BACKLOG = int(os.getenv("TRAFFIC_BACKLOG", "1000"))
backlog = collections.deque(maxlen=MAX_BACKLOG)

# -------------------------
# Agent process control
# -------------------------

AGENT_PROC = None
AGENT_LOCK = threading.Lock()  

def _agent_cmd():
    """
    Launch ic_agent.py using the same Python interpreter as the backend.
    Assumes ic_agent.py is located at the backend root (../ic_agent.py from routes/).
    """
    here = os.path.dirname(os.path.abspath(__file__))        
    backend_root = os.path.abspath(os.path.join(here, ".."))  
    agent_path = os.path.join(backend_root, "ic_agent.py")
    return [sys.executable, agent_path]

@bp.route("/agent/status", methods=["GET"])
def agent_status():
    global AGENT_PROC
    with AGENT_LOCK:
        running = AGENT_PROC is not None and AGENT_PROC.poll() is None
        pid = AGENT_PROC.pid if running else None
    return {"ok": True, "running": running, "pid": pid}, 200

@bp.route("/agent/start", methods=["POST"])
def agent_start():
    """
    Option 1: Start the agent without piping stdout/stderr (prevents pipe-buffer deadlock).
    """
    global AGENT_PROC
    with AGENT_LOCK:
        if AGENT_PROC is not None and AGENT_PROC.poll() is None:
            return {"ok": True, "running": True, "pid": AGENT_PROC.pid}, 200

        cmd = _agent_cmd()

        
        env = os.environ.copy()
        
        env.setdefault("IC_API", (os.getenv("IC_API") or "http://localhost:5000").rstrip("/"))
        env.setdefault("IC_CLIENT_KEY", os.getenv("IC_CLIENT_KEY", ""))

        try:
            
            AGENT_PROC = subprocess.Popen(cmd, env=env)
        except Exception as e:
            current_app.logger.exception("Failed to start agent")
            return {"ok": False, "error": "agent_start_failed", "detail": str(e)}, 500

        log_event(actor="system", action="agent_start", target="ic_agent", details=f"pid={AGENT_PROC.pid}")
        return {"ok": True, "running": True, "pid": AGENT_PROC.pid}, 200

@bp.route("/agent/stop", methods=["POST"])
def agent_stop():
    global AGENT_PROC
    with AGENT_LOCK:
        if AGENT_PROC is None or AGENT_PROC.poll() is not None:
            AGENT_PROC = None
            return {"ok": True, "running": False}, 200

        try:
            if os.name == "nt":
               
                AGENT_PROC.terminate()
            else:
                AGENT_PROC.send_signal(signal.SIGTERM)

            try:
                AGENT_PROC.wait(timeout=3)
            except Exception:
                AGENT_PROC.kill()
        except Exception as e:
            current_app.logger.exception("Failed to stop agent")
            return {"ok": False, "error": "agent_stop_failed", "detail": str(e)}, 500

        pid = AGENT_PROC.pid
        AGENT_PROC = None

    log_event(actor="system", action="agent_stop", target="ic_agent", details=f"pid={pid}")
    return {"ok": True, "running": False}, 200

# -------------------------
# Traffic helpers / storage
# -------------------------

RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _get_client_key():
    return (
        request.headers.get("X-Client-Key")
        or request.args.get("client_key")
        or ""
    )

def _get_client_by_api_key(api_key: str):
    conn = get_db_connection()
    if conn is None:
        return None

    cur = None
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT client_id, client_name, api_key, domain, created_at
            FROM clients
            WHERE api_key = %s
            LIMIT 1
            """,
            (api_key,),
        )
        row = cur.fetchone()
        if not row:
            return None

        return {
            "client_id": row["client_id"],
            "client_name": row["client_name"],
            "api_key": row["api_key"],
            "domain": row["domain"],
            "created_at": row["created_at"],
        }
    except Exception:
        current_app.logger.exception("Client lookup failed")
        return None
    finally:
        try:
            if cur is not None:
                cur.close()
        except Exception:
            pass
        put_db_connection(conn)

def _is_inside(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_loopback or obj.is_link_local:
            return True
        return any(obj in net for net in RFC1918)
    except Exception:
        return False

def _to_int(x):
    try:
        return int(x)
    except Exception:
        return None

def _infer_dir(src, dst):
    if src and dst:
        if _is_inside(src) and not _is_inside(dst): return "outbound"
        if not _is_inside(src) and _is_inside(dst): return "inbound"
        if _is_inside(src) and _is_inside(dst): return "internal"
        return "external"
    return "unknown"

def _score_level(norm):
    suspicious = {22, 23, 25, 445, 3389, 5900, 1433}
    proto = (norm.get("proto") or "").lower()
    dport = norm.get("dport")
    if proto == "tcp" and dport in suspicious:
        return "High", f"TCP/{dport} is on the suspicious port list"
    if proto in {"tcp", "udp"} and (dport == 0 or dport is None):
        return "Medium", "Missing/invalid destination port for L4 traffic"
    return "Low", "Benign default based on current heuristic"

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

def _client_key_for_limiter():
    return request.headers.get("X-Client-Key") or get_remote_address()

_TRAFFIC_COILS = {
    "event_type","protocol","app","direction","iface",
    "src_ip","dst_ip","src_port","dst_port","src_mac","dst_mac",
    "dns_qname","tcp_flags_str","length","packets_delta","bytes_delta",
}

def _epoch_to_dt(ts_val):
    if ts_val is None:
        return None
    try:
        if isinstance(ts_val, (int, float)):
            return datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
    except Exception:
        pass
    return None

def _event_meta(ev: dict) -> dict:
    meta = {}
    for k, v in ev.items():
        if k in _TRAFFIC_COILS or k in ("ts", "event_ts"):
            continue
        meta[k] = v
    return meta

def _insert_traffic_events(client_id: int, items: list[dict]) -> int:
    rows = []
    for ev in items:
        if not isinstance(ev, dict):
            continue

        src_ip = ev.get("src_ip") or ev.get("src")
        dst_ip = ev.get("dst_ip") or ev.get("dst")

        proto = ev.get("protocol") or ev.get("l4") or ev.get("proto")
        if proto:
            p = str(proto).lower()
            proto = str(proto).upper() if p in ("tcp", "udp", "icmp", "arp") else str(proto)

        # safer than "or" (preserves 0 if it exists)
        raw_sport = ev.get("src_port")
        if raw_sport is None:
            raw_sport = ev.get("sport")
        sport = _to_int(raw_sport)

        raw_dport = ev.get("dst_port")
        if raw_dport is None:
            raw_dport = ev.get("dport")
        dport = _to_int(raw_dport)

        event_type = ev.get("event_type") or ev.get("type")
        app = ev.get("app")
        direction = ev.get("direction") or ev.get("dir") or _infer_dir(src_ip, dst_ip)

        iface = ev.get("iface")
        src_mac = ev.get("src_mac")
        dst_mac = ev.get("dst_mac")

        dns_qname = ev.get("dns_qname") or ev.get("dns")
        tcp_flags_str = ev.get("tcp_flags_str")

        length = _to_int(ev.get("length"))
        packets_delta = _to_int(ev.get("packets_delta"))
        bytes_delta = _to_int(ev.get("bytes_delta"))

        event_ts = _epoch_to_dt(ev.get("ts")) or _epoch_to_dt(ev.get("event_ts"))
        meta = ev.get("meta") if isinstance(ev.get("meta"), dict) else _event_meta(ev)

        rows.append((
            client_id, event_ts, event_type, proto, app, direction, iface,
            src_ip, dst_ip, sport, dport, src_mac, dst_mac,
            dns_qname, tcp_flags_str, length, packets_delta, bytes_delta,
            json.dumps(meta),
        ))

    if not rows:
        return 0

    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("db_unavailable")

    try:
        with conn.cursor() as cur:
            sql = """
                INSERT INTO traffic_events (
                  client_id, event_ts, event_type, protocol, app, direction, iface,
                  src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac,
                  dns_qname, tcp_flags_str, length, packets_delta, bytes_delta, meta
                ) VALUES %s
            """
            execute_values(cur, sql, rows, page_size=1000)
        conn.commit()
        return len(rows)
    finally:
        put_db_connection(conn)

# -------------------------
# In-memory SSE
# -------------------------

@bp.route("/stream/traffic")
def stream():
    def event_stream():
        q = queue.Queue()
        subscribers.add(q)
        try:
            for ev in list(backlog):
                eid = ev.get("eid") or ev.get("id")
                if eid:
                    yield f"id: {eid}\n"
                yield f"data: {json.dumps(ev)}\n\n"

            last_beat = 0.0
            while True:
                try:
                    ev = q.get(timeout=1.0)
                    eid = ev.get("eid") or ev.get("id")
                    if eid:
                        yield f"id: {eid}\n"
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

# -------------------------
# DB-backed Catch-up + SSE
# -------------------------

@bp.route("/traffic", methods=["GET"])
def traffic_list():
    client_key = _get_client_key()
    if not client_key:
        return {"error": "missing_client_key"}, 400

    client = _get_client_by_api_key(client_key)
    if not client:
        return {"error": "invalid_client_key"}, 403
    client_id = int(client["client_id"])

    since = request.args.get("since", default=0, type=int)
    limit = request.args.get("limit", default=500, type=int)
    limit = max(1, min(limit, 2000))

    conn = get_db_connection()
    if conn is None:
        return {"error": "db_unavailable"}, 503

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, client_id, event_ts, created_at, event_type, protocol, app, direction, iface,
                       src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac,
                       dns_qname, tcp_flags_str, length, packets_delta, bytes_delta, meta
                FROM traffic_events
                WHERE client_id = %s AND id > %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (client_id, since, limit),
            )
            rows = cur.fetchall() or []
        return {"ok": True, "items": rows}, 200
    finally:
        put_db_connection(conn)

@bp.route("/traffic/stream", methods=["GET"])
def traffic_stream_db():
    client_key = _get_client_key()
    if not client_key:
        return {"error": "missing_client_key"}, 400

    client = _get_client_by_api_key(client_key)
    if not client:
        return {"error": "invalid_client_key"}, 403
    client_id = int(client["client_id"])

    since_qs = request.args.get("since", default=0, type=int) or 0
    last_event_id = request.headers.get("Last-Event-ID")
    since_hdr = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0
    since = max(since_qs, since_hdr)

    def gen():
        nonlocal since
        last_beat = 0.0
        while True:
            conn = get_db_connection()
            if conn is None:
                yield ": db_unavailable\n\n"
                time.sleep(1.0)
                continue
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, client_id, event_ts, created_at, event_type, protocol, app, direction, iface,
                               src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac,
                               dns_qname, tcp_flags_str, length, packets_delta, bytes_delta, meta
                        FROM traffic_events
                        WHERE client_id = %s AND id > %s
                        ORDER BY id ASC
                        LIMIT 500
                        """,
                        (client_id, since),
                    )
                    rows = cur.fetchall() or []
            finally:
                put_db_connection(conn)

            if rows:
                for r in rows:
                    since = int(r["id"])
                    payload = json.dumps(r, default=str)
                    yield f"id: {since}\n"
                    yield f"data: {payload}\n\n"
            else:
                time.sleep(0.5)

            now = time.time()
            if now - last_beat >= 10.0:
                yield ": keep-alive\n\n"
                last_beat = now

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)

@bp.route("/traffic/ingest", methods=["POST"])
@limiter.limit("6000 per minute", key_func=_client_key_for_limiter)
def ingest():
    client_key = _get_client_key()
    if not client_key:
        return {"error": "missing_client_key"}, 400

    client = _get_client_by_api_key(client_key)
    if not client:
        return {"error": "invalid_client_key"}, 403

    client_id = int(client["client_id"])

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

    normalized_for_broadcast = []
    for ev in items:
        if not isinstance(ev, dict):
            continue

        src = ev.get("src") or ev.get("src_ip")
        dst = ev.get("dst") or ev.get("dst_ip")
        proto = (ev.get("proto") or ev.get("l4") or ev.get("protocol") or "ip").lower()

        sport = _to_int(ev.get("sport") if ev.get("sport") is not None else ev.get("src_port"))
        dport = _to_int(ev.get("dport") if ev.get("dport") is not None else ev.get("dst_port"))

        dns = ev.get("dns") or ev.get("dns_qname") or ""

        norm = {
            "eid": str(uuid.uuid4()),
            "client_id": client_id,
            "ts": ev.get("ts", time.time()),
            "src": src,
            "dst": dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "dns": dns,
            "event_type": ev.get("event_type"),
            "protocol": ev.get("protocol"),
            "app": ev.get("app"),
            "direction": ev.get("direction"),
            "iface": ev.get("iface"),
            "src_mac": ev.get("src_mac"),
            "dst_mac": ev.get("dst_mac"),
            "tcp_flags_str": ev.get("tcp_flags_str"),
            "length": ev.get("length"),
            "packets_delta": ev.get("packets_delta"),
            "bytes_delta": ev.get("bytes_delta"),
        }

        norm["dir"] = _infer_dir(src, dst)
        level, reason = score_event(norm)
        norm["level"] = level
        norm["reason"] = reason

        try:
            s_geo, d_geo = enrich_pair(src, dst, readers)
            if s_geo: norm["src_geo"] = s_geo
            if d_geo: norm["dst_geo"] = d_geo
        except Exception:
            pass

        if norm["level"] == "High":
            tgt = f"{src}:{sport} -> {dst}:{dport}"
            det = f"{(proto or '').upper()}/{dport} classified High"
            log_event(actor="system", action="alert", target=tgt, details=det)

        normalized_for_broadcast.append(norm)

    try:
        inserted = _insert_traffic_events(client_id, normalized_for_broadcast)
    except Exception as e:
        current_app.logger.exception("Traffic insert failed: %s", e)
        return {"error": "db_insert_failed"}, 503

    for norm in normalized_for_broadcast:
        _broadcast(norm)

    current_app.logger.info("Traffic ingest: received=%s inserted=%s", len(items), inserted)
    return {"ok": True, "received": len(items), "inserted": inserted}, 200