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

# === [FIX 1] Define the Global Queue for live traffic ===
global_queue = queue.Queue()
# ========================================================

subscribers = set()
MAX_BACKLOG = int(os.getenv("TRAFFIC_BACKLOG", "1000"))
backlog = collections.deque(maxlen=MAX_BACKLOG)

# -------------------------
# Agent process control
# -------------------------

AGENT_PROC = None
AGENT_LOCK = threading.Lock()

def _agent_cmd():
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
    try:
        with conn.cursor() as cur:
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
            if not row: return None
            return {
                "client_id": row["client_id"],
                "client_name": row["client_name"],
                "api_key": row["api_key"],
                "domain": row["domain"],
                "created_at": row["created_at"],
            }
    finally:
        put_db_connection(conn)

def _is_inside(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_loopback or obj.is_link_local: return True
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
    return "Low", "Benign"

def _client_key_for_limiter():
    return request.headers.get("X-Client-Key") or get_remote_address()

def _epoch_to_dt(ts_val):
    if ts_val is None: return None
    try:
        if isinstance(ts_val, (int, float)):
            return datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
    except Exception: pass
    return None

# -------------------------
# Stream Endpoints
# -------------------------

@bp.route("/traffic/stream", methods=["GET"])
def traffic_stream_db():
    # 1. Authenticate
    client_key = request.args.get("client_key") # simplify getting key
    if not client_key:
        return Response("data: {'error': 'missing_client_key'}\n\n", mimetype='text/event-stream')

    # 2. Setup Generator
    def gen():
        yield f"data: {json.dumps({'status': 'connected'})}\n\n"
        
        while True:
            try:
                # Wait for packet (1.0s timeout to allow heartbeat)
                packet = global_queue.get(timeout=1.0)
                print(f"??? POPPED FROM QUEUE: {packet.get('id')} ???")
                # --- SAFETY BLOCK: Ensure data is clean ---
                # Convert timestamps to strings so JSON doesn't crash
                if 'timestamp' in packet:
                    packet['timestamp'] = str(packet['timestamp'])
                if 'created_at' in packet:
                    packet['created_at'] = str(packet['created_at'])
                
                # Send
                yield f"data: {json.dumps(packet, default=str)}\n\n"
                
            except queue.Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break # Client disconnected
            except Exception as e:
                # Print error to terminal but DON'T crash the stream
                print(f"[STREAM ERROR] {e}") 
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(1)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    })

# -------------------------
# Ingest (Standard Route)
# -------------------------
# Note: Your collector.py uses /api/collect/ip, but this handles batch ingest
@bp.route("/traffic/ingest", methods=["POST"])
@limiter.limit("6000 per minute", key_func=_client_key_for_limiter)
def ingest():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return {"error": "bad_json"}, 400

        # The sensor sends a list of items
        items = data.get("items", [])
        
        count = 0
        for item in items:
            # PUSH EACH ITEM TO THE QUEUE
            # We normalize it to look like what the frontend expects
            packet = {
                "id": str(uuid.uuid4()),
                "src_ip": item.get("src_ip", "0.0.0.0"),
                "dst_ip": item.get("dst_ip", "0.0.0.0"),
                "protocol": item.get("protocol", "IP"),
                "length": item.get("length", 0),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "info": f"{item.get('protocol')} packet"
            }
            global_queue.put(packet)
            count += 1
            
        print(f"[DEBUG] Ingested {count} packets into queue")
        return {"ok": True, "count": count}, 200
        
    except Exception as e:
        print(f"[ERROR] Ingest failed: {e}")
        return {"error": str(e)}, 500