import os, json, time, queue, collections, uuid, ipaddress, subprocess, signal, sys, threading
from datetime import datetime, timezone

from flask import Blueprint, Response, request, current_app
from flask_limiter.util import get_remote_address
from services.traffic_detect import score_event
from extensions import limiter
from services.geo import enrich_pair
from models.db import get_db_connection, put_db_connection
from auth import require_auth, verify_api
from services.rules_engine import evaluate_rules

bp = Blueprint("traffic", __name__)

# ── Fan-out broadcaster — each SSE client gets its own queue ─────────────────
class _Broadcaster:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: dict[int, queue.Queue] = {}
        self._next_id = 0

    def subscribe(self) -> tuple[int, queue.Queue]:
        q = queue.Queue(maxsize=500)
        with self._lock:
            cid = self._next_id
            self._next_id += 1
            self._clients[cid] = q
        return cid, q

    def unsubscribe(self, cid: int):
        with self._lock:
            self._clients.pop(cid, None)

    def publish(self, packet: dict):
        with self._lock:
            dead = []
            for cid, q in self._clients.items():
                try:
                    q.put_nowait(packet)
                except queue.Full:
                    dead.append(cid)
            for cid in dead:
                self._clients.pop(cid, None)

broadcaster = _Broadcaster()

# ── Agent state ───────────────────────────────────────────────────────────────
_agent_enabled: bool = False
_last_ingest_time: float = 0.0

AGENT_PROC = None
AGENT_LOCK = threading.Lock()

MAX_BACKLOG = int(os.getenv("TRAFFIC_BACKLOG", "1000"))
backlog = collections.deque(maxlen=MAX_BACKLOG)

# ── Agent control routes ──────────────────────────────────────────────────────

@bp.route("/agent/status", methods=["GET"])
@require_auth
def agent_status():
    running = _agent_enabled and (time.time() - _last_ingest_time) < 30
    return {"ok": True, "running": running, "pid": None}, 200


@bp.route("/agent/start", methods=["POST"])
@require_auth
def agent_start():
    global _agent_enabled
    _agent_enabled = True
    return {"ok": True, "running": True}, 200


@bp.route("/agent/stop", methods=["POST"])
@require_auth
def agent_stop():
    global _agent_enabled
    _agent_enabled = False
    return {"ok": True, "running": False}, 200


@bp.route("/agent/enabled", methods=["GET"])
def agent_enabled_check():
    """Public endpoint the agent polls to know if it should capture."""
    client_key = request.args.get("client_key", "")
    client = _get_client_by_api_key(client_key) if client_key else None
    if not client:
        return {"error": "unauthorized"}, 401
    return {"enabled": _agent_enabled}, 200

@bp.route("/agent/flush", methods=["POST"])
@require_auth
def agent_flush():
    """Drain the broadcaster queues for all connected clients."""
    with broadcaster._lock:
        for q in broadcaster._clients.values():
            try:
                while True:
                    q.get_nowait()
            except queue.Empty:
                pass
    return {"ok": True}, 200


# ── Traffic helpers ───────────────────────────────────────────────────────────

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
                FROM clients WHERE api_key = %s LIMIT 1
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
    finally:
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


def _client_key_for_limiter():
    return request.headers.get("X-Client-Key") or get_remote_address()


def _epoch_to_dt(ts_val):
    if ts_val is None:
        return None
    try:
        if isinstance(ts_val, (int, float)):
            return datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
    except Exception:
        pass
    return None


def _insert_alert(packet: dict, client_id: int | None = None) -> None:
    conn = get_db_connection()
    if conn is None:
        return
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                    status, severity, detection_type, reason,
                    src_ip, dst_ip, protocol, src_port, dst_port,
                    sensor_id, client_id, event_payload
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (
                    "open",
                    packet.get("level"),
                    packet.get("detection_type"),
                    packet.get("reason"),
                    packet.get("src_ip"),
                    packet.get("dst_ip"),
                    packet.get("protocol"),
                    packet.get("src_port"),
                    packet.get("dst_port"),
                    packet.get("sensor_id"),
                    client_id,
                    json.dumps(packet, default=str),
                ),
            )
    except Exception:
        current_app.logger.exception("Failed to insert alert")
    finally:
        put_db_connection(conn)


def _insert_traffic_event(packet: dict) -> None:
    conn = get_db_connection()
    if conn is None:
        return
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO traffic_events (
                    event_ts, src_ip, dst_ip, protocol,
                    src_port, dst_port, level, detection_type, reason,
                    sensor_id, src_zone, dst_zone, network_scope,
                    dns, direction, event_payload
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    packet.get("timestamp"),
                    packet.get("src_ip"),
                    packet.get("dst_ip"),
                    packet.get("protocol"),
                    packet.get("src_port"),
                    packet.get("dst_port"),
                    packet.get("level"),
                    packet.get("detection_type"),
                    packet.get("reason"),
                    packet.get("sensor_id"),
                    packet.get("src_zone"),
                    packet.get("dst_zone"),
                    packet.get("network_scope"),
                    packet.get("dns"),
                    packet.get("direction"),
                    json.dumps(packet, default=str),
                ),
            )
    except Exception:
        current_app.logger.exception("Failed to insert traffic event")
    finally:
        put_db_connection(conn)


# ── SSE stream ────────────────────────────────────────────────────────────────

@bp.route("/traffic/stream", methods=["GET"])
def traffic_stream_db():
    client_key = request.args.get("client_key", "")
    if not client_key:
        return Response(
            'data: {"error": "missing_client_key"}\n\n',
            mimetype="text/event-stream", status=401
        )
    client = _get_client_by_api_key(client_key)
    if not client:
        return Response(
            'data: {"error": "unauthorized"}\n\n',
            mimetype="text/event-stream", status=401
        )

    cid, my_queue = broadcaster.subscribe()

    def gen():
        try:
            yield f"data: {json.dumps({'status': 'connected'})}\n\n"
            while True:
                try:
                    packet = my_queue.get(timeout=1.0)
                    p = dict(packet)
                    if "timestamp" in p:
                        p["timestamp"] = str(p["timestamp"])
                    if "created_at" in p:
                        p["created_at"] = str(p["created_at"])
                    yield f"data: {json.dumps(p, default=str)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            broadcaster.unsubscribe(cid)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    })


# ── Recent traffic ────────────────────────────────────────────────────────────

@bp.route("/traffic/recent", methods=["GET"])
def traffic_recent():
    conn = get_db_connection()
    if conn is None:
        return {"error": "db_unavailable"}, 500
    try:
        limit = _to_int(request.args.get("limit")) or 100
        limit = max(1, min(limit, 1000))
        ip = (request.args.get("ip") or "").strip()
        protocol = (request.args.get("protocol") or "").strip().upper()
        level = (request.args.get("level") or "").strip()

        where, params = [], []
        if ip:
            where.append("(src_ip = %s OR dst_ip = %s)")
            params.extend([ip, ip])
        if protocol:
            where.append("protocol = %s")
            params.append(protocol)
        if level:
            where.append("level = %s")
            params.append(level)

        sql = """
            SELECT id, created_at, event_ts, src_ip, dst_ip, protocol,
                src_port, dst_port, level, detection_type, reason,
                sensor_id, src_zone, dst_zone, network_scope, dns, direction
            FROM traffic_events
        """
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        with conn, conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

        items = []
        for r in rows:
            items.append({
                "id": r["id"],
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
                "event_ts": r["event_ts"].isoformat() if r.get("event_ts") else None,
                "src_ip": r.get("src_ip"),
                "dst_ip": r.get("dst_ip"),
                "protocol": r.get("protocol"),
                "src_port": r.get("src_port"),
                "dst_port": r.get("dst_port"),
                "level": r.get("level"),
                "detection_type": r.get("detection_type"),
                "reason": r.get("reason"),
                "sensor_id": r.get("sensor_id"),
                "src_zone": r.get("src_zone"),
                "dst_zone": r.get("dst_zone"),
                "network_scope": r.get("network_scope"),
                "dns": r.get("dns"),
                "direction": r.get("direction"),
            })
        return {"items": items, "count": len(items)}, 200
    except Exception:
        current_app.logger.exception("Failed to fetch recent traffic")
        return {"error": "traffic_recent_failed"}, 500
    finally:
        put_db_connection(conn)


# ── Ingest ────────────────────────────────────────────────────────────────────

@bp.route("/traffic/ingest", methods=["POST"])
@limiter.limit("6000 per minute", key_func=_client_key_for_limiter)
@verify_api
def ingest():
    global _last_ingest_time
    try:
        data = request.get_json(force=True, silent=True)
        if data is None:
            return {"error": "bad_json"}, 400

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items") or data.get("events", [])
        else:
            return {"error": "bad_payload_type"}, 400

        if not isinstance(items, list):
            return {"error": "items_must_be_list"}, 400

        _last_ingest_time = time.time()

        client_id = None
        api_key = _get_client_key()
        client = _get_client_by_api_key(api_key) if api_key else None
        if client:
            client_id = client.get("client_id")

        count = 0
        skipped = 0

        for item in items:
            if not isinstance(item, dict):
                skipped += 1
                continue

            norm = {
                "src": item.get("src") or item.get("src_ip"),
                "dst": item.get("dst") or item.get("dst_ip"),
                "proto": (item.get("proto") or item.get("protocol") or "").lower(),
                "sport": _to_int(item.get("sport") or item.get("src_port")),
                "dport": _to_int(item.get("dport") or item.get("dst_port")),
                "dns": item.get("dns"),
                "dir": item.get("dir") or item.get("direction"),
                "src_zone": item.get("src_zone"),
                "dst_zone": item.get("dst_zone"),
                "network_scope": item.get("network_scope"),
                "sensor_id": item.get("sensor_id"),
                "ts": item.get("ts"),
            }

            level, reason, detection_type = score_event(norm)

            packet = {
                "id": str(uuid.uuid4()),
                "src_ip": norm.get("src"),
                "dst_ip": norm.get("dst"),
                "protocol": (norm.get("proto") or "").upper(),
                "src_port": norm.get("sport"),
                "dst_port": norm.get("dport"),
                "level": level,
                "reason": reason,
                "detection_type": detection_type,
                "sensor_id": norm.get("sensor_id"),
                "src_zone": norm.get("src_zone"),
                "dst_zone": norm.get("dst_zone"),
                "network_scope": norm.get("network_scope"),
                "dns": norm.get("dns"),
                "direction": norm.get("dir"),
                "timestamp": _epoch_to_dt(norm.get("ts")) or datetime.now(timezone.utc),
                "info": reason,
            }

            _insert_traffic_event(packet)

            triggered_rules = evaluate_rules(packet, client_id=client_id)
            for rule in triggered_rules:
                current_app.logger.info(
                    "Rule triggered: %s severity=%s", rule["rule_id"], rule["severity"]
                )

            broadcaster.publish(packet)
            count += 1

            if level in {"High", "Medium"}:
                _insert_alert(packet, client_id=client_id)

        return {"ok": True, "count": count, "skipped": skipped}, 200

    except Exception as e:
        current_app.logger.exception("Ingest failed")
        return {"error": str(e)}, 500