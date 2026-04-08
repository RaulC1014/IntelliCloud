import psycopg2
import os
from flask import Blueprint, request, jsonify
from werkzeug.exceptions import BadRequest
from ipaddress import ip_address
from models.db import get_db_connection, put_db_connection
from models.tracker import log_visitor_ip           # raw IP visit log
from services.rules_engine import eval_event 
# === [FIX 1] Import the live stream queue ===
from routes.traffic import global_queue  

collector_bp = Blueprint("collector", __name__, url_prefix="/api/collect")
try:
    from extensions import limiter
except Exception:
    def _noop(*args, **kwargs):
        def deco(f): return f
        return deco
    limiter = type("NoLimiter", (), {"limit": staticmethod(_noop)})

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

def _best_ip_from_request(req) -> str:
    xff = req.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = req.headers.get("X-Real-IP") or req.remote_addr or ""
    try:
        str(ip_address(ip))
    except Exception:
        ip = "0.0.0.0"
    return ip

@collector_bp.route("/ip", methods=["POST"])
@limiter.limit("60/minute")
def collect_ip():
    client_key = request.headers.get("X-Client-Key")
    if not client_key:
        return jsonify({"error": "missing_client_key"}), 400

    client = _get_client_by_api_key(client_key)
    if not client:
        return jsonify({"error": "invalid_client_key"}), 403

    ip = _best_ip_from_request(request)
    ua = request.headers.get("User-Agent", "unknown")
    payload = request.get_json(silent=True) or {}
    page = (payload.get("page") or "").strip()

    # 1) Log to Database
    try:
        raw_log_row = log_visitor_ip(ip_address=ip, user_agent=ua, client_id=client["client_id"], page=page)
    except Exception as e:
        return jsonify({"error": "log_write_failed", "detail": str(e)}), 500

    try:
        live_data = {
            "id": raw_log_row.get("id"),
            "src_ip": ip,
            "dst_ip": "127.0.0.1", # Local traffic
            "protocol": "HTTP",
            "length": request.content_length or 0,
            "info": f"Page Visit: {page}" if page else f"User-Agent: {ua[:30]}...",
            "timestamp": raw_log_row.get("created_at")
        }
        global_queue.put(live_data)
        print(f"[DEBUG] Pushed to queue: {ip}") # Print so you can see it working
    except Exception as e:
        print(f"[ERROR] Queue push failed: {e}")
 

    # 2) Evaluate Threats
    try:
        event = {
            "ip_address": ip,
            "user_agent": ua,
            "description": f"page={page}" if page else "",
            "threat_level": 0,
        }
        eval_event(event, client["client_id"])
    except Exception as e:
        return jsonify({"ok": True, "log": raw_log_row, "warn": f"detections_failed: {e}"}), 202

    return jsonify({"ok": True, "log": raw_log_row}), 201

@collector_bp.route("/_ping", methods=["GET"])
def ping():
    return jsonify({"ok": True})