import psycopg2
import os
from flask import Blueprint, request, jsonify
from werkzeug.exceptions import BadRequest
from ipaddress import ip_address
from models.db import get_db_connection, put_db_connection
from models.tracker import log_visitor_ip           # raw IP visit log
from services.rules_engine import eval_event 

          # rule engine → alerts/threats

collector_bp = Blueprint("collector", __name__, url_prefix="/api/collect")
try:
    from extensions import limiter
except Exception:  # no limiter available; create a no-op decorator
    def _noop(*args, **kwargs):
        def deco(f): return f
        return deco
    limiter = type("NoLimiter", (), {"limit": staticmethod(_noop)})

def _get_client_by_api_key(api_key: str):
    """
    Minimal direct lookup to avoid 'undefined' import errors.
    Expects a 'clients' table with columns: client_id, client_name, api_key, domain, created_at
    Returns a dict or None.
    """
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
    """
    Picks the right source IP. Handles common proxy headers.
    """
    xff = req.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = req.headers.get("X-Real-IP") or req.remote_addr or ""

    # Validate
    try:
        str(ip_address(ip))
    except Exception:
        ip = "0.0.0.0"
    return ip

@collector_bp.route("/ip", methods=["POST"])
@limiter.limit("60/minute")  # or remove if you don't use limiter
def collect_ip():
    """
    Ingestion endpoint used by the embeddable script.
    Contract:
    - Header:   X-Client-Key: <client API key>
    - Body:     { "page": "https://example.com/path" }   (optional)
    Response:     { ok: true, log: {...} }
    """
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

    # 1) raw log (for timeline/forensics)
    try:
        raw_log_row = log_visitor_ip(ip_address=ip, user_agent=ua, client_id=client["client_id"], page=page)
    except Exception as e:
        return jsonify({"error": "log_write_failed", "detail": str(e)}), 500

    # 2) evaluate detections → alerts/threat rows
    try:
        event = {
            "ip_address": ip,
            "user_agent": ua,
            "description": f"page={page}" if page else "",
            "threat_level": 0,   # initial; your rules can escalate
        }
        eval_event(event, client["client_id"])
    except Exception as e:
        # Detection errors should not break ingestion; just report
        return jsonify({"ok": True, "log": raw_log_row, "warn": f"detections_failed: {e}"}), 202

    return jsonify({"ok": True, "log": raw_log_row}), 201

# Health-check for debugging
@collector_bp.route("/_ping", methods=["GET"])
def ping():
    return jsonify({"ok": True})

