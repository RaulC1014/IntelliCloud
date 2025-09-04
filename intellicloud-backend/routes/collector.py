from flask import Blueprint, request, jsonify, g
from datetime import datetime
from auth import verify_api
from extensions import limiter
from models.threats import insert_threat

collector_bp = Blueprint("collector_bp", __name__)

def _best_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

@collector_bp.route("/ip", methods=["POST"])
@verify_api
@limiter.limit("10 per minute")
def collect_ip():
    data = request.get_json(silent=True) or {}
    page = str(data.get("page", "unknown"))[:255]
    user_agent = (request.headers.get("User-Agent") or "unknown")[:255]
    ip_address = _best_client_ip()

    insert_threat(
        ip_address=ip_address,
        threat_level=0,                       
        client_id=g.client["client_id"],      
        description=f"page={page} ua={user_agent}",
        timestamp=datetime.utcnow()
    )

    return jsonify({"ok": True, "logged_ip": ip_address, "client_id": g.client["client_id"]}), 201
