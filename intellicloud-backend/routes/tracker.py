from flask import Blueprint, request, jsonify
from models.tracker import log_visitor_ip
from models.db import get_db_connection

track_bp = Blueprint("track_bp", __name__, url_prefix="/api")

@track_bp.route("/track", methods=["POST"])
def track_ip():
    data = request.get_json()
    ip = data.get("ip")
    api_key = data.get("client_api_key")
    user_agent = request.headers.get("User-Agent", "unknown")

    if not ip or not api_key:
        return jsonify({"error": "Missing ip or client_api_key"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM client_keys WHERE api_key = %s;", (api_key,))
    client = cursor.fetchone()
    cursor.close()
    conn.close()

    if not client:
        return jsonify({"error": "Invalid API key"}), 403
    
    try:
        result = log_visitor_ip(ip, user_agent, client[0])
        return jsonify({
            "message": "IP logged successfully",
            "log_id": result["id"],
            "timestamp": result["timestamp"]
        }), 201
    except Exception as e:
        print("Tracking error:", e)
        return jsonify({"error:" "Server error"}), 500
