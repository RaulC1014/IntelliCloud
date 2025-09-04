from flask import Blueprint, request, jsonify
from models.db import get_db_connection
from auth import authenticate_request, require_auth
from datetime import datetime

collector_bp = Blueprint("collector_bp", __name__, url_prefix="/api/collect")

@collector_bp.route("/ip", methods=["POST"])
@require_auth
def collect_ip():
    try:
        ip_address = request.remote_addr or request.headers.get('X-Forwarded-For')
        user_agent = request.headers.get("User-Agent", "unknown")
        page = request.json.get("page", "unknown")
        timestamp = datetime.utcnow()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSET INTO ip_logs (ip_address, user_agent, page_visited, timestamp)
            VALUES (%s, %s, %s, %s)
            """, (ip_address, user_agent, page, timestamp))
        
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "IP logged successfully"}), 201
    
    except Exception as e:
        return jsonify({"error could not log IP": str(e)}), 500 