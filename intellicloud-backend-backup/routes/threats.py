from flask import Blueprint, request, jsonify, g
from models.threats import (
    insert_threat, get_all_threats, delete_threat_by_id, 
    update_threat_by_id, get_audit_logs, log_action, 
    get_threats_from_db, get_threats_for_user,get_audit_logs_for_user,
    create_client
)

from app import limiter

from auth import require_auth, require_role

from auth import verify_api
from datetime import datetime

import re

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.{3}[0-9]{1,3}$)")
    return pattern.match(ip)

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/client/threats", methods=["GET"])
@verify_api
def list_threats_for_client():
    from models.threats import get_threats_for_client
    client_id = g.client["client_id"]

    ip_filter = request.args.get("ip")
    level_filter = request.args.get("threat_level")

    threats = get_threats_for_client(client_id)

    if ip_filter:
        threats = [t for t in threats if t["ip_address"] == ip_filter]

    if level_filter:
        try:
            level_filter = int(level_filter)
            threats = [t for t in threats if t["threat_level"] == level_filter]
        except ValueError:
            return jsonify({"error": "Invalid threat_level, must be an integer"}), 400
        
    return jsonify(threats), 200 

@threats_bp.route("/external-log", methods=["POST"])
@verify_api
@limiter.limit("10 per minute")
def external_log_ip():
    data = request.get_json()
    ip = data.get("ip")
    threat_level = data.get("threat_level", "low")

    if not ip:
        return jsonify({"error": "Missing IP"}), 400
    
    from models.threats import insert_threat
    client_id = g.client["client_id"]
    insert_threat(ip, threat_level, client_id=client_id)

    return jsonify({"message": f"IP {ip} logged for {g.client['client_name']}"}), 201

@threats_bp.route('/public', methods=['GET'])
def get_threats():
    ip = request.args.get('ip')
    threat_level = request.args.get('threat_level')

    threats = get_threats_from_db(ip, threat_level)
    return jsonify(threats)    


@threats_bp.route("/", methods=["POST"])
@limiter.limit("20 per minute")
@require_auth
def add_threat(user):

    data = request.get_json()
    ip_address = data.get("ip_address")
    threat_level = data.get("threat_level")
    description = data.get("description", "")
    timestamp_str = data.get("timestamp")

    if not ip_address or threat_level is None:
        return jsonify({"error": "Missing required fields"}), 400
    
    if not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid IP format"}), 400

    if timestamp_str:
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return jsonify({"error": "Invalid timestamp format, use ISO 8601"}), 400
    else:
        timestamp = datetime.now()
    
    insert_threat(ip_address, threat_level, client_id=None, description=None, timestamp=None)
    log_action("create", user["user_id"])

    return jsonify({
        "message": "Threat inserted successfully",
        "ip_address": ip_address,
        "threat_level": threat_level,
        "description": description,
        "timestamp": timestamp.isoformat()
    }), 201


@threats_bp.route("/", methods=["GET"])
@require_auth
def list_threats(user):
    ip_filter = request.args.get("ip")
    level_filter = request.args.get("threat_level")

    all_threats = get_threats_for_user(user["user_id"])

    if ip_filter:
        all_threats = [t for t in all_threats if t["ip_address"] == ip_filter]
   
    if level_filter:
        try:
            level_filter = int(level_filter)
            all_threats = [t for t in all_threats if t["threat_level"] == level_filter]
        except ValueError:
            return jsonify({"error": "Invalid threat_level, must be an integer"}), 400

    return jsonify(all_threats), 200

@threats_bp.route("/<int:threat_id>", methods=["GET"])
@require_auth
def get_threat_by_id(user, threat_id):
    all_threats = get_threats_for_user(user["user_id"])
    for threat in all_threats:
        if threat["id"] == threat_id:
            return jsonify(threat), 200
    return jsonify({"error": "Threat not found}), 404"})


@threats_bp.route("/<int:threat_id>", methods=["DELETE"])
@require_auth
def delete_threat(user, threat_id):
    success = delete_threat_by_id(user["user_id"], threat_id)

    if success:
        log_action("delete", user["user_id"], threat_id)
        return jsonify({"message": f"Threat {threat_id} deleted successfully"}), 200
    else:
        return jsonify({"error": f"Threat {threat_id} not found"}), 404
    

@threats_bp.route("/<int:threat_id>", methods=["PATCH"])
@require_auth
def update_threat(user, threat_id):
    updates = request.get_json()
    success = update_threat_by_id(user["user_id"], threat_id, updates)

    if success:
        log_action("update", user["user_id"], threat_id)
        return jsonify({"message": f"Threat {threat_id} updated successfully"}), 200
    else:
        return jsonify({"error": f"Threat {threat_id} not found or no valid fields provided"}), 404
    

@threats_bp.route("/audit-log", methods=["GET"])
@require_role("admin")
def list_audit_logs(user):
    if user.get("role") == "admin":
        logs = get_audit_logs()
    else:
        logs = get_audit_logs_for_user(user["user_id"])
    return jsonify(logs), 200

@threats_bp.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal Server Error"}), 500

@threats_bp.route("/client/meta", methoda=["GET"])
@verify_api
def get_client_meta():
    client = g.client
    return jsonify({
        "client_id": client["client_id"],
        "client_name": client ["client_name"],
        "registered": client.get("created_at", "unknown")
    }), 200

@threats_bp.route("/all", methods=["GET"])
@require_role("admin")
def list_all_threats(user):
    threats = get_all_threats()
    return jsonify(threats), 200

def register_client(user):
    data = request.get_json()
    client_name = data.get("client_name")

    if not client_name:
        return jsonify({"error": "Missing client_name"}), 400
    
    new_client = create_client(client_name)

    if new_client:
        return jsonify ({
            "message": "Client registered successfully",
            "client": new_client
        }), 201
    else:
        return jsonify({"error": "Failed to register client"}), 500
    

@app.route("/ping")
@limiter.limit("5 per minute")
def ping():
    return jsonify({"Message": "pong"})

