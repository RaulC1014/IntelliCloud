from flask import Blueprint, request, jsonify, g
from extensions import limiter
from auth import require_auth, require_role, verify_api
from models.threats import (
    insert_threat, get_all_threats, delete_threat_by_id,
    update_threat_by_id, get_audit_logs, log_action,
    get_threats_from_db, get_threats_for_user
)
from datetime import datetime
import re

threats_bp = Blueprint("threats_bp", __name__)

def is_valid_ipv4(ip: str) -> bool:
    if not isinstance(ip, str):
        return False
    
    if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
        return False
    
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False

@threats_bp.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "service": "threats"}), 200

@threats_bp.route("/public", methods=["GET"])
def public_threats():

    ip = request.args.get("ip")
    threat_level = request.args.get("threat_level")
    data = get_threats_from_db(ip, threat_level)
    return jsonify(data), 200

@threats_bp.route("/", methods=["GET"])
@require_auth
@limiter.limit("10 per minute")
def list_threats():

    uid = request.user["uid"]
    ip_filter = request.args.get("ip")
    level_filter = request.args.get("threat_level")

    items = get_threats_for_user(uid)

    if ip_filter:
        items = [t for t in items if t.get("ip_address") == ip_filter]

    if level_filter is not None:
        try:
            level_int = int(level_filter)
            items = [t for t in items if str(t.get("threat_level")) == str(level_int)]
        except ValueError:
            items = [t for t in items if str(t.get("threat_level")) == level_filter]

    return jsonify(items), 200

@threats_bp.route("/", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def add_threat():

    uid = request.user["uid"]
    data = request.get_json(silent=True) or {}

    ip_address = data.get("ip_address")
    threat_level = data.get("threat_level")
    description = data.get("description", "")
    timestamp_str = data.get("timestamp")

    if not ip_address or threat_level is None:
        return jsonify({"error": "Missing required fields"}), 400
    if not is_valid_ipv4(ip_address):
        return jsonify({"error": "Invalid IP format"}), 400

    timestamp = None
    if timestamp_str:
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return jsonify({"error": "Invalid timestamp format, use ISO 8601"}), 400

    insert_threat(
        ip_address,
        threat_level,
        client_id=None,
        description=description,
        timestamp=timestamp
    )
    log_action("create", uid)

    return jsonify({
        "message": "Threat inserted successfully",
        "ip_address": ip_address,
        "threat_level": threat_level,
        "description": description,
        "timestamp": (timestamp.isoformat() if timestamp else None)
    }), 201


@threats_bp.route("/<int:threat_id>", methods=["GET"])
@require_auth
def get_threat_by_id(threat_id):

    uid = request.user["uid"]
    items = get_threats_for_user(uid)
    for threat in items:
        if threat.get("id") == threat_id:
            return jsonify(threat), 200
    return jsonify({"error": "Threat not found"}), 404


@threats_bp.route("/<int:threat_id>", methods=["DELETE"])
@require_auth
def delete_threat(threat_id):

    uid = request.user["uid"]
    success = delete_threat_by_id(uid, threat_id)
    if success:
        log_action("delete", uid, threat_id)
        return jsonify({"message": f"Threat {threat_id} deleted successfully"}), 200
    return jsonify({"error": f"Threat {threat_id} not found"}), 404


@threats_bp.route("/<int:threat_id>", methods=["PATCH"])
@require_auth
def update_threat(threat_id):

    uid = request.user["uid"]
    updates = request.get_json(silent=True) or {}
    success = update_threat_by_id(uid, threat_id, updates)
    if success:
        log_action("update", uid, threat_id)
        return jsonify({"message": f"Threat {threat_id} updated successfully"}), 200
    return jsonify({"error": f"Threat {threat_id} not found or no valid fields provided"}), 404


@threats_bp.route("/audit-log", methods=["GET"])
@require_role("admin")
def list_audit_logs():

    logs = get_audit_logs()
    return jsonify(logs), 200


@threats_bp.route("/client/threats", methods=["GET"])
@verify_api
def list_threats_for_client():

    from models.threats import get_threats_for_client
    client_id = g.client["client_id"]

    ip_filter = request.args.get("ip")
    level_filter = request.args.get("threat_level")

    items = get_threats_for_client(client_id)

    if ip_filter:
        items = [t for t in items if t.get("ip_address") == ip_filter]
    if level_filter is not None:
        items = [t for t in items if str(t.get("threat_level")) == str(level_filter)]

    return jsonify(items), 200

@threats_bp.route("/external-log", methods=["POST"])
@verify_api
@limiter.limit("10 per minute")
def external_log_ip():

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    threat_level = data.get("threat_level", "low")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400
    if not is_valid_ipv4(ip):
        return jsonify({"error": "Invalid IP format"}), 400

    client_id = g.client["client_id"]
    insert_threat(
        ip,
        threat_level,
        client_id=client_id,
        description="external-log",
        timestamp=datetime.utcnow()
    )
    return jsonify({"message": f"IP {ip} logged for {g.client['client_name']}"}), 201

@threats_bp.route("/client/meta", methods=["GET"])
@verify_api
def get_client_meta():

    client = g.client
    return jsonify({
        "client_id": client["client_id"],
        "client_name": client["client_name"],
        "registered": client.get("created_at")
    }), 200


@threats_bp.errorhandler(500)
def internal_error(e):
    
    return jsonify({"error": "Internal Server Error"}), 500
