from flask import Blueprint, request, jsonify
from auth import require_role, require_auth
from models.clients import create_client, get_all_clients

clients_bp = Blueprint("clients", __name__, url_prefix="/api/clients")

@clients_bp.route("/", methods=["GET"])
@require_role("admin")
@require_auth
def list_clients(user):
    clients = get_all_clients()
    for c in clients:
        c["api_key"] = "hidden"
    return jsonify(clients), 200

@clients_bp.route("/", methods=["POST"])
@require_auth
@require_role("admin")
def register_client(user):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    domain = (data.get("domain") or "").strip() or None

    if not name:
        return jsonify({"error": "Missing name"}), 400

    row = create_client(name, domain)
    if not row:
        return jsonify({"error": "create_client_failed"}), 500

    
    api_key = row.get("api_key") if hasattr(row, "get") else row[3]

    return jsonify({
        "ok": True,
        "client": {
            "client_id": row["client_id"] if hasattr(row, "get") else row[0],
            "client_name": row["client_name"] if hasattr(row, "get") else row[1],
            "domain": row["domain"] if hasattr(row, "get") else row[2],
            "created_at": row["created_at"] if hasattr(row, "get") else row[4],
        },
        "api_key": api_key,
        "warning": "Copy this key now. It may not be shown again."
    }), 201
