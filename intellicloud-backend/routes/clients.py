from flask import Blueprint, request, jsonify
from auth import require_role
from models.clients import create_client, get_all_clients


clients_bp = Blueprint("clients", __name__, url_prefix="/api/clients")

@clients_bp.route("/", methods=["POST"])
@require_role("admin")
def register_client(user):
    data = request.get_json()
    name = data.get("name")
    domain = data.get("domain")

    if not name or not domain:
        return jsonify({"error": "Missing name or domain"}), 400
    
    client = create_client(name, domain)
    return jsonify(client), 201

@clients_bp.route("/", methods=["GET"])
@require_role("admin")
def list_clients(user):
    clients = get_all_clients()
    for c in clients:
        c["api_key"] = "hidden"
    return jsonify(clients), 200