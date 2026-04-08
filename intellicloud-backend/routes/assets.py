from flask import Blueprint, jsonify, request

from models.assets import (
    list_assets,
    get_asset_by_id,
    create_asset,
    update_asset,
    delete_asset,
)

bp = Blueprint("assets", __name__)


def _get_client_id() -> int:
    """
    Temporary client resolution.
    Replace this later with real client scoping from auth / API key context.
    """
    client_id = request.args.get("client_id") or request.headers.get("X-Client-Id") or 1
    try:
        return int(client_id)
    except (TypeError, ValueError):
        return 1


@bp.route("/assets", methods=["GET"])
def api_list_assets():
    client_id = _get_client_id()
    rows = list_assets(client_id)
    return jsonify({"items": rows, "count": len(rows)}), 200


@bp.route("/assets/<int:asset_id>", methods=["GET"])
def api_get_asset(asset_id: int):
    client_id = _get_client_id()
    row = get_asset_by_id(asset_id, client_id)
    if not row:
        return jsonify({"error": "asset_not_found"}), 404
    return jsonify(row), 200


@bp.route("/assets", methods=["POST"])
def api_create_asset():
    client_id = _get_client_id()
    data = request.get_json(silent=True) or {}

    ip_address = (data.get("ip_address") or "").strip()
    if not ip_address:
        return jsonify({"error": "ip_address_required"}), 400

    row = create_asset(
        client_id=client_id,
        ip_address=ip_address,
        display_name=data.get("display_name"),
        notes=data.get("notes"),
        trust_status=data.get("trust_status", "unknown"),
        last_seen=data.get("last_seen"),
    )

    if not row:
        return jsonify({"error": "asset_create_failed"}), 500

    return jsonify(row), 201


@bp.route("/assets/<int:asset_id>", methods=["PATCH"])
def api_update_asset(asset_id: int):
    client_id = _get_client_id()
    data = request.get_json(silent=True) or {}

    row = update_asset(
        asset_id=asset_id,
        client_id=client_id,
        display_name=data.get("display_name"),
        notes=data.get("notes"),
        trust_status=data.get("trust_status"),
        last_seen=data.get("last_seen"),
    )

    if not row:
        return jsonify({"error": "asset_not_found_or_update_failed"}), 404

    return jsonify(row), 200


@bp.route("/assets/<int:asset_id>", methods=["DELETE"])
def api_delete_asset(asset_id: int):
    client_id = _get_client_id()
    ok = delete_asset(asset_id, client_id)
    if not ok:
        return jsonify({"error": "asset_not_found_or_delete_failed"}), 404
    return jsonify({"ok": True, "deleted_id": asset_id}), 200