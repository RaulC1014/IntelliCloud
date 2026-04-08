from flask import Blueprint, jsonify, request
from auth import require_auth
from models.alerts import list_alerts, update_alert_status

bp = Blueprint("alerts", __name__)

@bp.route("/alerts", methods=["GET"])
def get_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    detection_type = request.args.get("detection_type")

    items = list_alerts(
        status = status,
        severity = severity,
        detection_type = detection_type,
    )

    return jsonify(items), 200

@bp.route("/alerts/<int:alert_id>", methods=["PATCH"])
def patch_alert(alert_id: int):
    data = request.get_json(silent=True) or {}
    status = data.get("status")

    if not status:
        return jsonify({"error": "missing_status"}), 400
    
    ok = update_alert_status(alert_id, status)
    if not ok:
        return jsonify({"error": "alert_not_found"}), 404
    
    return jsonify({"ok": True, "id": alert_id, "status": status}), 200