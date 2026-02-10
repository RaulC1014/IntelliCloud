import ipaddress
from flask import Blueprint, request, jsonify, current_app
from models.db import get_db_connection

bp = Blueprint("aliases", __name__)

def _valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except: return False

@bp.get("/ip-aliases")
def list_aliases():
    conn = get_db_connection()
    with conn.cursor() as cur:
       cur.execute("SELECT ip::text, alias, COALESCE(notes,'') FROM ip_aliases ORDER BY ip;")
       rows = cur.fetchall()
    return jsonify({"items":[{"ip":r[0],"alias":r[1],"notes":r[2]} for r in rows]})

@bp.put("/ip-aliases/<ip>")
def upsert_alias(ip):
    if not _valid_ip(ip):
        return jsonify({"error": "invalid_ip"}), 400
    j = request.get_json(force=True, silent=True) or {}
    alias = (j.get("alias") or "").strip()
    notes = (j.get("notes") or "").strip()
    if not alias:
        return jsonify({"error":"alias_required"}), 400
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO ip_aliases(ip, alias, notes)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET alias=EXCLUDED.alias, notes=EXCLUDED.notes, updated_at=now()
            """, (ip, alias, notes))
        conn.commit()
    return jsonify({"ok":True, "ip":ip, "alias":alias, "notes":notes})

@bp.delete("/ip-aliases/<ip>")
def delete_alias(ip):
    if not _valid_ip(ip):
        return jsonify({"error":"invalid_ip"}), 400
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ip_aliases WHERE ip = %s", (ip,))
        conn.commit()
    return jsonify({"ok":True})