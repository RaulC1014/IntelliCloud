import json
from models.db import get_db_connection


def list_alerts(status=None, severity=None, detection_type=None):
    conn = get_db_connection()
    if not conn:
        return []

    where = []
    params = []

    if status:
        where.append("status = %s")
        params.append(status)
    if severity:
        where.append("severity = %s")
        params.append(severity)
    if detection_type:
        where.append("detection_type = %s")
        params.append(detection_type)

    sql = """
        SELECT id, created_at, status, severity, detection_type, reason,
            src_ip, dst_ip, protocol, src_port, dst_port, sensor_id, client_id
        FROM alerts
    """

    if where:
        sql += " WHERE " + " AND ".join(where)

    sql += " ORDER BY created_at DESC"

    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
            for r in rows:
                if r.get("created_at") and hasattr(r["created_at"], "isoformat"):
                    r["created_at"] = r["created_at"].isoformat()
            return rows
    except Exception as e:
        print("Failed to list alerts:", e)
        return []


def update_alert_status(alert_id: int, status: str) -> bool:
    conn = get_db_connection()
    if not conn:
        return False

    try:
        with conn, conn.cursor() as cur:
            if status == "closed":
                cur.execute(
                    """
                    UPDATE alerts
                    SET status = %s, closed_at = NOW()
                    WHERE id = %s
                    """,
                    (status, alert_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE alerts
                    SET status = %s
                    WHERE id = %s
                    """,
                    (status, alert_id),
                )
            return cur.rowcount > 0
    except Exception as e:
        print("Failed to update alert status:", e)
        return False


def create_alert(
    *,
    client_id: int | None,
    severity: str,
    detection_type: str,
    reason: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    sensor_id: str | None = None,
    event_payload: dict | None = None,
) -> int | None:
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None

    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                    status, severity, detection_type, reason,
                    src_ip, dst_ip, protocol, src_port, dst_port,
                    sensor_id, client_id, event_payload
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    "open",
                    severity,
                    detection_type,
                    reason,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    sensor_id,
                    client_id,
                    json.dumps(event_payload or {}, default=str),
                ),
            )
            row = cur.fetchone()
            return row["id"] if row else None
    except Exception as e:
        print("create_alert failed:", e)
        return None


def block_ip(client_id: int | None, ip: str, reason: str) -> None:
    conn = get_db_connection()
    if not conn:
        return

    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ip_blocklist (client_id, ip_address, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (client_id, ip, reason),
            )
    except Exception as e:
        print("block_ip failed:", e)


def is_ip_blocked(ip: str) -> bool:
    conn = get_db_connection()
    if not conn:
        return False

    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM ip_blocklist
                WHERE ip_address = %s
                LIMIT 1
                """,
                (ip,),
            )
            return cur.fetchone() is not None
    except Exception:
        return False