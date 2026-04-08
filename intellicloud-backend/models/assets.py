from typing import Optional, Any

from models.db import get_db_connection, put_db_connection


ALLOWED_TRUST_STATUSES = {"unknown", "trusted", "untrusted", "monitor"}


def _normalize_trust_status(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    value = value.strip().lower()
    return value if value in ALLOWED_TRUST_STATUSES else "unknown"


def list_assets(client_id: int) -> list[dict[str, Any]]:
    conn = get_db_connection()
    if not conn:
        return []

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    client_id,
                    host(ip_address) AS ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen,
                    created_at,
                    updated_at
                FROM network_assets
                WHERE client_id = %s
                ORDER BY
                    COALESCE(last_seen, created_at) DESC,
                    id DESC
                """,
                (client_id,),
            )
            rows = cur.fetchall()
            return rows or []
    except Exception as e:
        print("list_assets failed:", e)
        return []
    finally:
        put_db_connection(conn)


def get_asset_by_id(asset_id: int, client_id: int) -> Optional[dict[str, Any]]:
    conn = get_db_connection()
    if not conn:
        return None

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    client_id,
                    host(ip_address) AS ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen,
                    created_at,
                    updated_at
                FROM network_assets
                WHERE id = %s AND client_id = %s
                LIMIT 1
                """,
                (asset_id, client_id),
            )
            return cur.fetchone()
    except Exception as e:
        print("get_asset_by_id failed:", e)
        return None
    finally:
        put_db_connection(conn)


def create_asset(
    client_id: int,
    ip_address: str,
    display_name: Optional[str] = None,
    notes: Optional[str] = None,
    trust_status: Optional[str] = "unknown",
    last_seen=None,
) -> Optional[dict[str, Any]]:
    conn = get_db_connection()
    if not conn:
        return None

    trust_status = _normalize_trust_status(trust_status)

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO network_assets (
                    client_id,
                    ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (client_id, ip_address)
                DO UPDATE SET
                    display_name = COALESCE(EXCLUDED.display_name, network_assets.display_name),
                    notes = COALESCE(EXCLUDED.notes, network_assets.notes),
                    trust_status = COALESCE(EXCLUDED.trust_status, network_assets.trust_status),
                    last_seen = COALESCE(EXCLUDED.last_seen, network_assets.last_seen),
                    updated_at = NOW()
                RETURNING
                    id,
                    client_id,
                    host(ip_address) AS ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen,
                    created_at,
                    updated_at
                """,
                (
                    client_id,
                    ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen,
                ),
            )
            row = cur.fetchone()
            conn.commit()
            return row
    except Exception as e:
        conn.rollback()
        print("create_asset failed:", e)
        return None
    finally:
        put_db_connection(conn)


def update_asset(
    asset_id: int,
    client_id: int,
    display_name: Optional[str] = None,
    notes: Optional[str] = None,
    trust_status: Optional[str] = None,
    last_seen=None,
) -> Optional[dict[str, Any]]:
    conn = get_db_connection()
    if not conn:
        return None

    trust_status = _normalize_trust_status(trust_status) if trust_status is not None else None

    fields = []
    values = []

    if display_name is not None:
        fields.append("display_name = %s")
        values.append(display_name)

    if notes is not None:
        fields.append("notes = %s")
        values.append(notes)

    if trust_status is not None:
        fields.append("trust_status = %s")
        values.append(trust_status)

    if last_seen is not None:
        fields.append("last_seen = %s")
        values.append(last_seen)

    fields.append("updated_at = NOW()")

    try:
        with conn.cursor() as cur:
            if fields:
                values.extend([asset_id, client_id])
                cur.execute(
                    f"""
                    UPDATE network_assets
                    SET {", ".join(fields)}
                    WHERE id = %s AND client_id = %s
                    RETURNING
                        id,
                        client_id,
                        host(ip_address) AS ip_address,
                        display_name,
                        notes,
                        trust_status,
                        last_seen,
                        created_at,
                        updated_at
                    """,
                    tuple(values),
                )
                row = cur.fetchone()
                conn.commit()
                return row

            cur.execute(
                """
                SELECT
                    id,
                    client_id,
                    host(ip_address) AS ip_address,
                    display_name,
                    notes,
                    trust_status,
                    last_seen,
                    created_at,
                    updated_at
                FROM network_assets
                WHERE id = %s AND client_id = %s
                LIMIT 1
                """,
                (asset_id, client_id),
            )
            return cur.fetchone()
    except Exception as e:
        conn.rollback()
        print("update_asset failed:", e)
        return None
    finally:
        put_db_connection(conn)


def delete_asset(asset_id: int, client_id: int) -> bool:
    conn = get_db_connection()
    if not conn:
        return False

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM network_assets
                WHERE id = %s AND client_id = %s
                """,
                (asset_id, client_id),
            )
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted
    except Exception as e:
        conn.rollback()
        print("delete_asset failed:", e)
        return False
    finally:
        put_db_connection(conn)