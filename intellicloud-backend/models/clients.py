import secrets
from models.db import get_db_connection, put_db_connection  

def create_client(name: str, domain: str | None = None):
    conn = get_db_connection()
    if not conn:
        return None

    api_key = secrets.token_urlsafe(32)  

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO clients (client_name, domain, api_key)
                VALUES (%s, %s, %s)
                RETURNING client_id, client_name, domain, api_key, created_at
                """,
                (name, domain, api_key),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return None
    finally:
        put_db_connection(conn)  

def get_all_clients():
    conn = get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, client_name, domain, api_key, created_at
                FROM clients
                ORDER BY client_id DESC
                """
            )
            return cur.fetchall()
    finally:
        put_db_connection(conn)

def get_client_by_api_key(api_key: str):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, client_name, domain, api_key, created_at
                FROM clients
                WHERE api_key = %s
                LIMIT 1
                """,
                (api_key,),
            )
            return cur.fetchone()
    finally:
        put_db_connection(conn)
