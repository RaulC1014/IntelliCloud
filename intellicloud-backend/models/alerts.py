from models.db import get_db_connection

def create_alert(client_id: int | None, rule_id: str, severity: str, title: str, details: dict) -> int | None:
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (client_id, rule_id, severity, title, details)
                VALUES (%s, %s, %s, %s, %s,)
                RETURNING id
                """, (client_id, rule_id, severity, title, details)
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
            cur.execute("""
                INSERT INTO ip_blocklist (client_id, ip_address, reason) Values (%s, %s, %s) 
                ON CONFLICT DO NOTHING
                """, (client_id, ip, reason))
    except Exception as e:
        print("block_ip failed: ", e)

def is_ip_blocked(ip:str) -> bool:
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT 1 FROM ip_blocklist
                WHERE ip_address = %s
                LIMIT 1
                """, (ip,)
            )
            return cur.fetchone() is not None
    except Exception:
        return False
