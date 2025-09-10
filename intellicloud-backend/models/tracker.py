from models.db import get_db_connection
from datetime import datetime

def log_visitor_ip(ip: str, user_agent: str, client_id: int) -> dict | None:
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO  tracked_ips (ip, user_agent, client_id, timestamp)
                VALUES (%s, %s, %s, %s)
                RETURNING id, timestamp;
            """, 
            (ip, user_agent, client_id, datetime.utcnow())
        )
        row = cur.fetchone()
        if not row:
            return None
        ts = row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"]
        return {"id": row["id"], "timestamp": ts}
    except Exception as e:
        print("Failed to log visitor IP:", e)
        return None
    