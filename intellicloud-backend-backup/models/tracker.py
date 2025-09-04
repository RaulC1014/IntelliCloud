from models.db import get_db_connection
from datetime import datetime

def log_visitor_ip(ip, user_agent, client_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO  tracked_ips (ip, user_agent, client_id, timestamp)
        VALUES (%s, %s, %s, %s)
        RETURNING id, timestamp;
    """, (ip, user_agent, client_id, datetime.utcnow()))

    result = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "id": result[0],
        "timestamp": result[1].isoformat()
    }