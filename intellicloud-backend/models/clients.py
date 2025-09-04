import secrets, uuid
from models.db import get_db_connection

def create_client(name, domain):
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    
    try:
        api_key = secrets.token_hex(16)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO clients (client_name, domain, api_key)
            VALUES (%s, %s, %s)
            RETURNING client_id, client_name, domain, api_key
            """, (name, domain, api_key))
        
        client = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        return {
            "client_id": client[0],
            "client_name": client[1],
            "domain": client[2],
            "api_key": client[3],
        }
    except Exception as e:
        print("Failed to create client:", e)
        return None
    

def get_all_clients():
    conn = get_db_connection()
    if not conn:
        print("Cannot connect to DB")
        return []
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT client_id, client_name, domain, api_key, created_at FROM clients")
        rows = cur.fetchall()
        cur.close()
        conn.close()

        return [{
            "client_id": row[0],
            "client_name": row[1],
            "domain": row[2],
            "api_key": row[3],
            "created_at": row[4].isoformat() if row[3] else None
        } for row in rows] 
    except Exception as e:
        print("Failed to retrieve clients: ", e)
        return []
    
def get_client_by_api_key(api_key):
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT client_id, client_name, domain, created_at FROM clients WHERE api_key = %s", (api_key,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            return {
                "client_id": row[0],
                "client_name": row[1],
                "domain": row[2],
                "created_at": row[3].isoformat() if row[3] else None
            }
    except Exception as e:
        print("Failed to lookup client by API key: ", e)
        return None