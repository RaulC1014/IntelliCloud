import secrets
from models.db import get_db_connection

def create_client(name, domain=None):
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    try:
        api_key = secrets.token_hex(16)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO clients (client_name, domain, api_key)
                VALUES (%s, %s, %s)
                RETURNING client_id, client_name, domain, api_key, created_at
                """, (name, domain, api_key))
        row = cur.fetchone()
        conn.commit()
        return row

    except Exception as e:
        print("Failed to create client:", e)
        return None
    finally:
        conn.close()
    

def get_all_clients():
    conn = get_db_connection()
    if not conn:
        print("Cannot connect to DB")
        return []
    try:
       with conn.cursor() as cur:
            cur.execute("""SELECT client_id, client_name, domain, api_key, created_at FROM clients
                        ORDER BY client_id DESC""")
            rows = cur.fetchall()
            return rows 
    except Exception as e:
        print("Failed to retrieve clients: ", e)
        return []
    finally:
        conn.close()
    
def get_client_by_api_key(api_key):
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return None
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT client_id, client_name, domain, created_at 
                FROM clients 
                WHERE api_key = %s", 
            """, (api_key,))
        row = cur.fetchone()
        return row
    
    except Exception as e:
        print("Failed to lookup client by API key: ", e)
        return None
    finally:
        conn.close()