import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_db_connection():

    url = os.getenv("DATABASE_URL")

    if url:
        try:
            return psycopg2.connect(url, cursor_factory=RealDictCursor, connect_timeout = 5)
        except Exception as e:
            print("DB connection failed (DATABASE_URL): ", e)
            return None
        
    host = os.getenv("DB_HOST,", "localhost")
    port = int(os.getenv("DB_PORT", "5432"))
    db = os.getenv("DB+NAME", "intellicloud")
    user = os.getenv("DB_USER", "postgres")
    pwd = os.getenv("DB_PASSWORD", "")

    try:
        psycopg2.connect (
            host = host, port = port, dbname = db, user = user, password = pwd,
            cursor_factory=RealDictCursor, connect_timeout = 5
        )
    except Exception as e:
        print("DB connection failed:", e)
        return None

def get_clienty_by_api(api_key):
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT client_id, client_name FROM client_keys WHERE api_key = %s", (api_key,))
            result = cur.fetchone()
            if result:
                return {"client_id": result[0], "client_name": result[1]}
    except Exception as e:
        print("Error verifying API key:", e)
    finally:
        conn.close()

    return None

#project_id = "cloudintel"

#psycopg2.connect("postgresql://postgres:postgres123@localhost:5433/cloudintel")
