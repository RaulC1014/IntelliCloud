import psycopg2

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname="cloudintel",
            user="postgres",
            password="postgres123",
            host="localhost",
            port="5433"
        )
        print("Connection successful!")
        return conn
    except psycopg2.OperationalError as e:
        print("Connection failed: ")
        print (e)
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
