from models.db import get_db_connection
from auth import require_auth, require_role, verify_api
import secrets

def get_threats_for_user(user_id):
    conn = get_db_connection()
    if not conn:
         print("Could not connect to DB")
         return []
    
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, ip_address, threat_level, description, timestamp 
            FROM threats WHERE user_id = %s
        """, (user_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        threats = []
        for row in rows:
            threats.append({
            
                "id": row[0],
                "ip_address": row[1],
                "threat_level": row[2],
                "description": row[3],
                "timestamp": row[4].isoformat()

            })
        return threats
    
    except Exception as e:
         print("Error fetching user thrats: ", e)
         return []
    
def get_threats_for_client(client_id):
    conn = get_db_connection()
    if not conn:
        print("Unable to connect to DB")
        return []
    
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, ip_address, threat_level, description, timestamp
        FROM threats WHERE client_id = %s
        """, (client_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        threats = []
        for row in rows:
            threats.append({
                "id": row[0],
                "ip_address": row[1],
                "threat_level": row[2],
                "description": row[3],
                "timestamp": row[4].isoformat() if row[4] else None,
            })
        return threats
    except Exception as e:
        print("Error fetching threats for client", e)
        return []

def get_threats_from_db(ip = None, threat_level = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM threats"
    params = []
    conditions = []

    if ip:
        conditions.append("ip_address = %s")
        params.append(ip)
    if threat_level:
        conditions.append("threat_level %s")
        params.append(threat_level)
    if conditions:
         query += " WHERE " + " AND " .join(conditions)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return [{
         "id": row[0],
         "ip": row[1],
         "threat_level": row[2],
         "description": row[3]

    } for row in rows]

     
def insert_threat(ip_address, threat_level, description=None, timestamp=None, user_id=None, client_id=None):
    conn = get_db_connection()
    if not conn:
          print("Cannot insert threat: no DB connection")
          return

    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threats (ip_address, threat_level, description, timestamp, user_id, client_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """, (ip_address, threat_level, description, timestamp, user_id, client_id))
        conn.commit()
        print("Threat inserted successfully.")

    except Exception as e:
            print("Database inset failed: ", e)
    finally:
            cur.close()
            conn.close()


def get_all_threats():
    conn = get_db_connection()
    if not conn:
          print("Cannot fetch threats: no DB connection")
          return[]
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, ip_address, threat_level, description, timestamp FROM threats")
        rows = cur.fetchall()
        cur.close()
        conn.close()

        threats = []
        for row in rows:
              threats.append({
                "id": row[0],
                "ip_address": row[1],
                "threat_level": row[2],
                "description": row[3],
                "timestamp": row[4],
              })
        return threats
    
    except Exception as e:
          print("Failed to fetch threats:")
          print(e)
          return []
    

def delete_threat_by_id(user_id, threat_id):
    conn = get_db_connection()
    if not conn:
            print("Cannot delete threat: no DB connection")
            return False

    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM threats 
            WHERE id = %s AND user_id = %s
        """, (threat_id, user_id))
        conn.commit()
        rows_deleted = cur.rowcount
        cur.close()
        conn.close()
        return rows_deleted > 0
    except Exception as e:
            print("Failed to delete threat:")
            print(e)
            return False

def update_threat_by_id(user_id, threat_id, updates):
      conn = get_db_connection()
      if not conn:
            print("Cannot delete threat: no DB connection")
            return False

      try:
        cur = conn.cursor()
        set_clauses = []
        values = []

        if "threat_level" in updates:
                set_clauses.append("threat_level = %s")
                values.append(updates["threat_level"])

        if "description" in updates:
                set_clauses.append("description = %s")
                values.append(updates["description"])

        if not set_clauses:
            return False
        
        values.extend([threat_id, user_id])


        query = f"""
            UPDATE threats SET {', '.join(set_clauses)} 
            WHERE id = %s AND user_id = %s
        """
        cur.execute(query, values)
        conn.commit()
        rows_updated = cur.rowcount
        cur.close()
        conn.close()
        return rows_updated > 0
      
      except Exception as e:
            print("Failed to update threat:")
            print(e)
            return False

def get_audit_logs():
    conn = get_db_connection()
    if not conn:
        print("Cannot delete threat: no DB connection")
        return []
      
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT log_id, action, user_id, target_id, timestamp 
            FROM audit_log 
            ORDER 
            BY timestamp DESC""")
        rows = cur.fetchall()
        cur.close()
        conn.close()

        logs = []
        for row in rows:
            logs.append({
            "log_id": row[0],
            "action": row[1],
            "user_id": row[2],
            "target_id": row[3],
            "timestamp": row[4].isoformat() if row[4] else None
            })
        return logs

    except Exception as e:
        print("Failed to fetch audit logs:")
        print(e)
        return []
    
def get_audit_logs_for_user(user_id):
    conn = get_db_connection()
    if not conn:
        print("Cannot fetch audit logs for user: no DB connection")
        return []
    
    try:
        cur = conn.cursor()
        cur.execute(
             "SELECT log_id, action, user_id, target_id, timestamp FROM audit_log WHERE user_id = %s ORDER BY timestamp DESC",
             (user_id)
        )

        rows = cur.fetchall()
        cur.close()
        conn.close()

        logs = []
        for row in rows:
             logs.append({
                  "log_id": row[0],
                  "action": row[1],
                  "user_id": row[2],
                  "target_id": row[3],
                  "timestamp": row[4].isoformat() if row[4] else None
             })
        return logs
    
    except Exception as e:
         print("Failed to fetch audit logs for user:")
         print(e)
         return []
    
def log_action(action, user_id, target_id=None):
    conn = get_db_connection()
    if not conn:
        print("Cannot log action: no DB conncetion")
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_log (action, user_id, target_id)
            VALUES (%s, %s, %s)
        """, (action, user_id, target_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Failed to log action:")
        print(e)

def create_client(client_name):
    conn = get_db_connection()
    if not conn:
        print("Cannot create client: no DB connection")
        return None
    
    try:
         api_key = secrets.token_hex(32)
         cur = conn.cursor()
         cur.execute("""
            INSERT INTO clients (client_name, api_key) VALUES (%s, %s)
            RETURNING client_id, client_name, api_key, created_at
            """, (client_name, api_key))
         new_client = cur.fetchone()
         conn.commit()
         cur.close()
         conn.close()

         return {
              "client_id": new_client[0],
              "client_name": new_client[1],
              "api_key": new_client[2],
              "created_at": new_client[3].isoformat() if new_client[3] else None
         }
    except Exception as e:
         print("Failed to create client:")
         print(e)
         return None