from models.db import get_db_connection
from datetime import datetime
from typing import Any, Dict, List, Optional
from auth import require_auth, require_role, verify_api
import secrets

def get_threats_for_user(user_id: str) -> List[dict]:
    conn = get_db_connection()
    if not conn:
         print("Could not connect to DB")
         return []
    
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, ip_address, threat_level, description, timestamp 
                FROM threats 
                WHERE user_id = %s
                """, 
                (user_id,),
            )
            rows = cur.fetchall()
            
            for r in rows:
                if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                    r["timestamp"] = r["timestamp"].isoformat()
            return rows
    except Exception as e:
            print("Error fetching user threats: ", e)
            return[]
    
def get_threats_for_client(client_id: int) -> List[dict]:
    conn = get_db_connection()
    if not conn:
        print("Unable to connect to DB")
        return []
    
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
            """
            SELECT id, ip_address, threat_level, description, timestamp
            FROM threats 
            WHERE client_id = %s
            ORDER BY id DESC
            """, 
            (client_id,),
            )
            rows = cur.fetchall()
            for r in rows:
                if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                    r["timestamp"] = r["timestamp"].isoformat()
            return rows
    except Exception as e:
        print("Error fetching threats for client", e)
        return []

def get_threats_from_db(ip: Optional[str] = None, threat_level: Optional[int] = None) -> List[dict]:
    conn = get_db_connection()
    if not conn:
        print("No DB connection")
        return []
    try:
        where, params = [], []
        if ip:
            where.append("ip_address = %s "); params.append(ip)
        if threat_level is not None:
            where.append("threat_level = %s"); params.append(threat_level)

        sql = "SELECT id, ip_address, threat_level, description, timestamp FROM threats"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC"

        with conn, conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
            for r in rows:
                 if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                    r["timestamp"] = r["timestamp"].isoformat()
            return rows
    except Exception as e:
        print("Failed to fetch threats: ", e)
        return []

     
def insert_threat(
    ip_address: str,
    threat_level: int,
    description: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    user_id: Optional[str] = None,
    client_id: Optional[int] = None,
) -> Optional[int]:
    
    conn = get_db_connection()
    if not conn:
        print("Cannot insert threat: no DB connection")
        return

    try:
        with conn,conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threats (ip_address, threat_level, description, timestamp, user_id, client_id)
                VALUES (%s, %s, %s, COALESCE (%s, now()), %s, %s)
                RETURNING id
                """, 
                (ip_address, threat_level, description, timestamp, user_id, client_id),
            )
            row = cur.fetchone()
            return row["id"] if row else None
    except Exception as e:
        print("Database insert failed: ", e)
        return None

def get_all_threats() -> List[dict]:
    conn = get_db_connection()
    if not conn:
          print("Cannot fetch threats: no DB connection")
          return[]
    
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, ip_address, threat_level, description, timestamp 
                FROM 
                ORDER BY id DESC
                """
            )
        rows = cur.fetchall()
        for r in rows:
            if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                 r["timestamp"] = r["timestamp"].isoformat()
        return rows
    except Exception as e:
        print("Failed to fetch threats: ", e)
        return[]

def delete_threat_by_id(user_id: str, threat_id: int) -> bool:
    conn = get_db_connection()
    if not conn:
            print("Cannot delete threat: no DB connection")
            return False

    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM threats 
                WHERE id = %s AND user_id = %s
                """, 
                (threat_id, user_id),
            )
            return cur.rowcount > 0
    except Exception as e:
            print("Failed to delete threat:", e)
            return False

def update_threat_by_id(user_id: str, threat_id: int, updates: Dict[str, Any]) -> bool:
    conn = get_db_connection()
    if not conn:
        print("Cannot delete threat: no DB connection")
        return False
    try:
        set_parts, values = [], []
        if "threat_level" in updates:
            set_parts.append("threat_level = %s")
            values.append(updates["threat_level"])
        if "description" in updates:
            set_parts.append("description = %s")
            values.append(updates["description"])
        if not set_parts:
            return False
    
        values.extend([threat_id, user_id])
        sql = f"UPDATE threats SET {', '.join(set_parts)} WHERE id = %s AND user_id = %s"

        with conn, conn.cursor() as cur:
            cur.execute(sql, values)
            return cur.rowcount > 0
    
    except Exception as e:
        print("Failed to update threat:")
        print(e)
        return False

def get_audit_logs() -> List[dict]:
    conn = get_db_connection()
    if not conn:
        print("Cannot delete threat: no DB connection")
        return []
      
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT log_id, action, user_id, target_id, timestamp 
                FROM audit_log 
                ORDER 
                BY timestamp DESC
                """
            )
            rows = cur.fetchall()
            for r in rows:
                if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                    r["timestamp"] = r["timestamp"].isoformat()
            return rows
    except Exception as e:
        print("Failed to fetch audit logs:")
        print(e)
        return []
    
def get_audit_logs_for_user(user_id: str) -> List[dict]:
    conn = get_db_connection()
    if not conn:
        print("Cannot fetch audit logs for user: no DB connection")
        return []
    
    try:
        with conn, conn.cursor() as cur:

            cur.execute(
                """
                SELECT log_id, action, user_id, target_id, timestamp 
                FROM audit_log 
                WHERE user_id = %s 
                ORDER BY timestamp DESC
                """,
                (user_id,),
            )

        rows = cur.fetchall()
        for r in rows:
            if r.get("timestamp") and hasattr(r["timestamp"], "isoformat"):
                r["timestamp"] = r["timestamp"].isoformat()
        return rows
    except Exception as e:
         print("Failed to fetch audit logs for user:", e)
         return []
    
def log_action(action: str, user_id: str, target_id: int | None = None) -> None:
    conn = get_db_connection()
    if not conn:
        print("Cannot log action: no DB conncetion")
        return
    try:
        with conn, conn.cursor() as cur:

            cur.execute("""
                INSERT INTO audit_log (action, user_id, target_id)
                VALUES (%s, %s, %s)
            """, (action, user_id, target_id)
        )
    except Exception as e:
        print("Failed to log action:", e)
