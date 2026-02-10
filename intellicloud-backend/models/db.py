import os
import threading
import psycopg2
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor

def _ensure_sslmode_in_url(url: str, default_sslmode: str = "require") -> str:
    """
    If DATABASE_URL lacks ?sslmode=..., then append sslmode=<default_sslmode>.
    Preserves any existing query params.
    """
    parts = list(urlparse(url))
    query = dict(parse_qsl(parts[4], keep_blank_values=True))
    query.setdefault("sslmode", default_sslmode)
    parts[4] = urlencode(query)
    return urlunparse(parts)

def get_db_connection():

    """Return a psycopg2 connection with RealDictCursor or None on failure."""

    url = os.getenv("DATABASE_URL")
    sslmode_env = os.getenv("DB_SSLMODE", "require")
    sslrootcert = os.getenv("DB_SSLROOTCERT")
    if url:
        try:
            url = _ensure_sslmode_in_url(url, sslmode_env or "require")
            return psycopg2.connect(
                url,
                cursor_factory=RealDictCursor,
                connect_timeout=5,
            )
        except Exception as e:
            print("DB connection failed (DATABASE_URL): ", e)
        
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "5432"))
    db   = os.getenv("DB_NAME", "intellicloud")
    user = os.getenv("DB_USER", "postgres")
    pwd  = os.getenv("DB_PASSWORD", "")

    try:
        conn_kwargs = dict(
            host = host, port = port, dbname = db, user = user, password = pwd,
            cursor_factory=RealDictCursor, connect_timeout = 5, sslmode = sslmode_env or "require",
        )
        if sslrootcert:
            conn_kwargs["sslrootcert"] = sslrootcert
        return psycopg2.connect(**conn_kwargs)
    except Exception as e:
        print("DB connection failed:", e)
        return None
    

def put_db_connection(conn):
    if conn:
        conn.close()

