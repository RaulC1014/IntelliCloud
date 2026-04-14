import os
import threading
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

_pool: ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()

def _ensure_sslmode_in_url(url: str, default_sslmode: str = "require") -> str:
    parts = list(urlparse(url))
    query = dict(parse_qsl(parts[4], keep_blank_values=True))
    query.setdefault("sslmode", default_sslmode)
    parts[4] = urlencode(query)
    return urlunparse(parts)

def _build_pool() -> ThreadedConnectionPool | None:
    url = os.getenv("DATABASE_URL")
    sslmode = os.getenv("DB_SSLMODE", "prefer")   # 'prefer' works for local dev

    try:
        if url:
            url = _ensure_sslmode_in_url(url, sslmode)
            return ThreadedConnectionPool(
                minconn=2, maxconn=20,
                dsn=url,
                cursor_factory=RealDictCursor,
                connect_timeout=5,
            )
        return ThreadedConnectionPool(
            minconn=2, maxconn=20,
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.getenv("DB_NAME", "intellicloud"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", ""),
            cursor_factory=RealDictCursor,
            connect_timeout=5,
            sslmode=sslmode,
        )
    except Exception as e:
        print(f"[DB] Pool creation failed: {e}")
        return None

def _get_pool() -> ThreadedConnectionPool | None:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = _build_pool()
    return _pool

def get_db_connection():
    """Borrow a connection from the pool. Returns None on failure."""
    pool = _get_pool()
    if pool is None:
        return None
    try:
        return pool.getconn()
    except Exception as e:
        print(f"[DB] getconn failed: {e}")
        return None

def put_db_connection(conn):
    """Return a connection to the pool."""
    if conn is None:
        return
    pool = _get_pool()
    if pool:
        try:
            pool.putconn(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass