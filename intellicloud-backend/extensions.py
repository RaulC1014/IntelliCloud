import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func = get_remote_address,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    default_limits=["200000 per day", "5000 per hour"]
)
'''
from psycopg2 import pool
_pool = pool.ThreadedConnectionPool(minconn=2, maxconn=20, dsn=DATABASE_URL)

def get_db_connection():
    return _pool.getconn()

def put_db_connection(conn):
    _pool.putconn(conn)
'''