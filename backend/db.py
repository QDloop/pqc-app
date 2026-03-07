import os
import sqlite3
import re
try:
    import psycopg2
    from psycopg2.extras import DictCursor
    from psycopg2 import pool as psycopg2_pool
except ImportError:
    psycopg2 = None
    psycopg2_pool = None

DB_NAME = 'pqc_secure.db'
DB_URL = os.environ.get("DATABASE_URL")

# Fix Render's postgres:// to postgresql:// (psycopg2 requires the latter)
if DB_URL and DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

# Create a single shared connection pool (min=1, max=3 connections)
# This prevents "too many connections" errors on the free PostgreSQL tier
_pg_pool = None
if DB_URL and psycopg2_pool:
    try:
        _pg_pool = psycopg2_pool.SimpleConnectionPool(1, 3, DB_URL)
        print("[db] PostgreSQL connection pool created successfully.")
    except Exception as e:
        print(f"[db] WARNING: Could not create PostgreSQL pool: {e}. Falling back to SQLite.")

class PostgresCursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, query, params=None):
        # Replace ? with %s for psycopg2
        query = query.replace("?", "%s")

        # Handle INSERT OR IGNORE -> INSERT ... ON CONFLICT DO NOTHING
        # Must check for "INSERT OR IGNORE INTO" before replacing "INSERT OR IGNORE"
        if re.search(r'INSERT\s+OR\s+IGNORE', query, re.IGNORECASE):
            query = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', query, flags=re.IGNORECASE)
            query = query.rstrip().rstrip(';')
            query += " ON CONFLICT DO NOTHING"

        if params is None:
            self.cursor.execute(query)
        else:
            self.cursor.execute(query, params)
        return self

    def fetchone(self):
        result = self.cursor.fetchone()
        return dict(result) if result else None

    def fetchall(self):
        results = self.cursor.fetchall()
        return [dict(r) for r in results] if results else []

    def __getitem__(self, key):
        return self.cursor.fetchone()[key]


class PostgresConnectionWrapper:
    def __init__(self, conn, pool=None):
        self.conn = conn
        self._pool = pool       # keep reference to release back to pool
        self.row_factory = None

    def cursor(self):
        return PostgresCursorWrapper(self.conn.cursor(cursor_factory=DictCursor))

    def execute(self, query, params=None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        # Return connection back to the pool instead of destroying it
        if self._pool:
            self._pool.putconn(self.conn)
        else:
            self.conn.close()


def get_db():
    # Use the pool if available, otherwise fall back to SQLite
    if _pg_pool:
        try:
            conn = _pg_pool.getconn()   # borrow a connection from the pool
            return PostgresConnectionWrapper(conn, pool=_pg_pool)
        except Exception as e:
            print(f"[db] WARNING: PostgreSQL pool failed ({e}), falling back to SQLite.")
    # Fallback to SQLite if pool is unavailable or exhausted
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

