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

# Create a single shared connection pool (min=1, max=20 connections)
# ThreadedConnectionPool is REQUIRED for multi-threaded Flask apps
_pg_pool = None
if DB_URL and psycopg2_pool:
    try:
        _pg_pool = psycopg2_pool.ThreadedConnectionPool(1, 20, DB_URL)
        print("[db] PostgreSQL Threaded Pool created (max=20).")
    except Exception as e:
        print(f"[db] WARNING: Could not create PostgreSQL pool: {e}")

class DbCursorWrapper:
    def __init__(self, cursor, is_pg=False):
        self.cursor = cursor
        self.is_pg = is_pg

    def execute(self, query, params=None):
        if self.is_pg:
            # Postgres translations
            query = query.replace("?", "%s")
            if re.search(r'INSERT\s+OR\s+IGNORE', query, re.IGNORECASE):
                query = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', query, flags=re.IGNORECASE)
                query = query.rstrip().rstrip(';')
                query += " ON CONFLICT DO NOTHING"
        
        # SQLite handles "INSERT OR IGNORE" natively, no change needed
        
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
    
    def __iter__(self):
        return iter(self.fetchall())

class DbConnectionWrapper:
    def __init__(self, conn, pool=None, is_pg=False):
        self.conn = conn
        self._pool = pool
        self.is_pg = is_pg

    def cursor(self):
        if self.is_pg:
            return DbCursorWrapper(self.conn.cursor(cursor_factory=DictCursor), is_pg=True)
        else:
            return DbCursorWrapper(self.conn.cursor(), is_pg=False)

    def execute(self, query, params=None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        if self.is_pg and self._pool:
            self._pool.putconn(self.conn)
        else:
            self.conn.close()

def get_db():
    if _pg_pool:
        try:
            conn = _pg_pool.getconn()
            return DbConnectionWrapper(conn, pool=_pg_pool, is_pg=True)
        except Exception as e:
            print(f"[db] WARNING: Pool exhausted or failed ({e}). Attempting direct fallback.")
    
    # Fallback to local SQLite
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return DbConnectionWrapper(conn, is_pg=False)


