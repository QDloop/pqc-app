import os
import sqlite3
import re
try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

DB_NAME = 'pqc_secure.db'
DB_URL = os.environ.get("DATABASE_URL")

# Fix Render's postgres:// to postgresql:// (psycopg2 requires the latter)
if DB_URL and DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

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
    def __init__(self, conn):
        self.conn = conn
        self.row_factory = None

    def cursor(self):
        return PostgresCursorWrapper(self.conn.cursor(cursor_factory=DictCursor))

    def execute(self, query, params=None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_db():
    if DB_URL and psycopg2:
        conn = psycopg2.connect(DB_URL)
        return PostgresConnectionWrapper(conn)
    else:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn

