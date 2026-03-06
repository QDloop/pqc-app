import os
import sqlite3
try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

DB_NAME = 'pqc_secure.db'
DB_URL = os.environ.get("DATABASE_URL")

class PostgresCursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor
        
    def execute(self, query, params=None):
        query = query.replace("?", "%s")
        if "INSERT OR IGNORE" in query.upper():
            query = query.replace("INSERT OR IGNORE", "INSERT").replace("INSERT OR IGNORE INTO", "INSERT INTO")
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
