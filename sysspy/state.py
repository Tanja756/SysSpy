import os
import sqlite3
import time
from contextlib import contextmanager

from .finding import Finding, Severity


class State:
    """SQLite-backed store for findings and baselines."""

    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                category TEXT,
                severity TEXT,
                title TEXT,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated TEXT
            );
            CREATE TABLE IF NOT EXISTS connections (
                key TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                count INTEGER
            );
            CREATE TABLE IF NOT EXISTS modules (
                name TEXT PRIMARY KEY,
                first_seen TEXT
            );
            """
        )
        self.conn.commit()

    @contextmanager
    def _cur(self):
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        finally:
            pass

    def add_finding(self, f: Finding):
        with self._cur() as cur:
            cur.execute(
                "INSERT INTO findings (timestamp,category,severity,title,detail) "
                "VALUES (?,?,?,?,?)",
                (f.timestamp, f.category, f.severity.value, f.title, f.detail),
            )

    def recent_findings(self, limit=300, since=None):
        with self._cur() as cur:
            if since:
                cur.execute(
                    "SELECT timestamp,category,severity,title,detail FROM findings "
                    "WHERE timestamp>=? ORDER BY id DESC LIMIT ?",
                    (since, limit),
                )
            else:
                cur.execute(
                    "SELECT timestamp,category,severity,title,detail FROM findings "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append(
                Finding(
                    category=r[1],
                    severity=Severity(r[2]),
                    title=r[3],
                    detail=r[4],
                    timestamp=r[0],
                )
            )
        return out

    def count_findings(self):
        with self._cur() as cur:
            cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            return dict(cur.fetchall())

    def count_connections(self):
        with self._cur() as cur:
            cur.execute("SELECT COUNT(*) FROM connections")
            return cur.fetchone()[0]

    def count_modules(self):
        with self._cur() as cur:
            cur.execute("SELECT COUNT(*) FROM modules")
            return cur.fetchone()[0]

    def remember_connection(self, key):
        """Record an endpoint; return True if already seen before (baseline)."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._cur() as cur:
            cur.execute("SELECT count FROM connections WHERE key=?", (key,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE connections SET last_seen=?, count=count+1 WHERE key=?",
                    (now, key),
                )
                return True
            cur.execute(
                "INSERT INTO connections (key,first_seen,last_seen,count) "
                "VALUES (?,?,?,1)",
                (key, now, now),
            )
            return False

    def remember_module(self, name):
        with self._cur() as cur:
            cur.execute("SELECT name FROM modules WHERE name=?", (name,))
            if cur.fetchone():
                return True
            cur.execute(
                "INSERT INTO modules (name,first_seen) VALUES (?,?)",
                (name, time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            return False

    def set_kv(self, key, value):
        with self._cur() as cur:
            cur.execute(
                "INSERT INTO kv (key,value,updated) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated=excluded.updated",
                (key, value, time.strftime("%Y-%m-%dT%H:%M:%S")),
            )

    def bulk_kv(self, pairs):
        """Insert/update many key->value pairs in a single transaction."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._cur() as cur:
            cur.executemany(
                "INSERT INTO kv (key,value,updated) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated=excluded.updated",
                [(k, v, now) for k, v in pairs],
            )

    def get_kv(self, key):
        with self._cur() as cur:
            cur.execute("SELECT value FROM kv WHERE key=?", (key,))
            r = cur.fetchone()
            return r[0] if r else None

    def delete_kv_prefix(self, prefix):
        """Удаляет все kv-записи, ключ которых начинается с prefix."""
        with self._cur() as cur:
            cur.execute("DELETE FROM kv WHERE key LIKE ?", (prefix + "%",))

    def clear(self):
        """Удаляет все находки и базовые линии (findings/connections/modules/kv)."""
        total = 0
        with self._cur() as cur:
            for t in ("findings", "connections", "modules", "kv"):
                cur.execute(f"DELETE FROM {t}")
                total += cur.rowcount
        return total

    def close(self):
        self.conn.close()
