"""
SQLite access layer.

The Database class owns ONE sqlite3 connection, creates every table
automatically (CREATE TABLE IF NOT EXISTS) and offers tiny helpers so that
the rest of the code never has to deal with cursors.
"""

import os
import sqlite3
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "database.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(tenant_id)
);

-- A user can be a member of several tenants (users.tenant_id is the home tenant).
CREATE TABLE IF NOT EXISTS user_tenants (
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS roles (
    role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name   TEXT NOT NULL,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(tenant_id),
    UNIQUE (role_name, tenant_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id     INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Directed edge parent_role_id -> child_role_id : child INHERITS parent.
CREATE TABLE IF NOT EXISTS role_hierarchy (
    parent_role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    child_role_id  INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id),
    CHECK (parent_role_id != child_role_id)
);

CREATE TABLE IF NOT EXISTS explicit_denials (
    denial_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    reason        TEXT NOT NULL DEFAULT 'Explicit deny rule',
    UNIQUE (user_id, tenant_id, permission_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    username    TEXT NOT NULL,
    tenant      TEXT NOT NULL,
    permission  TEXT NOT NULL,
    result      TEXT NOT NULL,
    reason      TEXT NOT NULL
);
"""


class Database:
    """Thin wrapper around a single SQLite connection (thread-safe via a lock)."""

    def __init__(self, path=DEFAULT_DB_PATH):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self.init_schema()

    def init_schema(self):
        """Create all tables if they do not exist yet."""
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql, params=()):
        """Run INSERT/UPDATE/DELETE, commit, and return the last inserted row id."""
        with self._lock:
            try:
                cursor = self._conn.execute(sql, params)
                self._conn.commit()
            except sqlite3.Error:
                self._conn.rollback()
                raise
            return cursor.lastrowid

    def query_all(self, sql, params=()):
        """Run a SELECT and return a list of dicts."""
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params).fetchall()]

    def query_one(self, sql, params=()):
        """Run a SELECT and return the first row as a dict (or None)."""
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def close(self):
        with self._lock:
            self._conn.close()
