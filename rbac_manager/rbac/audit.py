"""
Audit logging: every permission check is recorded in the audit_logs table.

Example line:  Alice | ACME | billing:delete | DENY | Explicit deny rule
"""

from datetime import datetime

from .models import ALLOW, DENY


class AuditEntry:
    """One row of the audit log."""

    def __init__(self, log_id, timestamp, username, tenant, permission, result, reason):
        self.log_id = log_id
        self.timestamp = timestamp
        self.username = username
        self.tenant = tenant
        self.permission = permission
        self.result = result
        self.reason = reason

    def format(self):
        return f"{self.username} | {self.tenant} | {self.permission} | {self.result} | {self.reason}"

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "username": self.username,
            "tenant": self.tenant,
            "permission": self.permission,
            "result": self.result,
            "reason": self.reason,
        }

    def __repr__(self):
        return f"AuditEntry({self.timestamp} | {self.format()})"


class AuditLog:
    """Writes and reads audit entries using the Database object."""

    def __init__(self, db):
        self._db = db

    def record(self, username, tenant, permission, result, reason):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_id = self._db.execute(
            "INSERT INTO audit_logs (timestamp, username, tenant, permission, result, reason) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, username, tenant, permission, result, reason),
        )
        return AuditEntry(log_id, timestamp, username, tenant, permission, result, reason)

    def list_entries(self, limit=200, result=None):
        """Newest entries first. `result` may be 'ALLOW' or 'DENY' to filter."""
        sql = "SELECT * FROM audit_logs"
        params = []
        if result in (ALLOW, DENY):
            sql += " WHERE result = ?"
            params.append(result)
        sql += " ORDER BY log_id DESC LIMIT ?"
        params.append(int(limit))
        return [AuditEntry(**row) for row in self._db.query_all(sql, params)]

    def stats(self):
        row = self._db.query_one(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN result = 'ALLOW' THEN 1 ELSE 0 END), 0) AS allowed, "
            "COALESCE(SUM(CASE WHEN result = 'DENY' THEN 1 ELSE 0 END), 0) AS denied "
            "FROM audit_logs"
        )
        return {"total": row["total"], "allowed": row["allowed"], "denied": row["denied"]}

    def clear(self):
        self._db.execute("DELETE FROM audit_logs")
