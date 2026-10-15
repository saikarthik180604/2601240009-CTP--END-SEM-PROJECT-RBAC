"""
RBACManager - the facade that ties everything together.

It uses COMPOSITION: a manager HAS a Database, an AuditLog and a
GreedyPermissionResolver, and it builds a RoleGraph whenever it needs one.

Permission check pipeline (check_permission):
  1. user exists?                          -> else DENY (UserNotFoundError)
  2. tenant exists?                        -> else DENY (TenantNotFoundError)
  3. user belongs to that tenant?          -> else DENY (TenantAccessDeniedError)
  4. permission exists in the catalog?     -> else DENY (PermissionNotFoundError)
  5. collect the user's roles THAT BELONG TO THIS TENANT (tenant isolation)
  6. greedy BFS over the role hierarchy to resolve inherited permissions
  7. explicit deny beats allow             -> DENY "Explicit deny rule"
  8. permission resolved                   -> ALLOW
  9. otherwise                             -> DENY (default deny)
Every outcome is written to the audit log.
"""

import sqlite3

from .audit import AuditLog
from .database import Database
from .errors import (
    CircularRoleError,
    DuplicateEntityError,
    PermissionDeniedError,
    PermissionNotFoundError,
    RBACError,
    RoleNotFoundError,
    TenantAccessDeniedError,
    TenantNotFoundError,
    UserNotFoundError,
    ValidationError,
)
from .graph import RoleGraph
from .models import ALLOW, DENY, Role, Tenant, User
from .permissions import GreedyPermissionResolver, Permission


class RBACManager:
    def __init__(self, db=None, audit=None):
        self.db = db if db is not None else Database()
        self.audit = audit if audit is not None else AuditLog(self.db)
        self.resolver = GreedyPermissionResolver()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _clean(value, label):
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{label} is required")
        return value.strip()

    # ------------------------------------------------------------------ tenants
    def create_tenant(self, name):
        name = self._clean(name, "Tenant name")
        try:
            tenant_id = self.db.execute("INSERT INTO tenants (name) VALUES (?)", (name,))
        except sqlite3.IntegrityError:
            raise DuplicateEntityError(f"Tenant '{name}' already exists")
        return Tenant(tenant_id, name)

    def get_tenant(self, tenant_id):
        row = self.db.query_one("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
        if row is None:
            raise TenantNotFoundError(f"Tenant {tenant_id} not found")
        return Tenant(row["tenant_id"], row["name"])

    def get_tenant_by_name(self, name):
        row = self.db.query_one("SELECT * FROM tenants WHERE name = ?", (name,))
        if row is None:
            raise TenantNotFoundError(f"Tenant '{name}' not found")
        return Tenant(row["tenant_id"], row["name"])

    def list_tenants(self):
        rows = self.db.query_all("SELECT * FROM tenants ORDER BY tenant_id")
        return [Tenant(r["tenant_id"], r["name"]) for r in rows]

    # -------------------------------------------------------------- permissions
    def create_permission(self, name, description=""):
        name = self._clean(name, "Permission name")
        permission = Permission(None, name, description)  # validates the format
        try:
            permission_id = self.db.execute(
                "INSERT INTO permissions (name, description) VALUES (?, ?)",
                (name, permission.description),
            )
        except sqlite3.IntegrityError:
            raise DuplicateEntityError(f"Permission '{name}' already exists")
        return Permission(permission_id, name, permission.description)

    def get_permission_by_name(self, name):
        row = self.db.query_one("SELECT * FROM permissions WHERE name = ?", (name,))
        if row is None:
            raise PermissionNotFoundError(f"Permission '{name}' not found")
        return Permission(row["permission_id"], row["name"], row["description"])

    def list_permissions(self):
        rows = self.db.query_all("SELECT * FROM permissions ORDER BY name")
        return [Permission(r["permission_id"], r["name"], r["description"]) for r in rows]

    # -------------------------------------------------------------------- roles
    def _row_to_role(self, row):
        role_id = row["role_id"]
        permissions = [
            r["name"]
            for r in self.db.query_all(
                "SELECT p.name FROM role_permissions rp "
                "JOIN permissions p ON p.permission_id = rp.permission_id "
                "WHERE rp.role_id = ?",
                (role_id,),
            )
        ]
        parents = [
            r["parent_role_id"]
            for r in self.db.query_all(
                "SELECT parent_role_id FROM role_hierarchy WHERE child_role_id = ? "
                "ORDER BY parent_role_id",
                (role_id,),
            )
        ]
        return Role(role_id, row["role_name"], row["tenant_id"], permissions, parents)

    def create_role(self, role_name, tenant_id, permissions=None, parent_roles=None):
        role_name = self._clean(role_name, "Role name")
        self.get_tenant(tenant_id)
        permissions = list(permissions or [])
        parent_roles = list(parent_roles or [])
        for permission_name in permissions:       # validate before inserting anything
            self.get_permission_by_name(permission_name)
        for parent_id in parent_roles:
            self.get_role(parent_id)
        try:
            role_id = self.db.execute(
                "INSERT INTO roles (role_name, tenant_id) VALUES (?, ?)", (role_name, tenant_id)
            )
        except sqlite3.IntegrityError:
            raise DuplicateEntityError(f"Role '{role_name}' already exists in tenant {tenant_id}")
        for permission_name in permissions:
            self.grant_permission(role_id, permission_name)
        for parent_id in parent_roles:
            self.add_role_parent(role_id, parent_id)
        return self.get_role(role_id)

    def get_role(self, role_id):
        row = self.db.query_one("SELECT * FROM roles WHERE role_id = ?", (role_id,))
        if row is None:
            raise RoleNotFoundError(f"Role {role_id} not found")
        return self._row_to_role(row)

    def get_role_by_name(self, role_name, tenant_id):
        row = self.db.query_one(
            "SELECT * FROM roles WHERE role_name = ? AND tenant_id = ?", (role_name, tenant_id)
        )
        if row is None:
            raise RoleNotFoundError(f"Role '{role_name}' not found in tenant {tenant_id}")
        return self._row_to_role(row)

    def list_roles(self, tenant_id=None):
        if tenant_id is None:
            rows = self.db.query_all("SELECT * FROM roles ORDER BY tenant_id, role_id")
        else:
            rows = self.db.query_all(
                "SELECT * FROM roles WHERE tenant_id = ? ORDER BY role_id", (tenant_id,)
            )
        return [self._row_to_role(r) for r in rows]

    def grant_permission(self, role_id, permission_name):
        """Attach a permission (allow) directly to a role."""
        self.get_role(role_id)
        permission = self.get_permission_by_name(permission_name)
        self.db.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
            (role_id, permission.permission_id),
        )
        return self.get_role(role_id)

    def revoke_permission(self, role_id, permission_name):
        self.get_role(role_id)
        permission = self.get_permission_by_name(permission_name)
        self.db.execute(
            "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            (role_id, permission.permission_id),
        )
        return self.get_role(role_id)

    # ---------------------------------------------------------- role hierarchy
    def build_graph(self):
        """Load every role and hierarchy edge from SQLite into a RoleGraph."""
        graph = RoleGraph()
        for row in self.db.query_all("SELECT role_id FROM roles"):
            graph.add_role(row["role_id"])
        for row in self.db.query_all("SELECT parent_role_id, child_role_id FROM role_hierarchy"):
            graph.add_edge(row["parent_role_id"], row["child_role_id"])
        return graph

    def add_role_parent(self, child_role_id, parent_role_id):
        """
        Make `child` inherit every permission of `parent`  (edge parent -> child).
        Rejected with CircularRoleError if it would create a cycle, and with
        TenantAccessDeniedError if the two roles belong to different tenants.
        """
        child = self.get_role(child_role_id)
        parent = self.get_role(parent_role_id)
        if child.tenant_id != parent.tenant_id:
            raise TenantAccessDeniedError(
                "Role inheritance cannot cross tenants "
                f"('{parent.role_name}' and '{child.role_name}' are in different tenants)"
            )
        graph = self.build_graph()
        try:
            graph.add_edge(parent.role_id, child.role_id)
        except CircularRoleError:
            raise CircularRoleError(
                f"Circular role inheritance rejected: {parent.role_name} -> {child.role_name} "
                f"would create a cycle ('{parent.role_name}' already inherits from '{child.role_name}')"
            )
        self.db.execute(
            "INSERT OR IGNORE INTO role_hierarchy (parent_role_id, child_role_id) VALUES (?, ?)",
            (parent.role_id, child.role_id),
        )
        return self.get_role(child.role_id)

    def remove_role_parent(self, child_role_id, parent_role_id):
        self.get_role(child_role_id)
        self.get_role(parent_role_id)
        self.db.execute(
            "DELETE FROM role_hierarchy WHERE parent_role_id = ? AND child_role_id = ?",
            (parent_role_id, child_role_id),
        )
        return self.get_role(child_role_id)

    def get_hierarchy(self, tenant_id):
        """Nodes and edges of one tenant's hierarchy (used by the visualisation page)."""
        tenant = self.get_tenant(tenant_id)
        roles = self.list_roles(tenant_id)
        names = {r.role_id: r.role_name for r in roles}
        edges = [
            {
                "parent_id": p,
                "child_id": c,
                "parent_name": names[p],
                "child_name": names[c],
            }
            for c in names
            for p in self.get_role(c).parent_roles
            if p in names
        ]
        nodes = []
        for role in roles:
            nodes.append(
                {
                    "role_id": role.role_id,
                    "role_name": role.role_name,
                    "permissions": role.permissions,
                    "parents": role.parent_roles,  # roles it inherits from
                    "children": [e["child_id"] for e in edges if e["parent_id"] == role.role_id],
                }
            )
        return {"tenant": tenant.to_dict(), "nodes": nodes, "edges": edges}

    # -------------------------------------------------------------------- users
    def _row_to_user(self, row):
        user_id = row["user_id"]
        role_ids = [
            r["role_id"]
            for r in self.db.query_all(
                "SELECT role_id FROM user_roles WHERE user_id = ? ORDER BY role_id", (user_id,)
            )
        ]
        tenant_ids = [
            r["tenant_id"]
            for r in self.db.query_all(
                "SELECT tenant_id FROM user_tenants WHERE user_id = ?", (user_id,)
            )
        ]
        return User(user_id, row["username"], row["email"], row["tenant_id"], role_ids, tenant_ids)

    def create_user(self, username, email, tenant_id):
        username = self._clean(username, "Username")
        email = self._clean(email, "Email")
        if "@" not in email:
            raise ValidationError(f"Invalid email address: {email!r}")
        self.get_tenant(tenant_id)
        try:
            user_id = self.db.execute(
                "INSERT INTO users (username, email, tenant_id) VALUES (?, ?, ?)",
                (username, email, tenant_id),
            )
        except sqlite3.IntegrityError:
            raise DuplicateEntityError(f"User '{username}' already exists")
        self.db.execute(
            "INSERT OR IGNORE INTO user_tenants (user_id, tenant_id) VALUES (?, ?)",
            (user_id, tenant_id),
        )
        return self.get_user(user_id)

    def get_user(self, user_id):
        row = self.db.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
        if row is None:
            raise UserNotFoundError(f"User {user_id} not found")
        return self._row_to_user(row)

    def get_user_by_username(self, username):
        row = self.db.query_one("SELECT * FROM users WHERE username = ?", (username,))
        if row is None:
            raise UserNotFoundError(f"User '{username}' not found")
        return self._row_to_user(row)

    def list_users(self, tenant_id=None):
        if tenant_id is None:
            rows = self.db.query_all("SELECT * FROM users ORDER BY user_id")
        else:
            rows = self.db.query_all(
                "SELECT u.* FROM users u JOIN user_tenants ut ON ut.user_id = u.user_id "
                "WHERE ut.tenant_id = ? ORDER BY u.user_id",
                (tenant_id,),
            )
        return [self._row_to_user(r) for r in rows]

    def add_user_to_tenant(self, user_id, tenant_id):
        """Make an existing user a member of an additional tenant."""
        self.get_user(user_id)
        self.get_tenant(tenant_id)
        self.db.execute(
            "INSERT OR IGNORE INTO user_tenants (user_id, tenant_id) VALUES (?, ?)",
            (user_id, tenant_id),
        )
        return self.get_user(user_id)

    def user_belongs_to_tenant(self, user_id, tenant_id):
        return self.get_user(user_id).belongs_to_tenant(tenant_id)

    def assign_role(self, user_id, role_id):
        """Give a user a role. The user must be a member of the role's tenant."""
        user = self.get_user(user_id)
        role = self.get_role(role_id)
        if not user.belongs_to_tenant(role.tenant_id):
            raise TenantAccessDeniedError(
                f"User '{user.username}' is not a member of the tenant that owns role '{role.role_name}'"
            )
        self.db.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id)
        )
        return self.get_user(user_id)

    def remove_role(self, user_id, role_id):
        user = self.get_user(user_id)
        role = self.get_role(role_id)
        if not user.has_role(role_id):
            raise RoleNotFoundError(f"User '{user.username}' does not have role '{role.role_name}'")
        self.db.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", (user_id, role_id)
        )
        return self.get_user(user_id)

    # ---------------------------------------------------------- explicit denials
    def add_explicit_deny(self, user_id, tenant_id, permission_name, reason="Explicit deny rule"):
        """DENY a permission for one user inside one tenant. Overrides any allow."""
        user = self.get_user(user_id)
        tenant = self.get_tenant(tenant_id)
        permission = self.get_permission_by_name(permission_name)
        if not user.belongs_to_tenant(tenant.tenant_id):
            raise TenantAccessDeniedError(
                f"User '{user.username}' does not belong to tenant '{tenant.name}'"
            )
        self.db.execute(
            "INSERT OR REPLACE INTO explicit_denials (user_id, tenant_id, permission_id, reason) "
            "VALUES (?, ?, ?, ?)",
            (user_id, tenant_id, permission.permission_id, reason or "Explicit deny rule"),
        )

    def remove_explicit_deny(self, user_id, tenant_id, permission_name):
        permission = self.get_permission_by_name(permission_name)
        self.db.execute(
            "DELETE FROM explicit_denials WHERE user_id = ? AND tenant_id = ? AND permission_id = ?",
            (user_id, tenant_id, permission.permission_id),
        )

    def list_explicit_denials(self, user_id=None, tenant_id=None):
        sql = (
            "SELECT d.denial_id, d.user_id, u.username, d.tenant_id, t.name AS tenant, "
            "p.name AS permission, d.reason FROM explicit_denials d "
            "JOIN users u ON u.user_id = d.user_id "
            "JOIN tenants t ON t.tenant_id = d.tenant_id "
            "JOIN permissions p ON p.permission_id = d.permission_id WHERE 1 = 1"
        )
        params = []
        if user_id is not None:
            sql += " AND d.user_id = ?"
            params.append(user_id)
        if tenant_id is not None:
            sql += " AND d.tenant_id = ?"
            params.append(tenant_id)
        return self.db.query_all(sql + " ORDER BY d.denial_id", params)

    # ----------------------------------------------------- permission resolution
    def _role_permission_map(self):
        mapping = {}
        for row in self.db.query_all(
            "SELECT rp.role_id, p.name FROM role_permissions rp "
            "JOIN permissions p ON p.permission_id = rp.permission_id"
        ):
            mapping.setdefault(row["role_id"], set()).add(row["name"])
        return mapping

    def _resolve_for(self, user, tenant):
        """Run the greedy resolver for one user inside one tenant."""
        # Tenant isolation: only roles owned by THIS tenant are considered.
        assigned = [
            r["role_id"]
            for r in self.db.query_all(
                "SELECT ur.role_id FROM user_roles ur JOIN roles r ON r.role_id = ur.role_id "
                "WHERE ur.user_id = ? AND r.tenant_id = ? ORDER BY ur.role_id",
                (user.user_id, tenant.tenant_id),
            )
        ]
        denied = {
            d["permission"]
            for d in self.list_explicit_denials(user.user_id, tenant.tenant_id)
        }
        resolved = self.resolver.resolve(
            self.build_graph(), assigned, self._role_permission_map(), denied
        )
        return resolved, assigned

    def _role_name(self, role_id):
        return self.get_role(role_id).role_name

    def _decide(self, user, tenant, permission_name):
        """Steps 3-9 of the pipeline. Returns (decision, reason)."""
        if not user.belongs_to_tenant(tenant.tenant_id):
            raise TenantAccessDeniedError(
                f"User '{user.username}' does not belong to tenant '{tenant.name}' (tenant isolation)"
            )
        self.get_permission_by_name(permission_name)

        resolved, assigned = self._resolve_for(user, tenant)
        if not assigned:
            return DENY, f"User has no role in tenant '{tenant.name}'"
        if resolved.is_denied(permission_name):
            return DENY, "Explicit deny rule"
        if resolved.is_allowed(permission_name):
            source = resolved.source_of(permission_name)
            name = self._role_name(source)
            if source in assigned:
                return ALLOW, f"Allowed by assigned role '{name}'"
            return ALLOW, f"Allowed by inherited role '{name}'"
        return DENY, "No matching allow rule (default deny)"

    def _run_check(self, user_id, tenant_id, permission_name):
        """Evaluate, write the audit entry, return (result_dict, error_or_None)."""
        username = f"<user {user_id}>"
        tenant_label = f"<tenant {tenant_id}>"
        error = None
        try:
            user = self.get_user(user_id)
            username = user.username
            tenant = self.get_tenant(tenant_id)
            tenant_label = tenant.name
            decision, reason = self._decide(user, tenant, permission_name)
        except RBACError as exc:
            decision, reason, error = DENY, exc.message, exc
        self.audit.record(username, tenant_label, str(permission_name), decision, reason)
        result = {
            "result": decision,
            "reason": reason,
            "username": username,
            "tenant": tenant_label,
            "permission": permission_name,
        }
        return result, error

    def check_permission(self, user_id, tenant_id, permission):
        """Return 'ALLOW' or 'DENY'. Never raises for authorization problems."""
        return self._run_check(user_id, tenant_id, permission)[0]["result"]

    def check_permission_detailed(self, user_id, tenant_id, permission):
        """Same as check_permission but returns a dict that includes the reason."""
        return self._run_check(user_id, tenant_id, permission)[0]

    def enforce(self, user_id, tenant_id, permission):
        """
        Enforcement helper: returns normally on ALLOW, raises on DENY.
        Raises UserNotFoundError / TenantNotFoundError / TenantAccessDeniedError /
        PermissionNotFoundError for invalid access, PermissionDeniedError otherwise.
        """
        result, error = self._run_check(user_id, tenant_id, permission)
        if error is not None:
            raise error
        if result["result"] == DENY:
            raise PermissionDeniedError(result["reason"])
        return result

    def get_effective_permissions(self, user_id, tenant_id):
        """Every permission a user effectively holds in a tenant (allowed + denied)."""
        user = self.get_user(user_id)
        tenant = self.get_tenant(tenant_id)
        if not user.belongs_to_tenant(tenant.tenant_id):
            raise TenantAccessDeniedError(
                f"User '{user.username}' does not belong to tenant '{tenant.name}' (tenant isolation)"
            )
        resolved, assigned = self._resolve_for(user, tenant)
        allowed = [
            {"permission": p, "source_role": self._role_name(r), "inherited": r not in assigned}
            for p, r in sorted(resolved.effective.items())
        ]
        return {
            "user": user.username,
            "tenant": tenant.name,
            "assigned_roles": [self._role_name(r) for r in assigned],
            "allowed": allowed,
            "denied": sorted(resolved.denied),
        }

    # -------------------------------------------------------------------- stats
    def stats(self):
        def count(table):
            return self.db.query_one(f"SELECT COUNT(*) AS n FROM {table}")["n"]

        audit = self.audit.stats()
        return {
            "tenants": count("tenants"),
            "users": count("users"),
            "roles": count("roles"),
            "permissions": count("permissions"),
            "checks": audit["total"],
            "allowed": audit["allowed"],
            "denied": audit["denied"],
        }
