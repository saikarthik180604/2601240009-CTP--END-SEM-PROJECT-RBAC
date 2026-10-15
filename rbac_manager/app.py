"""
Flask web application for the RBAC Manager.

Run with:  python app.py      ->  http://127.0.0.1:5000

Pages : /  /dashboard  /tenants  /users  /roles  /permissions  /hierarchy  /audit
API   : /api/...  (JSON in, JSON out; errors look like {"error": "message"})
"""

from flask import Flask, jsonify, render_template, request

from data.seed_data import seed_if_empty
from rbac import RBACError, RBACManager, ValidationError
from rbac.database import DEFAULT_DB_PATH, Database


def create_app(db_path=None, seed=True):
    """Application factory. Tests call create_app(':memory:')."""
    app = Flask(__name__)
    manager = RBACManager(Database(db_path or DEFAULT_DB_PATH))
    if seed:
        seed_if_empty(manager)
    app.config["MANAGER"] = manager

    # ------------------------------------------------------------ small helpers
    def body():
        """JSON request body as a dict (empty dict if missing)."""
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def need_int(data, key):
        value = data.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValidationError(f"'{key}' is required and must be a number")

    def need_str(data, key):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"'{key}' is required")
        return value.strip()

    def optional_int(name):
        value = request.args.get(name)
        if value in (None, ""):
            return None
        try:
            return int(value)
        except ValueError:
            raise ValidationError(f"'{name}' must be a number")

    @app.errorhandler(RBACError)
    def handle_rbac_error(error):
        return jsonify({"error": error.message}), error.status_code

    # ------------------------------------------------------------------- pages
    @app.route("/")
    def index():
        return render_template("index.html", stats=manager.stats())

    @app.route("/dashboard")
    def dashboard():
        return render_template(
            "dashboard.html",
            stats=manager.stats(),
            recent=manager.audit.list_entries(limit=8),
            tenants=manager.list_tenants(),
            users=manager.list_users(),
            permissions=manager.list_permissions(),
        )

    @app.route("/tenants")
    def tenants():
        rows = []
        for tenant in manager.list_tenants():
            rows.append(
                {
                    "tenant": tenant,
                    "users": len(manager.list_users(tenant.tenant_id)),
                    "roles": len(manager.list_roles(tenant.tenant_id)),
                }
            )
        return render_template("tenants.html", rows=rows)

    @app.route("/users")
    def users():
        all_roles = manager.list_roles()
        return render_template(
            "users.html",
            users=manager.list_users(),
            tenants=manager.list_tenants(),
            tenant_names={t.tenant_id: t.name for t in manager.list_tenants()},
            roles=all_roles,
            role_map={r.role_id: r for r in all_roles},
            permissions=manager.list_permissions(),
            denials=manager.list_explicit_denials(),
        )

    @app.route("/roles")
    def roles():
        tenant_list = manager.list_tenants()
        role_list = manager.list_roles()
        return render_template(
            "roles.html",
            roles=role_list,
            role_map={r.role_id: r for r in role_list},
            tenants=tenant_list,
            tenant_names={t.tenant_id: t.name for t in tenant_list},
            permissions=manager.list_permissions(),
        )

    @app.route("/permissions")
    def permissions():
        return render_template("permissions.html", permissions=manager.list_permissions())

    @app.route("/hierarchy")
    def hierarchy():
        return render_template("hierarchy.html", tenants=manager.list_tenants())

    @app.route("/audit")
    def audit():
        return render_template(
            "audit.html",
            entries=manager.audit.list_entries(limit=500),
            stats=manager.audit.stats(),
        )

    # --------------------------------------------------------------------- API
    @app.get("/api/stats")
    def api_stats():
        return jsonify(manager.stats())

    @app.get("/api/tenants")
    def api_tenants():
        return jsonify([t.to_dict() for t in manager.list_tenants()])

    @app.post("/api/tenants")
    def api_create_tenant():
        tenant = manager.create_tenant(need_str(body(), "name"))
        return jsonify(tenant.to_dict()), 201

    @app.get("/api/users")
    def api_users():
        return jsonify([u.to_dict() for u in manager.list_users(optional_int("tenant_id"))])

    @app.post("/api/users")
    def api_create_user():
        data = body()
        user = manager.create_user(
            need_str(data, "username"), need_str(data, "email"), need_int(data, "tenant_id")
        )
        return jsonify(user.to_dict()), 201

    @app.post("/api/user-tenants")
    def api_add_user_to_tenant():
        data = body()
        user = manager.add_user_to_tenant(need_int(data, "user_id"), need_int(data, "tenant_id"))
        return jsonify(user.to_dict())

    @app.post("/api/assign-role")
    def api_assign_role():
        data = body()
        user = manager.assign_role(need_int(data, "user_id"), need_int(data, "role_id"))
        return jsonify(user.to_dict())

    @app.post("/api/remove-role")
    def api_remove_role():
        data = body()
        user = manager.remove_role(need_int(data, "user_id"), need_int(data, "role_id"))
        return jsonify(user.to_dict())

    @app.get("/api/roles")
    def api_roles():
        return jsonify([r.to_dict() for r in manager.list_roles(optional_int("tenant_id"))])

    @app.post("/api/roles")
    def api_create_role():
        data = body()
        permissions_list = data.get("permissions") or []
        parents = data.get("parent_roles") or []
        if not isinstance(permissions_list, list) or not isinstance(parents, list):
            raise ValidationError("'permissions' and 'parent_roles' must be lists")
        role = manager.create_role(
            need_str(data, "role_name"), need_int(data, "tenant_id"), permissions_list, parents
        )
        return jsonify(role.to_dict()), 201

    @app.post("/api/role-permissions")
    def api_grant_permission():
        data = body()
        role = manager.grant_permission(need_int(data, "role_id"), need_str(data, "permission"))
        return jsonify(role.to_dict())

    @app.post("/api/role-permissions/remove")
    def api_revoke_permission():
        data = body()
        role = manager.revoke_permission(need_int(data, "role_id"), need_str(data, "permission"))
        return jsonify(role.to_dict())

    @app.get("/api/permissions")
    def api_permissions():
        return jsonify([p.to_dict() for p in manager.list_permissions()])

    @app.post("/api/permissions")
    def api_create_permission():
        data = body()
        permission = manager.create_permission(need_str(data, "name"), data.get("description", ""))
        return jsonify(permission.to_dict()), 201

    @app.get("/api/hierarchy")
    def api_hierarchy():
        tenant_id = optional_int("tenant_id")
        if tenant_id is None:
            raise ValidationError("'tenant_id' query parameter is required")
        return jsonify(manager.get_hierarchy(tenant_id))

    @app.post("/api/hierarchy")
    def api_add_inheritance():
        """child inherits parent. A cycle is rejected with HTTP 409."""
        data = body()
        role = manager.add_role_parent(need_int(data, "child_role_id"), need_int(data, "parent_role_id"))
        return jsonify(role.to_dict()), 201

    @app.post("/api/hierarchy/remove")
    def api_remove_inheritance():
        data = body()
        role = manager.remove_role_parent(need_int(data, "child_role_id"), need_int(data, "parent_role_id"))
        return jsonify(role.to_dict())

    @app.get("/api/denials")
    def api_denials():
        return jsonify(manager.list_explicit_denials(optional_int("user_id"), optional_int("tenant_id")))

    @app.post("/api/denials")
    def api_add_denial():
        data = body()
        manager.add_explicit_deny(
            need_int(data, "user_id"),
            need_int(data, "tenant_id"),
            need_str(data, "permission"),
            data.get("reason") or "Explicit deny rule",
        )
        return jsonify({"status": "created"}), 201

    @app.post("/api/denials/remove")
    def api_remove_denial():
        data = body()
        manager.remove_explicit_deny(
            need_int(data, "user_id"), need_int(data, "tenant_id"), need_str(data, "permission")
        )
        return jsonify({"status": "removed"})

    @app.post("/api/check-permission")
    def api_check_permission():
        """Always HTTP 200: the answer (ALLOW / DENY) is in the JSON body."""
        data = body()
        result = manager.check_permission_detailed(
            need_int(data, "user_id"), need_int(data, "tenant_id"), need_str(data, "permission")
        )
        return jsonify(result)

    @app.get("/api/effective-permissions")
    def api_effective_permissions():
        user_id, tenant_id = optional_int("user_id"), optional_int("tenant_id")
        if user_id is None or tenant_id is None:
            raise ValidationError("'user_id' and 'tenant_id' query parameters are required")
        return jsonify(manager.get_effective_permissions(user_id, tenant_id))

    @app.get("/api/audit")
    def api_audit():
        limit = optional_int("limit") or 200
        result = request.args.get("result")
        return jsonify([e.to_dict() for e in manager.audit.list_entries(limit, result)])

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
