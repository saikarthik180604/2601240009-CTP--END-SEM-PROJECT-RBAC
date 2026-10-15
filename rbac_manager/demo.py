"""
Command-line demonstration of the RBAC Manager.

    python demo.py              # fresh in-memory database (repeatable output)
    python demo.py --use-db     # use database.db so the audit logs show up in the web UI
"""

import sys

from data.seed_data import seed_if_empty
from rbac import CircularRoleError, Database, RBACManager
from rbac.database import DEFAULT_DB_PATH


def show(manager, username, tenant_name, permission):
    """Run one permission check and print it as 'user -> tenant -> permission -> RESULT'."""
    user = manager.get_user_by_username(username)
    tenant = manager.get_tenant_by_name(tenant_name)
    result = manager.check_permission(user.user_id, tenant.tenant_id, permission)
    print(f"{username} -> {tenant_name} -> {permission} -> {result}")
    return result


def section(title):
    print(f"\n--- {title} ---")


def main():
    use_db = "--use-db" in sys.argv
    manager = RBACManager(Database(DEFAULT_DB_PATH if use_db else ":memory:"))
    seed_if_empty(manager)
    start_log_id = manager.audit.stats()["total"]

    print("=== RBAC DEMO ===")

    section("1. Alice (ACME Admin) can use admin permissions")
    show(manager, "Alice", "ACME", "users:create")
    show(manager, "Alice", "ACME", "roles:delete")
    show(manager, "Alice", "ACME", "products:delete")

    section("2. Bob (ACME Viewer) only has viewer permissions")
    show(manager, "Bob", "ACME", "dashboard:view")
    show(manager, "Bob", "ACME", "products:read")
    show(manager, "Bob", "ACME", "users:delete")

    section("3. Carol (ACME Editor) inherits Viewer permissions through Editor")
    show(manager, "Carol", "ACME", "products:create")   # Editor's own permission
    show(manager, "Carol", "ACME", "products:read")     # inherited from Viewer
    show(manager, "Carol", "ACME", "products:update")   # Manager only -> DENY

    section("4. Alice inherits Manager, Editor and Viewer permissions")
    show(manager, "Alice", "ACME", "products:update")   # from Manager
    show(manager, "Alice", "ACME", "reports:view")      # from Editor
    show(manager, "Alice", "ACME", "dashboard:view")    # from Viewer
    alice = manager.get_user_by_username("Alice")
    acme = manager.get_tenant_by_name("ACME")
    info = manager.get_effective_permissions(alice.user_id, acme.tenant_id)
    print(f"Alice's effective permissions ({len(info['allowed'])}):")
    for item in info["allowed"]:
        print(f"    {item['permission']:<16} from {item['source_role']}")

    section("5. Alice's explicit deny overrides an inherited allow")
    show(manager, "Alice", "ACME", "billing:edit")      # still allowed
    show(manager, "Alice", "ACME", "billing:delete")    # Admin allows it, explicit deny wins

    section("6. Tenant isolation: ACME users cannot access GLOBEX")
    show(manager, "Bob", "GLOBEX", "products:read")
    show(manager, "Alice", "GLOBEX", "users:create")
    show(manager, "Dave", "GLOBEX", "users:create")     # GLOBEX's own admin
    show(manager, "Dave", "ACME", "users:create")       # ...but no access to ACME
    show(manager, "Carol", "GLOBEX", "products:read")   # Carol is a GLOBEX Viewer
    show(manager, "Carol", "GLOBEX", "products:create") # ...her ACME Editor role does not leak

    section("7. Circular role inheritance is rejected")
    viewer = manager.get_role_by_name("Viewer", acme.tenant_id)
    admin = manager.get_role_by_name("Admin", acme.tenant_id)
    print("Existing chain: Viewer -> Editor -> Manager -> Admin (valid)")
    try:
        manager.add_role_parent(child_role_id=viewer.role_id, parent_role_id=admin.role_id)
        print("Admin -> Viewer was accepted (this should never happen)")
    except CircularRoleError as error:
        print(f"Admin -> Viewer REJECTED: {error}")

    section("8. Audit logs generated during this demo")
    entries = manager.audit.list_entries(limit=1000)
    new_count = len(entries) - start_log_id
    for entry in reversed(entries[:new_count][:12]):
        print(f"{entry.timestamp} | {entry.format()}")
    print(f"... {new_count} audit entries were written in total.")
    stats = manager.audit.stats()
    print(f"Audit totals -> checks: {stats['total']}, allowed: {stats['allowed']}, denied: {stats['denied']}")


if __name__ == "__main__":
    main()
