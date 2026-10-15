"""
Demo / seed data.

Creates two tenants (ACME, GLOBEX), 17 permissions, a four-level role
hierarchy in each tenant, four demo users and one explicit deny:

    Viewer -> Editor -> Manager -> Admin     (Admin inherits everything)

    Alice -> Admin   -> ACME      (+ explicit DENY billing:delete)
    Bob   -> Viewer  -> ACME
    Carol -> Editor  -> ACME      (+ Viewer in GLOBEX: member of both tenants)
    Dave  -> Admin   -> GLOBEX
"""

PERMISSIONS = [
    ("users:create", "Create users"),
    ("users:read", "View users"),
    ("users:update", "Edit users"),
    ("users:delete", "Delete users"),
    ("roles:create", "Create roles"),
    ("roles:read", "View roles"),
    ("roles:update", "Edit roles"),
    ("roles:delete", "Delete roles"),
    ("products:create", "Create products"),
    ("products:read", "View products"),
    ("products:update", "Edit products"),
    ("products:delete", "Delete products"),
    ("reports:view", "View reports"),
    ("billing:view", "View billing"),
    ("billing:edit", "Edit billing"),
    ("billing:delete", "Delete billing records"),
    ("dashboard:view", "View the dashboard"),
]

# Permissions attached DIRECTLY to each role (inheritance adds the rest).
ROLE_PERMISSIONS = {
    "Viewer": ["dashboard:view", "products:read", "users:read"],
    "Editor": ["products:create", "reports:view"],
    "Manager": ["products:update", "users:create", "users:update", "roles:read", "billing:view"],
    "Admin": [
        "products:delete", "users:delete", "roles:create", "roles:update",
        "roles:delete", "billing:edit", "billing:delete",
    ],
}

# (base role, inheriting role): the inheriting role gets the base role's permissions.
HIERARCHY = [("Viewer", "Editor"), ("Editor", "Manager"), ("Manager", "Admin")]

TENANTS = ["ACME", "GLOBEX"]


def seed_demo_data(manager):
    """Fill an empty database with demo data and return a dict of created ids."""
    refs = {"tenants": {}, "users": {}, "roles": {}}

    for name in TENANTS:
        refs["tenants"][name] = manager.create_tenant(name).tenant_id

    for name, description in PERMISSIONS:
        manager.create_permission(name, description)

    for tenant_name, tenant_id in refs["tenants"].items():
        refs["roles"][tenant_name] = {}
        for role_name in ("Viewer", "Editor", "Manager", "Admin"):
            role = manager.create_role(role_name, tenant_id, ROLE_PERMISSIONS[role_name])
            refs["roles"][tenant_name][role_name] = role.role_id
        for base, inheriting in HIERARCHY:
            manager.add_role_parent(
                refs["roles"][tenant_name][inheriting], refs["roles"][tenant_name][base]
            )

    acme, globex = refs["tenants"]["ACME"], refs["tenants"]["GLOBEX"]
    acme_roles, globex_roles = refs["roles"]["ACME"], refs["roles"]["GLOBEX"]

    users = [
        ("Alice", "alice@acme.com", acme, acme_roles["Admin"]),
        ("Bob", "bob@acme.com", acme, acme_roles["Viewer"]),
        ("Carol", "carol@acme.com", acme, acme_roles["Editor"]),
        ("Dave", "dave@globex.com", globex, globex_roles["Admin"]),
    ]
    for username, email, tenant_id, role_id in users:
        user = manager.create_user(username, email, tenant_id)
        manager.assign_role(user.user_id, role_id)
        refs["users"][username] = user.user_id

    # Carol is ALSO a member of GLOBEX, but only with the Viewer role there.
    manager.add_user_to_tenant(refs["users"]["Carol"], globex)
    manager.assign_role(refs["users"]["Carol"], globex_roles["Viewer"])

    # Alice is an ACME admin, yet billing:delete is explicitly denied for her.
    manager.add_explicit_deny(refs["users"]["Alice"], acme, "billing:delete")
    return refs


def seed_if_empty(manager):
    """Seed only when the database has no tenants yet. Returns True if seeded."""
    if manager.list_tenants():
        return False
    seed_demo_data(manager)
    return True
