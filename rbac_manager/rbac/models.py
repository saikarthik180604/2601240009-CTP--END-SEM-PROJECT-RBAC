"""
Domain models: Entity (base class), Tenant, Role and User.

OOP notes for the report:
  * Inheritance   - Tenant, Role and User all extend Entity.
  * Encapsulation - attributes are private (_name) and exposed via properties.
  * Composition   - a Role *has* permissions and parent roles; a User *has* roles.
"""

ALLOW = "ALLOW"
DENY = "DENY"


class Entity:
    """Common base class: every entity has an id and a display name."""

    def __init__(self, entity_id, name):
        self._entity_id = entity_id
        self._name = name

    @property
    def entity_id(self):
        return self._entity_id

    @property
    def name(self):
        return self._name

    def to_dict(self):
        return {"id": self._entity_id, "name": self._name}

    def __repr__(self):
        return f"{type(self).__name__}(id={self._entity_id}, name={self._name!r})"


class Tenant(Entity):
    """An isolated customer / organisation, e.g. ACME or GLOBEX."""

    def __init__(self, tenant_id, name):
        super().__init__(tenant_id, name)

    @property
    def tenant_id(self):
        return self._entity_id

    def to_dict(self):
        return {"tenant_id": self.tenant_id, "name": self.name}


class Role(Entity):
    """
    A named set of permissions that belongs to exactly one tenant.

    parent_roles holds the ids of the roles this role INHERITS from.
    Example: Manager.parent_roles == [Editor.role_id] means that
    Manager gets every permission of Editor (and, transitively, Viewer).
    """

    def __init__(self, role_id, role_name, tenant_id, permissions=None, parent_roles=None):
        super().__init__(role_id, role_name)
        self._tenant_id = tenant_id
        self._permissions = set(permissions or [])   # permission names
        self._parent_roles = list(parent_roles or [])  # role ids

    @property
    def role_id(self):
        return self._entity_id

    @property
    def role_name(self):
        return self._name

    @property
    def tenant_id(self):
        return self._tenant_id

    @property
    def permissions(self):
        """Directly assigned permission names (sorted copy - cannot be mutated)."""
        return sorted(self._permissions)

    @property
    def parent_roles(self):
        return list(self._parent_roles)

    def add_permission(self, permission_name):
        self._permissions.add(permission_name)

    def remove_permission(self, permission_name):
        self._permissions.discard(permission_name)

    def has_permission(self, permission_name):
        return permission_name in self._permissions

    def add_parent(self, parent_role_id):
        if parent_role_id != self.role_id and parent_role_id not in self._parent_roles:
            self._parent_roles.append(parent_role_id)

    def remove_parent(self, parent_role_id):
        if parent_role_id in self._parent_roles:
            self._parent_roles.remove(parent_role_id)

    def to_dict(self):
        return {
            "role_id": self.role_id,
            "role_name": self.role_name,
            "tenant_id": self.tenant_id,
            "permissions": self.permissions,
            "parent_roles": self.parent_roles,
        }


class User(Entity):
    """
    A person who belongs to one or more tenants.

    tenant_id is the user's HOME tenant; tenant_ids lists every tenant the
    user is a member of (home tenant included).
    roles is the list of assigned role ids.
    """

    def __init__(self, user_id, username, email, tenant_id, roles=None, tenant_ids=None):
        super().__init__(user_id, username)
        self._email = email
        self._tenant_id = tenant_id
        self._roles = list(roles or [])
        self._tenant_ids = set(tenant_ids or [])
        self._tenant_ids.add(tenant_id)

    @property
    def user_id(self):
        return self._entity_id

    @property
    def username(self):
        return self._name

    @property
    def email(self):
        return self._email

    @property
    def tenant_id(self):
        return self._tenant_id

    @property
    def roles(self):
        return list(self._roles)

    @property
    def tenant_ids(self):
        return sorted(self._tenant_ids)

    def add_role(self, role_id):
        if role_id not in self._roles:
            self._roles.append(role_id)

    def remove_role(self, role_id):
        if role_id in self._roles:
            self._roles.remove(role_id)

    def has_role(self, role_id):
        return role_id in self._roles

    def belongs_to_tenant(self, tenant_id):
        return tenant_id in self._tenant_ids

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "tenant_id": self.tenant_id,
            "tenant_ids": self.tenant_ids,
            "roles": self.roles,
        }
