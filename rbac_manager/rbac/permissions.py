"""
Permission objects and the GREEDY permission resolver.

GREEDY PERMISSION RESOLUTION
----------------------------
Goal: find the complete set of permissions a user effectively holds.

  1. Start with the roles directly assigned to the user.
  2. Walk up the role hierarchy with BFS (nearest roles first).
  3. For each visited role, take every permission that is NOT already
     resolved (greedy: the first/nearest role that offers a permission claims
     it; later duplicates are ignored - this removes duplicates).
  4. Continue until every reachable role has been processed.
  5. Explicit DENY rules are applied last and always win over any allow.
  6. The final decision is ALLOW only if the permission is resolved AND
     not denied; otherwise it is DENY (default deny).

It is "greedy" because every step makes the locally best choice (claim the
permission now) and never has to revisit or backtrack on that choice.
Complexity: O(V + E + P) for V roles, E hierarchy edges, P permissions.
"""

import re

from .errors import ValidationError
from .models import Entity

# resource:action  e.g. users:create, billing:view
PERMISSION_PATTERN = re.compile(r"^[a-z_]+:[a-z_]+$")


class Permission(Entity):
    """A permission such as 'users:create' (resource 'users', action 'create')."""

    def __init__(self, permission_id, name, description=""):
        self.validate_name(name)
        super().__init__(permission_id, name)
        self._description = description or ""

    @staticmethod
    def validate_name(name):
        if not isinstance(name, str) or not PERMISSION_PATTERN.match(name):
            raise ValidationError(
                f"Invalid permission name {name!r}: use lowercase 'resource:action', e.g. 'users:create'"
            )

    @property
    def permission_id(self):
        return self._entity_id

    @property
    def resource(self):
        return self._name.split(":")[0]

    @property
    def action(self):
        return self._name.split(":")[1]

    @property
    def description(self):
        return self._description

    def to_dict(self):
        return {
            "permission_id": self.permission_id,
            "name": self.name,
            "resource": self.resource,
            "action": self.action,
            "description": self.description,
        }


class ResolvedPermissions:
    """Result of the resolver: granted permissions plus explicit denials."""

    def __init__(self, granted, denied):
        self.granted = dict(granted)  # permission name -> id of the role that supplied it
        self.denied = set(denied)     # permission names with an explicit deny

    @property
    def effective(self):
        """Granted permissions after removing explicitly denied ones."""
        return {p: r for p, r in self.granted.items() if p not in self.denied}

    def is_denied(self, permission_name):
        return permission_name in self.denied

    def is_allowed(self, permission_name):
        return permission_name in self.granted and permission_name not in self.denied

    def source_of(self, permission_name):
        return self.granted.get(permission_name)


class GreedyPermissionResolver:
    """Implements the greedy algorithm described at the top of this file."""

    def resolve(self, graph, assigned_role_ids, role_permissions, denied_permissions=()):
        """
        graph              : RoleGraph
        assigned_role_ids  : roles directly assigned to the user (in one tenant)
        role_permissions   : dict role_id -> set of permission names
        denied_permissions : permission names explicitly denied for the user
        """
        granted = {}
        # Steps 1-2: assigned roles first, then inherited roles (BFS order).
        for role_id in graph.traverse_inherited(assigned_role_ids):
            # Step 3: greedily claim permissions that are not resolved yet.
            for permission_name in sorted(role_permissions.get(role_id, ())):
                if permission_name not in granted:
                    granted[permission_name] = role_id
        # Steps 5-6 happen when ResolvedPermissions is queried.
        return ResolvedPermissions(granted, denied_permissions)
