"""RBAC Manager - role-based access control for a multi-tenant application."""

from .audit import AuditEntry, AuditLog
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
from .manager import RBACManager
from .models import ALLOW, DENY, Role, Tenant, User
from .permissions import GreedyPermissionResolver, Permission

__all__ = [
    "ALLOW", "DENY", "AuditEntry", "AuditLog", "Database", "RoleGraph", "RBACManager",
    "Role", "Tenant", "User", "Permission", "GreedyPermissionResolver",
    "RBACError", "ValidationError", "UserNotFoundError", "TenantNotFoundError",
    "RoleNotFoundError", "PermissionNotFoundError", "DuplicateEntityError",
    "CircularRoleError", "TenantAccessDeniedError", "PermissionDeniedError",
]
