"""
Custom exceptions for the RBAC Manager.

Every error inherits from RBACError, so callers can catch one base class
(`except RBACError`) or a specific one. Each error also carries an HTTP
status code, which the Flask API uses to build clean JSON error responses.
"""


class RBACError(Exception):
    """Base class for all RBAC errors."""

    status_code = 400

    def __init__(self, message="RBAC error"):
        super().__init__(message)
        self.message = message


class ValidationError(RBACError):
    """Raised when input data is missing or malformed."""

    status_code = 400


class UserNotFoundError(RBACError):
    """Raised when a user id / username does not exist."""

    status_code = 404


class TenantNotFoundError(RBACError):
    """Raised when a tenant id / name does not exist."""

    status_code = 404


class RoleNotFoundError(RBACError):
    """Raised when a role does not exist (or a user does not hold it)."""

    status_code = 404


class PermissionNotFoundError(RBACError):
    """Raised when a permission is not in the permission catalog."""

    status_code = 404


class DuplicateEntityError(RBACError):
    """Raised when creating something that already exists."""

    status_code = 409


class CircularRoleError(RBACError):
    """Raised when a role inheritance edge would create a cycle."""

    status_code = 409


class TenantAccessDeniedError(RBACError):
    """Raised when a user tries to cross a tenant boundary."""

    status_code = 403


class PermissionDeniedError(RBACError):
    """Raised by RBACManager.enforce() when a permission check is DENY."""

    status_code = 403
