"""Tests: tenants, role creation, role object behaviour."""

import pytest

from rbac import DuplicateEntityError, Role, TenantNotFoundError, ValidationError, PermissionNotFoundError


def test_create_tenant(manager):
    tenant = manager.create_tenant("ACME")
    assert tenant.name == "ACME"
    assert manager.get_tenant(tenant.tenant_id).name == "ACME"


def test_duplicate_tenant_rejected(manager):
    manager.create_tenant("ACME")
    with pytest.raises(DuplicateEntityError):
        manager.create_tenant("ACME")


def test_blank_tenant_name_rejected(manager):
    with pytest.raises(ValidationError):
        manager.create_tenant("   ")


def test_create_role_in_tenant(manager):
    tenant = manager.create_tenant("ACME")
    role = manager.create_role("Viewer", tenant.tenant_id)
    assert role.role_name == "Viewer"
    assert role.tenant_id == tenant.tenant_id
    assert role.permissions == []
    assert role.parent_roles == []


def test_create_role_with_permissions(manager):
    tenant = manager.create_tenant("ACME")
    manager.create_permission("products:read")
    role = manager.create_role("Viewer", tenant.tenant_id, ["products:read"])
    assert role.permissions == ["products:read"]


def test_duplicate_role_in_same_tenant_rejected_but_allowed_in_other(manager):
    acme = manager.create_tenant("ACME")
    globex = manager.create_tenant("GLOBEX")
    manager.create_role("Admin", acme.tenant_id)
    with pytest.raises(DuplicateEntityError):
        manager.create_role("Admin", acme.tenant_id)
    assert manager.create_role("Admin", globex.tenant_id).tenant_id == globex.tenant_id


def test_create_role_in_unknown_tenant(manager):
    with pytest.raises(TenantNotFoundError):
        manager.create_role("Admin", 999)


def test_create_role_with_unknown_permission_creates_nothing(manager):
    tenant = manager.create_tenant("ACME")
    with pytest.raises(PermissionNotFoundError):
        manager.create_role("Ghost", tenant.tenant_id, ["nothing:here"])
    assert manager.list_roles(tenant.tenant_id) == []


def test_grant_and_revoke_permission(manager):
    tenant = manager.create_tenant("ACME")
    manager.create_permission("billing:view")
    role = manager.create_role("Finance", tenant.tenant_id)
    assert manager.grant_permission(role.role_id, "billing:view").permissions == ["billing:view"]
    assert manager.revoke_permission(role.role_id, "billing:view").permissions == []


def test_role_object_encapsulation():
    role = Role(1, "Editor", 1, ["products:create"], [5])
    copy = role.permissions
    copy.append("hacked:permission")           # changing the returned copy ...
    assert role.permissions == ["products:create"]  # ... does not change the role
    role.add_permission("reports:view")
    assert role.has_permission("reports:view")
    role.add_parent(1)                          # a role can never be its own parent
    assert role.parent_roles == [5]
